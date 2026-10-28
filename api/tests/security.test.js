import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { SignJWT } from 'jose';
import app from '../src/index.js';
import { AuthService } from '../src/services/auth.service.js';
import { hashToken } from '../src/utils/crypto.js';
import { createRateLimiter } from '../src/middleware/rateLimit.js';

// Execute the real SQL against SQLite, exposing the subset of the D1 API used here.
class LocalD1 {
    constructor() { this.sqlite = new DatabaseSync(':memory:'); this.sqlite.exec('PRAGMA foreign_keys=ON'); }
    prepare(sql) {
        const statement = this.sqlite.prepare(sql);
        let values = [];
        const query = {
            bind(...args) { values = args; return query; },
            async first() { return statement.get(...values) || null; },
            async all() { return { results: statement.all(...values) }; },
            async run() {
                const result = statement.run(...values);
                return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
            },
        };
        return query;
    }
}
let db, env, service, user;
beforeEach(async () => {
    db = new LocalD1();
    for (const name of readdirSync(new URL('../migrations/', import.meta.url)).sort()) {
        db.sqlite.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8'));
    }
    env = { DB: db, JWT_ACCESS_SECRET: 'test-only-secret-32-characters-long-not-for-deployment', FRONTEND_URL: 'http://localhost:5173' };
    service = new AuthService(env, db);
    const passwordHash = await service.hashPassword('Password123!');
    for (const [id, role] of [[1, 'User'], [2, 'User'], [3, 'Admin'], [4, 'Moderator']]) {
        db.sqlite.prepare('INSERT INTO users(id,email,password_hash) VALUES(?,?,?)').run(id, `person${id}@example.test`, passwordHash);
        db.sqlite.prepare('INSERT OR IGNORE INTO roles(name) VALUES(?)').run(role);
        db.sqlite.prepare('INSERT INTO user_roles(user_id,role_id) SELECT ?,id FROM roles WHERE name=?').run(id, role);
        db.sqlite.prepare('INSERT INTO sessions(id,user_id) VALUES(?,?)').run(`session-${id}`, id);
    }
    user = { id: 1, email: 'person1@example.test', roles: [{name:'User'}], permissions: [] };
});
afterEach(() => db.sqlite.close());
test('password change revokes all user sessions and preserves another user', async () => {
    const access = await service.generateAccessToken(user, 'session-1');
    db.sqlite.prepare('INSERT INTO sessions(id,user_id) VALUES(?,?)').run('other-device-1', 1);
    const raw = await service.generateRefreshToken(1, 'other-device-1');
    const wrong = await request('/user/change-password', {method:'POST', token:access, body:{currentPassword:'Incorrect1', newPassword:'UpdatedPassword123!'}});
    assert.equal(wrong.status, 400);
    assert.equal(db.sqlite.prepare('SELECT count(*) AS count FROM sessions WHERE user_id=1').get().count, 2);
    const changed = await request('/user/change-password', {method:'POST', token:access, body:{currentPassword:'Password123!', newPassword:'UpdatedPassword123!'}});
    assert.equal(changed.status, 200);
    assert.equal(db.sqlite.prepare('SELECT count(*) AS count FROM sessions WHERE user_id=1').get().count, 0);
    assert.equal((await request('/user/me', {token:access})).status, 401);
    await assert.rejects(service.verifyRefreshToken(raw));
    assert.equal((await request('/user/me', {id:2})).status, 200);
});
test('legacy migration revokes weak hashes while preserving modern token digests', () => {
    const legacy = new LocalD1();
    try {
        const names = readdirSync(new URL('../migrations/', import.meta.url)).sort();
        for (const name of names.filter(n => !n.startsWith('0005'))) legacy.sqlite.exec(readFileSync(new URL('../migrations/'+name, import.meta.url), 'utf8'));
        legacy.sqlite.exec("INSERT INTO users(id,email,password_hash) VALUES(1,'legacy@example.test','fixture'); INSERT INTO sessions(id,user_id) VALUES('legacy',1),('modern',1);");
        const insert = legacy.sqlite.prepare("INSERT INTO refresh_tokens(session_id,token_hash,expires_at) VALUES(?,?,datetime('now','+1 day'))");
        insert.run('legacy', 'old-weak-hash');
        insert.run('modern', 'a'.repeat(64));
        for (const table of ['password_reset_tokens','email_verification_tokens']) {
            const tokens = legacy.sqlite.prepare(`INSERT INTO ${table}(user_id,token_hash,expires_at) VALUES(1,?,datetime('now','+1 day'))`);
            tokens.run('old-weak-hash'); tokens.run('b'.repeat(64));
        }
        legacy.sqlite.exec(readFileSync(new URL('../migrations/0005_token_security_and_rate_limits.sql', import.meta.url), 'utf8'));
        assert.equal(legacy.sqlite.prepare('SELECT count(*) AS count FROM sessions').get().count, 1);
        assert.equal(legacy.sqlite.prepare('SELECT id FROM sessions').get().id, 'modern');
        for (const table of ['refresh_tokens','password_reset_tokens','email_verification_tokens']) assert.equal(legacy.sqlite.prepare(`SELECT count(*) AS count FROM ${table}`).get().count, 1);
    } finally { legacy.sqlite.close(); }
});
async function request(path, { id = 1, method = 'GET', body, token, headers = {} } = {}) {
    const access = token ?? await service.generateAccessToken({ ...user, id }, `session-${id}`);
    return app.request(path, { method, headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json', ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) }, env);
}

test('SHA-256 known vector and distinct legacy collision inputs', async () => {
    assert.equal(await hashToken('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.notEqual(await hashToken('Aa'), await hashToken('BB'));
    const raw = await service.generateRefreshToken(1, 'session-1');
    assert.equal(raw.length, 64);
    assert.equal(db.sqlite.prepare('SELECT token_hash FROM refresh_tokens').get().token_hash, await hashToken(raw));
});
test('password verification rejects incorrect and malformed credentials', async () => {
    const hash = await service.hashPassword('Password123!');
    assert.equal(await service.verifyPassword('Password123!', hash), true);
    assert.equal(await service.verifyPassword('Wrong123!', hash), false);
    assert.equal(await service.verifyPassword('Password123!', 'broken'), false);
});
test('refresh rotation permits one consumer under concurrent requests', async () => {
    const raw = await service.generateRefreshToken(1, 'session-1');
    const results = await Promise.allSettled(Array.from({ length: 12 }, () => service.verifyRefreshToken(raw)));
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(db.sqlite.prepare('SELECT * FROM sessions WHERE id=?').get('session-1'), undefined);
});
test('concurrent HTTP refresh returns authentication failures instead of server errors', async () => {
    const raw = await service.generateRefreshToken(1, 'session-1');
    const responses = await Promise.all(Array.from({length:12}, () => request('/auth/refresh', {method:'POST',body:{refreshToken:raw}})));
    assert(responses.every(response => [200,401].includes(response.status)));
    assert(responses.filter(response => response.status === 200).length <= 1);
    assert.equal(db.sqlite.prepare('SELECT * FROM sessions WHERE id=?').get('session-1'), undefined);
});
test('expired refresh tokens cannot be consumed, including exact expiry boundary', async () => {
    for (const expiry of ["datetime('now','-1 day')", "datetime('now')"]) {
        const raw = await service.generateRefreshToken(1, 'session-1');
        db.sqlite.exec(`UPDATE refresh_tokens SET expires_at=${expiry}`);
        await assert.rejects(service.verifyRefreshToken(raw));
    }
});
test('refresh replay invalidates the replacement and its access token', async () => {
    const raw = await service.generateRefreshToken(1, 'session-1');
    const response = await request('/auth/refresh', { method:'POST', body:{refreshToken:raw} });
    assert.equal(response.status, 200);
    const tokens = await response.json();
    assert.equal((await request('/me', { token:tokens.accessToken })).status, 200);
    assert.equal((await request('/auth/refresh', { method:'POST', body:{refreshToken:raw} })).status, 401);
    assert.equal((await request('/me', { token:tokens.accessToken })).status, 401);
    await assert.rejects(service.verifyRefreshToken(tokens.refreshToken));
});
test('logout revokes the caller session and cannot revoke another user via supplied token', async () => {
    const mine = await service.generateRefreshToken(1, 'session-1');
    const theirs = await service.generateRefreshToken(2, 'session-2');
    const token = await service.generateAccessToken(user, 'session-1');
    assert.equal((await request('/auth/logout', { token, method:'POST', body:{refreshToken:theirs} })).status, 200);
    assert.equal((await request('/me', { token })).status, 401);
    await assert.rejects(service.verifyRefreshToken(mine));
    assert.equal((await service.verifyRefreshToken(theirs)).userId, 2);
});
test('session ownership and role matrix protect routes', async () => {
    for (const id of [1, 2, 4]) assert.equal((await request('/admin/users', { id })).status, 403);
    const admin = await request('/admin/users', { id:3 });
    assert.equal(admin.status, 200);
    assert.equal(JSON.stringify(await admin.json()).includes('password_hash'), false);
    assert.equal((await request('/sessions/session-2', {method:'DELETE'})).status, 404);
    assert.ok(db.sqlite.prepare('SELECT id FROM sessions WHERE id=?').get('session-2'));
    const mismatched = await service.generateAccessToken({...user,id:2}, 'session-1');
    assert.equal((await request('/me', { token:mismatched })).status, 401);
});
test('job CRUD isolates users and ignores client-supplied ownership', async () => {
    const created = await request('/jobs', {method:'POST',body:{company:'Example',position:'SWE',user_id:2}});
    assert.equal(created.status, 201);
    const {job} = await created.json();
    assert.equal(job.user_id, 1);
    assert.equal((await request(`/jobs/${job.id}`, {id:2})).status, 404);
    assert.equal((await request(`/jobs/${job.id}`, {id:2,method:'PUT',body:{company:'Hijack',position:'SWE'}})).status, 404);
    assert.equal((await request(`/jobs/${job.id}`, {id:2,method:'DELETE'})).status, 404);
    assert.deepEqual((await (await request('/jobs', {id:2})).json()).jobs, []);
    assert.equal((await request(`/jobs/${job.id}`, {method:'PUT',body:{company:'Updated',position:'SWE'}})).status, 200);
    assert.equal((await request(`/jobs/${job.id}`, {method:'DELETE'})).status, 200);
});
test('invalid signatures, algorithms, expired and legacy tokens are rejected', async () => {
    const secret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);
    for (const [alg, expiry, sid] of [['HS384','1h','session-1'],['HS256',0,'session-1'],['HS256','1h',undefined]]) {
        const token = await new SignJWT({sub:'1',type:'access',...(sid?{sid}: {})}).setProtectedHeader({alg}).setExpirationTime(expiry).sign(secret);
        assert.equal((await request('/me', {token})).status, 401);
    }
    assert.equal((await request('/me', {token:'broken.jwt.signature'})).status, 401);
    await assert.rejects(new AuthService({...env,JWT_ACCESS_SECRET:'your-super-secret-jwt-access-key-change-this-in-production'},db).generateAccessToken(user,'session-1'));
});
test('separate rate limiter instances share an atomic persistent count', async () => {
    const context = (ip) => ({env,req:{path:'/auth/login',header:(name)=>name==='cf-connecting-ip'?ip:'spoofed'},header:()=>{}});
    const limiters = [createRateLimiter(5,300),createRateLimiter(5,300)];
    const results = await Promise.allSettled(Array.from({length:12},(_,i)=>limiters[i%2](context('127.0.0.1'),async()=>{})));
    assert.equal(results.filter(r=>r.status==='fulfilled').length,5);
    await limiters[0](context('127.0.0.2'),async()=>{});
    db.sqlite.exec('UPDATE rate_limits SET expires_at=0');
    await limiters[0](context('127.0.0.3'),async()=>{});
    assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM rate_limits').get().n,1);
});
test('reset tokens are one-time and password reset revokes prior access', async () => {
    const token = await service.generateAccessToken(user,'session-1');
    const reset = await service.generatePasswordResetToken(1);
    const args = {method:'POST',body:{token:reset,newPassword:'Changed123!'}};
    assert.equal((await request('/auth/reset-password',args)).status,200);
    assert.equal((await request('/auth/reset-password',args)).status,401);
    assert.equal((await request('/me',{token})).status,401);
    const hash = db.sqlite.prepare('SELECT password_hash FROM users WHERE id=1').get().password_hash;
    assert.equal(await service.verifyPassword('Changed123!',hash),true);
});
test('revoke-all identifies the current session and preserves another user', async () => {
    const token = await service.generateAccessToken(user,'session-1');
    const sessions = await request('/sessions',{token});
    assert.equal((await sessions.json()).currentSessionId,'session-1');
    db.sqlite.prepare('INSERT INTO sessions(id,user_id) VALUES(?,?)').run('second-device',1);
    assert.equal((await request('/sessions',{token,method:'DELETE'})).status,200);
    assert.equal((await request('/me',{token})).status,401);
    assert.ok(db.sqlite.prepare('SELECT id FROM sessions WHERE id=?').get('session-2'));
});
test('invalid credential types and malformed JSON produce client errors', async () => {
    for(const body of [null,[],42,{email:42,password:'Password123!'},{email:'bad',password:'Password123!'}]) {
        assert.equal((await request('/auth/login',{method:'POST',body})).status,400);
    }
    const response = await app.request('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:'{'},env);
    assert.equal(response.status,400);
});
test('favorites cannot be deleted or listed through another user', async () => {
    const created = await request('/favorites',{method:'POST',body:{item_type:'track',item_id:'fixture-track',title:'Fictional track',user_id:2}});
    assert.equal(created.status,201);
    const favorites = (await (await request('/favorites',{id:2})).json()).favorites;
    assert.deepEqual(favorites,[]);
    const response = await request('/favorites/fixture-track',{id:2,method:'DELETE'});
    assert.equal(response.status,404);
    assert.equal((await (await request('/favorites')).json()).favorites.length,1);
});
