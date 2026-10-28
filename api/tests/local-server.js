// Offline integration harness: actual Hono routes and SQL, a minimal D1 adapter.
// Not Cloudflare runtime validation. Fictional data only. Never deploy this file.
import {DatabaseSync} from 'node:sqlite';
import {createServer} from 'node:http';
import {mkdtempSync,readFileSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import app from '../src/index.js';
const folder=mkdtempSync(join(tmpdir(),'swopmobile-review-'));
const sqlite=new DatabaseSync(join(folder,'fixture.db'));
sqlite.exec('PRAGMA foreign_keys=ON');
for(const name of readdirSync(new URL('../migrations/',import.meta.url)).sort())sqlite.exec(readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8'));
sqlite.exec(readFileSync(new URL('../seeds/dev-data.sql',import.meta.url),'utf8'));
const DB={prepare(sql){const stmt=sqlite.prepare(sql);let values=[];const q={bind(...args){values=args;return q;},async first(){return stmt.get(...values)||null;},async all(){return {results:stmt.all(...values)};},async run(){const r=stmt.run(...values);return {success:true,meta:{changes:Number(r.changes),last_row_id:Number(r.lastInsertRowid)}};}};return q;}};
const env={DB,REVIEW_FIXTURE:'1',JWT_ACCESS_SECRET:'local-fixture-only-do-not-deploy-32-characters',FRONTEND_URL:'http://localhost:5173'};
const server=createServer(async(req,res)=>{try{const buffers=[];for await(const b of req)buffers.push(b);const result=await app.fetch(new Request('http://localhost:8787'+req.url,{method:req.method,headers:req.headers,...(['GET','HEAD'].includes(req.method)?{}:{body:Buffer.concat(buffers)})}),env);res.writeHead(result.status,Object.fromEntries(result.headers));res.end(Buffer.from(await result.arrayBuffer()));}catch{res.writeHead(500);res.end('Harness failed');}});
server.listen(8787,'127.0.0.1',()=>console.log('Fictional SQLite harness: http://localhost:8787'));
process.on('SIGTERM',()=>server.close(()=>{sqlite.close();process.exit();}));
