import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

function client(fetch) {
    const items = new Map([['refreshToken','old-token']]);
    const storage = {getItem:k=>items.get(k)??null,setItem:(k,v)=>items.set(k,v),removeItem:k=>items.delete(k)};
    const context = vm.createContext({window:{location:{hostname:'localhost',href:''}},sessionStorage:storage,localStorage:storage,
        fetch,console:{error(){}},atob,URLSearchParams,document:{addEventListener(){},getElementById(){return null;}}});
    vm.runInContext(readFileSync(new URL('../../client/js/api.js',import.meta.url),'utf8'),context);
    return {context,items};
}
test('parallel browser refresh callers send one request and share the rotated token',async()=>{
    let calls=0, complete;
    const {context,items} = client(async()=>{calls++;await new Promise(resolve=>{complete=resolve;});return Response.json({accessToken:'new-access',refreshToken:'new-refresh'});});
    const pending = vm.runInContext('Promise.all(Array.from({length:10},()=>refreshAccessToken()))',context);
    assert.equal(calls,1); complete();
    assert.equal((await pending).every(Boolean),true);
    assert.equal(items.get('refreshToken'),'new-refresh');
});
test('failed refresh clears local authentication without recursively calling logout',async()=>{
    let calls=0;
    const {context,items}=client(async()=>{calls++;return Response.json({error:{message:'revoked'}},{status:401});});
    assert.equal(await vm.runInContext('refreshAccessToken()',context),false);
    assert.equal(calls,1); assert.equal(items.has('refreshToken'),false);
});
