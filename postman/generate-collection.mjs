import {SignJWT} from 'jose';
import {writeFileSync} from 'node:fs';
const items=[];
function add(name,method,url,body,status,token,after=''){
 const header=[{key:'Content-Type',value:'application/json'}];if(token)header.push({key:'Authorization',value:`Bearer {{${token}}}`});
 items.push({name,request:{method,header,url:'{{baseUrl}}'+url,...(body===undefined?{}:{body:{mode:'raw',raw:typeof body==='string'?body:JSON.stringify(body),options:{raw:{language:'json'}}}})},event:[{listen:'test',script:{type:'text/javascript',exec:[`pm.test(${JSON.stringify(name)}, () => pm.response.to.have.status(${status}));`,after].filter(Boolean)}}]});
}
add('Local health','GET','/health',undefined,200);
add('Invalid credentials input','POST','/auth/login',{email:42,password:'short'},400);
add('User login','POST','/auth/login',{email:'user@example.com',password:'Password123!'},200,null,"const d=pm.response.json();pm.collectionVariables.set('access',d.accessToken);pm.collectionVariables.set('refresh',d.refreshToken);");
add('Protected profile','GET','/user/me',undefined,200,'access');
add('User cannot list accounts','GET','/admin/users',undefined,403,'access');
const expired=await new SignJWT({sub:'2',type:'access',sid:'synthetic-expired'}).setProtectedHeader({alg:'HS256'}).setExpirationTime(0).sign(new TextEncoder().encode('local-fixture-only-do-not-deploy-32-characters'));
items.push({name:'Expired fixture token rejected',request:{method:'GET',url:'{{baseUrl}}/user/me',header:[{key:'Authorization',value:'Bearer '+expired}]},event:[{listen:'test',script:{exec:["pm.test('Expired token returns 401',()=>pm.response.to.have.status(401));"]}}]});
add('Create own fictional job','POST','/jobs',{company:'Fictional Co',position:'Example engineer',user_id:1},201,'access',"pm.collectionVariables.set('jobId',pm.response.json().job.id);");
add('Admin login','POST','/auth/login',{email:'admin@example.com',password:'Password123!'},200,null,"pm.collectionVariables.set('adminAccess',pm.response.json().accessToken);");
add('Admin can list accounts','GET','/admin/users',undefined,200,'adminAccess');
add('Even admin cannot read another private job','GET','/jobs/{{jobId}}',undefined,404,'adminAccess');
add('Even admin cannot change another private job','PUT','/jobs/{{jobId}}',{company:'Changed',position:'Example'},404,'adminAccess');
add('User can delete own fixture','DELETE','/jobs/{{jobId}}',undefined,200,'access');
add('User refreshes credentials','POST','/auth/refresh',{refreshToken:'{{refresh}}'},200,null,"const d=pm.response.json();pm.collectionVariables.set('access',d.accessToken);pm.collectionVariables.set('refresh',d.refreshToken);");
add('User revokes own sessions','DELETE','/user/sessions',undefined,200,'access');
add('Revoked access rejected','GET','/user/me',undefined,401,'access');
add('Revoked refresh rejected','POST','/auth/refresh',{refreshToken:'{{refresh}}'},401);
add('Malformed JSON rejected','POST','/auth/login','{',400);
writeFileSync(new URL('swopmobile.postman_collection.json',import.meta.url),JSON.stringify({info:{name:'SwopMobile — offline fictional API checks',schema:'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',description:'Run only against api/tests/local-server.js. Fictional seeded credentials, never a production API. The expired JWT is signed with a public fixture-only key.'},variable:[{key:'baseUrl',value:'http://localhost:8787'}],item:items},null,2)+'\n');
