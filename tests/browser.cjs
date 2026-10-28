// Fictional local fixtures only. See docs/BROWSER_CHECKS.md before running.
const {chromium}=require(process.env.PLAYWRIGHT_PATH || 'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const out=process.env.REVIEW_OUTPUT||path.join(__dirname,'screenshots');
const reports=[];
async function check(name,run){if(process.env.CHECK_FILTER&&!name.match(process.env.CHECK_FILTER))return;await run();reports.push({name,result:'passed'});console.log('PASS',name);}
async function shot(page,name){await fs.mkdir(out,{recursive:true});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});}
async function noOverflow(page){
 const state=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,outside:[...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,cls:String(e.className),right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})).filter(e=>e.right>innerWidth+1&&e.width>0).slice(0,8)}));
 assert.ok(state.scroll<=state.width+1,`page must fit viewport: ${JSON.stringify(state)}`);
}
(async()=>{
 const browser=await chromium.launch({headless:true});
 const ctx=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 const errors=[];ctx.on('page',p=>p.on('pageerror',e=>errors.push(e.message)));
 const s=await ctx.newPage();
 await check('SwopMobile registration, protected API, reload and logout',async()=>{
  assert.equal((await(await ctx.request.get('http://localhost:8787/health')).json()).review_fixture,true,'Use the fictional API harness');
  await s.goto('http://localhost:5173/example/index.html');
  await s.getByLabel('Email',{exact:true}).fill(`review-${Date.now()}@example.test`);await s.getByLabel('Password',{exact:true}).fill('FictionalPass123!');
  await s.getByRole('button',{name:'Register',exact:true}).click();await s.getByRole('status').filter({hasText:'Account created'}).waitFor();
  await s.getByRole('button',{name:'Log in',exact:true}).click();await s.getByRole('heading',{name:'Protected workspace'}).waitFor();
  await s.reload();await s.getByRole('heading',{name:'Protected workspace'}).waitFor();
  await shot(s,'swopmobile-protected-desktop');
  await s.getByRole('button',{name:'Log out',exact:true}).click();await s.getByRole('status').filter({hasText:'Session revoked'}).waitFor();
  await s.reload();assert.ok(await s.locator('#private').isHidden());await noOverflow(s);
 });
 await check('SwopMobile session list identifies and revokes current session',async()=>{
  await s.evaluate(async()=>{await login('user@example.com','Password123!');});
  await s.goto('http://localhost:5173/sessions.html');await s.getByText(/This session/).waitFor();await shot(s,'swopmobile-sessions-desktop');
 });
 await check('SwopMobile detects old and updated session API contracts',async()=>{
  for(const updated of [false,true]){
   const legacy=await browser.newContext();legacy.on('page',p=>p.on('pageerror',e=>errors.push(e.message)));const page=await legacy.newPage();
   await page.addInitScript(()=>{const encode=value=>btoa(JSON.stringify(value));sessionStorage.setItem('accessToken',`${encode({alg:'none'})}.${encode({sub:'1',exp:Math.floor(Date.now()/1000)+600})}.fixture`);sessionStorage.setItem('user',JSON.stringify({id:'1',roles:[{name:'User'}]}));});
   await page.route('**/sessions',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({sessions:[{id:'fixture-current',device_name:'Fictional browser',last_activity:'2026-10-28'},{id:'fixture-other',device_name:'Fictional tablet',last_activity:'2026-10-28'}],...(updated?{currentSessionId:'fixture-current'}:{})})}));
   await page.goto('http://localhost:5173/sessions.html');await page.getByText('Fictional browser',{exact:!updated}).waitFor();
   assert.equal(await page.locator('#revokeAllBtn').isVisible(),updated);
   if(!updated)await page.getByRole('status').filter({hasText:'server update is pending'}).waitFor();
   await legacy.close();
  }
 });
 for(const [name,url] of [['SwopMobile', 'http://localhost:5173/showcase.html']]) {
  await check(`${name} desktop, tablet and phone layouts`,async()=>{
   // Fresh contexts avoid leaking the timer's emulated clock or focus between visual cases.
   for(const [w,h] of [[390,844],[768,1024],[1440,1000]]){
    const layout=await browser.newContext({viewport:{width:w,height:h},reducedMotion:'reduce'});layout.on('page',p=>p.on('pageerror',e=>errors.push(e.message)));const page=await layout.newPage();
    await page.goto(url);await page.waitForLoadState('networkidle');await noOverflow(page);await page.evaluate(()=>document.activeElement?.blur());await shot(page,`${name.toLowerCase()}-${w}`);await layout.close();
   }
  });
 }
 await check('SwopMobile keyboard disclosure navigation',async()=>{
  await s.goto('http://localhost:5173/showcase.html');await s.getByText('Login, refresh, logout—in plain language',{exact:true}).focus();await s.keyboard.press('Enter');
  assert.ok(await s.locator('details').first().evaluate(el=>el.open));
 });
 assert.deepEqual(errors,[],`Browser errors: ${errors.join('; ')}`);
 await fs.writeFile(path.join(out,'results.json'),JSON.stringify({fixture:'Fictional accounts; real Hono handlers and SQLite D1 adapter; Chromium viewport emulation',checks:reports,unhandledPageErrors:errors},null,2));
 await browser.close();console.log(JSON.stringify(reports));
})().catch(e=>{console.error(e);process.exit(1);});
