import { generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse } from '@simplewebauthn/server';
import {put,get,del} from '@vercel/blob';
import {randomUUID,randomBytes,createHmac,timingSafeEqual} from 'node:crypto';
const origin=process.env.PASSKEY_ORIGIN||'https://jm-portfolio-passkey.vercel.app', rpID=new URL(origin).hostname;
const path=(kind,id)=>'task8/'+kind+'/'+id+'.json';
const uid=()=>randomBytes(24).toString('base64url');
// Security-critical reads must bypass Vercel Blob's CDN cache: otherwise
// deleted sessions, consumed challenges, or removed credentials can remain valid
// for up to 60 seconds after a write or delete.
async function read(p){const f=await get(p,{access:'private',useCache:false});return f?await new Response(f.stream).json():null}
async function save(p,data){await put(p,JSON.stringify(data),{access:'private',addRandomSuffix:false,allowOverwrite:true,contentType:'application/json'})}
function sign(payload){const b=Buffer.from(JSON.stringify(payload)).toString('base64url');const mac=createHmac('sha256',process.env.SESSION_SECRET).update(b).digest('base64url');return b+'.'+mac}
function unsign(value){if(!value||!value.includes('.')||!process.env.SESSION_SECRET)return null;const [b,mac]=value.split('.');const expected=createHmac('sha256',process.env.SESSION_SECRET).update(b).digest('base64url');if(mac.length!==expected.length||!timingSafeEqual(Buffer.from(mac),Buffer.from(expected)))return null;try{return JSON.parse(Buffer.from(b,'base64url').toString())}catch{return null}}
function cookie(req){return (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('t8_session='))?.slice(11)}
function out(res,status,data){res.setHeader('Cache-Control','no-store');return res.status(status).json(data)}
const fail=(status,error)=>({status,error});
async function account(req){const token=unsign(cookie(req));if(!token||token.exp<Date.now()||!(await read(path('sessions',token.sid))))throw fail(401,'로그인이 필요합니다.');const a=await read(path('accounts',token.aid));if(!a)throw fail(401,'계정을 찾을 수 없습니다.');return {a,token}}
async function distinctPrivateItems(a){
 if(a.itemsVersion!==2){
  const stamp=a.name+' / '+a.id.slice(0,8);
  a.items=(a.items||[]).map((item,i)=>({...item,content:item.content+' · '+stamp+' 계정만의 가상 기록 '+(i+1)}));
  a.itemsVersion=2;
  await save(path('accounts',a.id),a);
 }
 return a.items;
}
async function handler(req,res){if(req.method==='GET'&&req.query.action==='private'){try{const {a}=await account(req);return out(res,200,{accountId:a.id,name:a.name,items:await distinctPrivateItems(a)})}catch(e){return out(res,e.status||401,{error:e.error||'로그인이 필요합니다.'})}}if(req.method!=='POST')return out(res,405,{error:'POST only'});if(!process.env.BLOB_READ_WRITE_TOKEN||!process.env.SESSION_SECRET)return out(res,503,{error:'인증 서버 환경변수 설정이 필요합니다.'});const action=req.query.action;const p=req.body||{};try{
if(action==='register-options'){let a;if(p.create){if(typeof p.name!=='string'||!p.name.trim()||p.name.length>32)throw fail(400,'계정 별칭을 입력하세요.');a={id:randomUUID(),name:p.name.trim(),credentials:[],items:[{category:'PROJECT',title:'아카이브 리뉴얼',content:'가상 프로젝트 메모: 11월 화면 구조 정리'},{category:'TARGETS',title:'관심 분야',content:'가상 목록: 클라우드 보안 / 웹 애플리케이션 보안'},{category:'RETROSPECT',title:'이번 주 회고',content:'가상 회고: 작은 실습을 반복하며 이해한 점 기록'}]}}else{a=(await account(req)).a}const options=await generateRegistrationOptions({rpName:'Jimin Private Lab',rpID,userID:Buffer.from(a.id),userName:a.name,attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},excludeCredentials:a.credentials.map(c=>({id:c.id,transports:c.transports||[]}))});const flowId=uid();await save(path('flows',flowId),{type:'register',challenge:options.challenge,account:a,created:Date.now(),newAccount:!!p.create});return out(res,200,{options,flowId})}
if(action==='register-verify'){const flow=await read(path('flows',p.flowId));if(!flow||flow.type!=='register'||Date.now()-flow.created>180000)throw fail(400,'등록 질문이 없거나 만료되었습니다.');await del(path('flows',p.flowId));if(!flow.newAccount){const current=await account(req);if(current.a.id!==flow.account.id)throw fail(403,'계정이 다릅니다.');flow.account=current.a}
const verify=await verifyRegistrationResponse({response:p.credential,expectedChallenge:flow.challenge,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true});if(!verify.verified||!verify.registrationInfo)throw fail(403,'패스키 등록 검증에 실패했습니다.');const {credential,credentialDeviceType,credentialBackedUp}=verify.registrationInfo;const a=flow.account;if(a.credentials.some(c=>c.id===credential.id))throw fail(409,'이미 등록된 패스키입니다.');a.credentials.push({id:credential.id,publicKey:Buffer.from(credential.publicKey).toString('base64url'),counter:credential.counter,transports:p.credential?.response?.transports||[],name:String(p.name||'패스키').slice(0,40),createdAt:new Date().toISOString(),credentialDeviceType,credentialBackedUp});await save(path('accounts',a.id),a);return out(res,200,{accountId:a.id,registered:true,credentialCount:a.credentials.length,credentialName:a.credentials.at(-1).name})}
if(action==='audit-revoked-options'){
 const {a}=await account(req);
 // Intentionally omit allowCredentials to let the authenticator offer local credentials,
 // including a key no longer trusted by this account. Verification uses the normal login route.
 const options=await generateAuthenticationOptions({rpID,userVerification:'required',allowCredentials:[]});
 const flowId=uid();
 await save(path('flows',flowId),{type:'login',challenge:options.challenge,accountId:a.id,created:Date.now(),audit:'revoked-login'});
 return out(res,200,{flowId,options,test:'revoked-passkey'});
}
if(action==='audit-session-start'){
 const {a,token}=await account(req);
 const ticket=uid();
 await save(path('audits',ticket),{type:'old-cookie-replay',token:{sid:token.sid,aid:token.aid,exp:token.exp},created:Date.now()});
 return out(res,200,{ticket,test:'old-cookie-replay',accountName:a.name});
}
if(action==='audit-session-replay'){
 // A one-use random ticket, never the cookie itself, is sent by the browser after logout.
 // Recreate the old signed HttpOnly cookie only on the server and call the real session guard.
 if(typeof p.ticket!=='string'||!/^[-_A-Za-z0-9]{24,80}$/.test(p.ticket))throw fail(400,'검사 티켓이 올바르지 않습니다.');
 const audit=await read(path('audits',p.ticket));
 if(!audit||audit.type!=='old-cookie-replay'||Date.now()-audit.created>120000)throw fail(410,'세션 검사 티켓이 없거나 만료되었습니다.');
 await del(path('audits',p.ticket));
 let replayStatus=200;
 try{await account({headers:{cookie:'t8_session='+sign(audit.token)}})}
 catch(e){replayStatus=e.status||500}
 const blocked=replayStatus===401;
 return out(res,blocked?401:500,{test:'old-cookie-replay',replayedOldCookieOnServer:true,originalSessionHTTPStatus:replayStatus,blocked,privateDataReturned:false,message:blocked?'로그아웃 이전 쿠키를 서버에서 재사용했지만 401로 거절되었습니다.':'이전 쿠키의 세션이 남아 있습니다. 확인이 필요합니다.'});
}
if(action==='audit-discard-flows'){
 const {a}=await account(req);
 const ids=Array.isArray(p.flowIds)?[...new Set(p.flowIds)]:[];
 if(ids.length===0||ids.length>4||ids.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(id)))throw fail(400,'검사 질문 ID 목록이 올바르지 않습니다.');
 let discarded=0;
 for(const id of ids){
  const item=await read(path('flows',id));
  if(!item)continue;
  const belongsToSession=(item.type==='register'&&!item.newAccount&&item.account?.id===a.id)||(item.type==='login'&&item.accountId===a.id);
  if(!belongsToSession)throw fail(403,'이 계정의 검사 질문이 아닙니다.');
  await del(path('flows',id));discarded++;
 }
 return out(res,200,{discarded,test:'challenge-comparison-cleanup'});
}
if(action==='login-options'){
 let a=null;
 if(p.accountId){
  if(typeof p.accountId!=='string'||!/^[0-9a-f-]{36}$/i.test(p.accountId))throw fail(400,'계정 ID 형식이 올바르지 않습니다.');
  a=await read(path('accounts',p.accountId));
  if(!a||!a.credentials.length)throw fail(401,'이 계정에 사용 가능한 패스키가 없습니다.');
 }
 // No accountId => discoverable/passkey-first authentication; no last-account dependency.
 const options=await generateAuthenticationOptions({rpID,userVerification:'required',...(a?{allowCredentials:a.credentials.map(c=>({id:c.id,transports:c.transports||[]}))}:{allowCredentials:[]})});
 const flowId=uid();await save(path('flows',flowId),{type:'login',challenge:options.challenge,accountId:a?.id||null,created:Date.now()});
 return out(res,200,{options,flowId});
}
if(action==='login-verify'){const flow=await read(path('flows',p.flowId));if(!flow||flow.type!=='login'||Date.now()-flow.created>180000)throw fail(401,'로그인 질문이 없거나 만료되었습니다.');await del(path('flows',p.flowId));let targetId=flow.accountId;
 if(!targetId){
  // WebAuthn discoverable credentials expose a userHandle created from the server-side account UUID.
  // userHandle alone is NOT trusted: the following credential ID lookup + signed challenge verification establish identity.
  const handle=p.credential?.response?.userHandle;
  if(typeof handle!=='string'||!handle)throw fail(403,'계정 식별에 필요한 패스키 사용자 정보가 없습니다. 기존 브라우저 계정으로 로그인해 주세요.');
  const decoded=Buffer.from(handle,'base64url').toString('utf8');
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(decoded))throw fail(403,'패스키에 연결된 계정 식별자가 올바르지 않습니다.');
  targetId=decoded;
 }
 const a=await read(path('accounts',targetId));
 const c=a?.credentials.find(x=>x.id===p.credential?.id);
 if(!c)throw fail(403,'이 계정에 등록되지 않은 패스키입니다.');const verify=await verifyAuthenticationResponse({response:p.credential,expectedChallenge:flow.challenge,expectedOrigin:origin,expectedRPID:rpID,credential:{id:c.id,publicKey:Buffer.from(c.publicKey,'base64url'),counter:c.counter,transports:c.transports},requireUserVerification:true});if(!verify.verified)throw fail(403,'서명 확인 실패');c.counter=verify.authenticationInfo.newCounter;await save(path('accounts',a.id),a);const sid=uid();const exp=Date.now()+1000*60*45;await save(path('sessions',sid),{aid:a.id,exp});res.setHeader('Set-Cookie','t8_session='+sign({sid,aid:a.id,exp})+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2700');return out(res,200,{authenticated:true,accountId:a.id,name:a.name})}
if(action==='logout'){const t=unsign(cookie(req));if(t?.sid)await del(path('sessions',t.sid));res.setHeader('Set-Cookie','t8_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return out(res,200,{loggedOut:true})}
if(action==='private'){const {a}=await account(req);return out(res,200,{accountId:a.id,name:a.name,items:await distinctPrivateItems(a)})}
if(action==='private-target'){
 const {a}=await account(req);
 if(typeof p.targetAccountId!=='string'||!p.targetAccountId.trim())throw fail(400,'검사 대상 계정 ID를 입력하세요.');
 if(p.targetAccountId!==a.id)throw fail(403,'다른 계정의 비공개 기록 접근은 허용되지 않습니다.');
 return out(res,200,{accountId:a.id,name:a.name,items:await distinctPrivateItems(a)});
}
if(action==='list'){const {a}=await account(req);return out(res,200,{credentials:a.credentials.map(c=>({id:c.id,name:c.name,createdAt:c.createdAt,publicKey:c.publicKey.slice(0,28)+'…'}))})}
if(action==='delete'){const {a}=await account(req);if(a.credentials.length<=1)throw fail(409,'마지막 패스키는 삭제할 수 없습니다.');const old=a.credentials.length;a.credentials=a.credentials.filter(c=>c.id!==p.credentialId);if(a.credentials.length===old)throw fail(404,'패스키를 찾을 수 없습니다.');await save(path('accounts',a.id),a);return out(res,200,{deleted:true})}
return out(res,404,{error:'Unknown action'});
}catch(e){console.error('task8',action,e?.message);return out(res,e.status||400,{error:e.error||'인증 또는 요청 검증에 실패했습니다.'})}}
export default handler;