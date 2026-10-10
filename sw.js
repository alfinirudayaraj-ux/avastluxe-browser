// ═══════════════════════════════════════════════════════════════════════════
// AvastLuxe Shield Agent — background worker (self-contained, no imports)
// • Middleman: scam/suspicious navigations NEVER fetch — blocked page shown
// • Background VERIFY: DNS + domain age + blocklist + phishing feed + page
// • Notifications raised from the worker (works while tab minimized)
// ═══════════════════════════════════════════════════════════════════════════
"use strict";

// ── Engine (same rules as the page, inlined so the worker is standalone) ──
const URL_RULES=[
 {re:/bit\.ly|tinyurl|t\.co|rebrand\.ly|cutt\.ly|is\.gd|s\.id|short\./i,w:22,label:"URL shortener hides the final destination"},
 {re:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,w:25,label:"Raw IP host — no legitimate brand uses this"},
 {re:/https?:\/\/[^\s]*@/i,w:30,label:"'@' trick — browser ignores everything before @"},
 {re:/[а-яё]|xn--/i,w:30,label:"Lookalike domain (IDN/punycode homoglyph)"},
 {re:/(hdfc|sbi|icici|axis|paytm|phonepe|amazon|flipkart|apple|microsoft|netflix|paypal|whatsapp|instagram|facebook|google)[-_.]?[a-z0-9]*\.(xyz|top|shop|click|loan|tk|ml|ga|gq|cf|buzz|store|online|sbs)/i,w:35,label:"Famous brand on a suspicious cheap domain"},
 {re:/[a-z0-9-]*(login|secure|verify|update|banking|wallet|alert|kyc|support)[a-z0-9-]*\.[a-z]{2,}/i,w:22,label:"Domain imitates a login/security page"},
 {re:/https?:\/\/(?!(www\.)?(google|youtube|github|microsoft|apple|amazon)\.com)[\w-]+\.(xyz|top|click|shop|tk|ml|ga|gq|cf|buzz|loan)/i,w:32,label:"High-risk TLD (xyz/top/click/tk…)"}];
const MSG_RULES=[
 {re:/prize|won|winner|congratulat|lottery|gift card|reward points|spin (to|and) win|free iphone|free gift/i,w:25,label:"Claims an unbelievable prize or reward"},
 {re:/pay\s*(rs|₹|\$|fee|deposit|registration|advance)|registration fee|processing fee|claim.*fee|refundable deposit/i,w:30,label:"Advance-fee demand (pay to receive money)"},
 {re:/urgent|immediately|within 24|last (day|chance|warning)|account (blocked|suspended|deactivated|locked)|verify now|act now|final notice/i,w:20,label:"Urgency / threats to rush you"},
 {re:/otp|pin number|\bcvv\b|password|login credentials|verify your account|share (your|the) (otp|code)/i,w:30,label:"Asks for OTP / password / code"},
 {re:/kyc|pan\s*(card)?\s*link|aadhaar\s*update|rbi\s*notice|income\s*tax\s*refund|electricity\s*(bill|disconnection)|cibil/i,w:22,label:"Impersonates KYC / RBI / tax / utility authority"},
 {re:/guaranteed return|double your money|\b10x\b|pump group|earn\s*\d+.*\/\s*day|part.?time job.*\d{4,}|like (videos?|youtube).*(earn|rs)/i,w:30,label:"Fake job / guaranteed-returns lure"},
 {re:/parcel|customs (duty|fee)|courier.*held|delivery failed.*fee|package.*pay/i,w:25,label:"Fake parcel / customs-fee scam"},
 {re:/qr.*scan.*(receive|refund)|upi.*(collect|request)|send ₹?1 (to verify|for verification)/i,w:30,label:"UPI/QR reversal trick (paying disguised as receiving)"},
 {re:/click this link to (claim|get|verify)|claim.*(reward|cashback|offer).*link/i,w:22,label:"Classic bait-to-link phrasing"}];
const TRUSTED=["google.com","youtube.com","github.com","microsoft.com","apple.com","amazon.in","amazon.com","hdfcbank.com","icicibank.com","axisbank.com","kotak.com","sbi.co.in","onlinesbi.com","paypal.com","netflix.com","phonepe.com","paytm.com","npci.org.in","cybercrime.gov.in","reddit.com","whatsapp.com","facebook.com","instagram.com","flipkart.com","irctc.co.in"];
const BRANDS=[
 {pat:/icici/i,name:"ICICI Bank",official:["icicibank.com"]},
 {pat:/hdfc/i,name:"HDFC Bank",official:["hdfcbank.com"]},
 {pat:/(^|[^a-z])sbi([^a-z]|$)/i,name:"SBI",official:["onlinesbi.com","sbi.co.in"],org:/state bank/i},
 {pat:/(^|[^a-z])axis([^a-z]|$)/i,name:"Axis Bank",official:["axisbank.com"]},
 {pat:/kotak/i,name:"Kotak Bank",official:["kotak.com"]},
 {pat:/(^|[^a-z])pnb([^a-z]|$)/i,name:"PNB",official:["pnb.co.in"],org:/punjab national/i},
 {pat:/bankofbaroda|(^|[^a-z])bob([^a-z]|$)/i,name:"Bank of Baroda",official:["bankofbaroda.in"],org:/bank of baroda/i},
 {pat:/canara/i,name:"Canara Bank",official:["canarabank.com"]},
 {pat:/paytm/i,name:"Paytm",official:["paytm.com"]},
 {pat:/phonepe/i,name:"PhonePe",official:["phonepe.com"]},
 {pat:/paypal/i,name:"PayPal",official:["paypal.com"]},
 {pat:/amazon/i,name:"Amazon",official:["amazon.com","amazon.in"]},
 {pat:/flipkart/i,name:"Flipkart",official:["flipkart.com"]},
 {pat:/(^|[^a-z])apple([^a-z]|$)/i,name:"Apple",official:["apple.com","icloud.com"]},
 {pat:/microsoft|outlook|office365/i,name:"Microsoft",official:["microsoft.com","office.com","outlook.com","live.com"]},
 {pat:/netflix/i,name:"Netflix",official:["netflix.com"]},
 {pat:/instagram/i,name:"Instagram",official:["instagram.com","facebook.com"]},
 {pat:/facebook|(^|[^a-z0-9])fb([^a-z0-9]|$)/i,name:"Facebook",official:["facebook.com","fb.com"]},
 {pat:/telegram/i,name:"Telegram",official:["telegram.org"]},
 {pat:/binance/i,name:"Binance",official:["binance.com"]},
 {pat:/zerodha/i,name:"Zerodha",official:["zerodha.com"]},
 {pat:/groww/i,name:"Groww",official:["groww.in"]},
 {pat:/irctc/i,name:"IRCTC",official:["irctc.co.in"]},
 {pat:/(^|[^a-z])jio([^a-z]|$)/i,name:"Jio",official:["jio.com"]},
 {pat:/airtel/i,name:"Airtel",official:["airtel.in","airtel.com"]},
 {pat:/(^|[^a-z])dhl([^a-z]|$)/i,name:"DHL",official:["dhl.com"]}
];
const RISKY_TLDS=/^(io|xyz|top|tk|ml|ga|gq|cf|buzz|sbs|loan|click|shop|store|online|site|live|vip|rest)$/;
function brandCheck(uh,path){const b=BRANDS.find(x=>x.pat.test(uh+" "+(path||"")));if(!b)return null;
 return{b,home:b.official.some(o=>uh===o||uh.endsWith("."+o))}}
function analyzeText(input){
 if(!input||!input.trim())return{score:0,verdict:"safe",hits:[],trusted:false,kind:"empty"};
 const t=input.trim();let score=0,brandPen=0,alleged=null;const hits=[];
 const isUrl=/https?:\/\/|www\.|\.(com|in|net|org|xyz|top|click|shop|tk|io|co)\b/i.test(t);
 for(const r of(isUrl?URL_RULES.concat(MSG_RULES):MSG_RULES)){if(r.re.test(t)){score+=r.w;if(r.label)hits.push(r.label)}}
 let trusted=false,host="";
 try{const u=new URL(/^https?:\/\//i.test(t)?t:"https://"+t.split(/\s/)[0]);host=u.hostname.toLowerCase();
 trusted=TRUSTED.some(x=>host===x||host.endsWith("."+x));
 if(u.protocol==="http:"){score+=10;hits.push("Not encrypted (http) — logins can be stolen")}
 if((host.match(/-/g)||[]).length>=3){score+=12;hits.push("Excessive hyphens — typosquat pattern")}
 if(host.split(".").length>3){score+=10;hits.push("Deep subdomain hides the true brand")}
 if(/whatsapp/i.test(t)&&!host.endsWith("whatsapp.com")&&!host.endsWith("whatsapp.net")){score+=28;hits.push("Impersonates WhatsApp on a foreign domain")}
 const bc=brandCheck(host,u.pathname||"");
 if(bc&&!bc.home){score+=40;brandPen+=40;if(!alleged)alleged={name:bc.b.name,official:bc.b.official,orgRe:bc.b.org||null};hits.push("Uses "+bc.b.name+"'s name but is NOT "+bc.b.official[0]+" — the real "+bc.b.name+" never operates from here");
  const tld=host.split(".").pop()||"";
  if(RISKY_TLDS.test(tld)){score+=15;hits.push("Bank/brand lure parked on risky suffix (."+tld+")")}
  if(/(login|verify|dashboard|secure|account|update|kyc|bank)([-_.]|$)/i.test(u.pathname||"")){score+=15;hits.push("Banking-action page on a non-official domain — credential-harvest layout")}}
 else if(bc&&bc.home){score=Math.max(0,score-15);hits.push("Confirmed on "+bc.b.name+"'s real official domain")}
 if(t.length>140){score+=8;hits.push("Abnormally long text/URL — obfuscation")}}catch{}
 const seen=new Set([host]);
 for(const m of(t.match(/https?:\/\/[^\s"'<>]+/gi)||[]).slice(0,4)){
  let uh="";try{uh=new URL(m).hostname.toLowerCase()}catch{continue}
  if(!uh||seen.has(uh))continue;seen.add(uh);
  const eb=brandCheck(uh,"");
  if(eb&&!eb.home){score+=40;brandPen+=40;if(!alleged)alleged={name:eb.b.name,official:eb.b.official,orgRe:eb.b.org||null};hits.push("Links to "+eb.b.name+" impostor "+uh+" — the real "+eb.b.name+" lives only at "+eb.b.official.join(", "))}
 }
 if(trusted)score=Math.max(0,score-60);
 score=Math.min(100,Math.round(score));
 return{score,verdict:score>=60?"scam":score>20?"suspicious":"safe",hits:[...new Set(hits)],trusted,host,kind:isUrl?"url":"message",brandPen,brandAlleged:alleged};
}

// ── Truth engine: keyless multi-source verification ─────────────────────────
function luxFetch(url,opts,ms){const c=new AbortController();const t=setTimeout(()=>c.abort(),ms||6000);return fetch(url,{...(opts||{}),signal:c.signal}).finally(()=>clearTimeout(t))}
async function checkDns(host){
 try{const r=await luxFetch("https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(host)+"&type=A",{headers:{accept:"application/dns-json"}},2000);
  const j=await r.json();
  if(j&&j.Answer&&j.Answer.length)return{state:"clean",detail:"Resolves publicly ("+j.Answer.length+" records)"};
  return{state:"warn",detail:"No public DNS answer — possible hijack",penalty:15};
 }catch{return{state:"skip",detail:"DNS unreachable"}}
}
let luxRdapServers=null;
async function luxRdapDomain(host){
 const bare=host.replace(/^www\./,"");
 try{const r=await luxFetch("https://rdap.org/domain/"+encodeURIComponent(bare),{},2000);
  if(r.ok)return await r.json()}catch{}
 try{
  if(!luxRdapServers){const b=await luxFetch("https://data.iana.org/rdap/dns.json",{},2000);luxRdapServers=await b.json()}
  const tld=bare.split(".").pop();
  const svc=(luxRdapServers.services||[]).find(s=>(s[0]||[]).includes(tld));
  if(svc&&svc[1]&&svc[1][0]){const r2=await luxFetch(svc[1][0]+"domain/"+encodeURIComponent(bare),{},2500);
   if(r2.ok)return await r2.json()}
 }catch{}
 return null;
}
function luxVcardFn(entity){
 try{const f=entity.vcardArray&&entity.vcardArray[1];if(!Array.isArray(f))return"";
  return f.filter(x=>x[0]==="fn").map(x=>x[3]).filter(Boolean).join("; ")}catch{return""}
}
async function checkDomainAge(host){
 try{const j=await luxRdapDomain(host);
  if(!j)return{state:"skip",detail:"Registry unreachable",ageDays:null,org:"",registrar:""};
  const ents=j.entities||[];
  const org=ents.filter(e=>(e.roles||[]).includes("registrant")).map(luxVcardFn).filter(Boolean).join("; ");
  const registrar=ents.filter(e=>(e.roles||[]).includes("registrar")).map(luxVcardFn).filter(Boolean).join("; ");
  const ev=(j.events||[]).find(e=>e.eventAction==="registration");
  if(!ev||!ev.eventDate)return{state:"skip",detail:"No registration date published",ageDays:null,org,registrar};
  const days=Math.max(0,Math.round((Date.now()-new Date(ev.eventDate).getTime())/86400000));
  const base={ageDays:days,org,registrar};
  if(days<14)return{state:"bad",detail:"Born "+days+" day(s) ago — classic scam age",penalty:30,...base};
  if(days<90)return{state:"warn",detail:"Only "+days+" days old — suspicious",penalty:15,...base};
  if(days>365)return{state:"clean",detail:"Established "+(Math.round(days/365*10)/10)+" year(s)",bonus:10,...base};
  return{state:"clean",detail:"Age "+days+" days",...base};
 }catch{return{state:"skip",detail:"Registry unreachable",ageDays:null,org:"",registrar:""}}
}
function rootOf(host){const p=host.split(".");const two=["co.in","bank.in","co.uk","com.au","co.nz","com.br","co.za"];
 if(p.length>=3&&two.includes(p.slice(-2).join(".")))return p.slice(-3).join(".");return p.slice(-2).join(".")}
async function officialAck(officialDomain,testedRoot){
 try{const r=await luxFetch("https://api.allorigins.win/get?url="+encodeURIComponent("https://"+officialDomain+"/"),{},3000);
  const j=await r.json();const html=typeof(j&&j.contents)==="string"?j.contents.slice(0,150000).toLowerCase():"";
  if(html&&html.includes(testedRoot.toLowerCase()))return officialDomain+" publicly references "+testedRoot+" — same owner";
  return null;
 }catch{return null}
}
function brandOrgRe(al){if(al.orgRe)return al.orgRe;
 const w=al.name.split(" ")[0].replace(/[.*+?^${}()|[\]\\]/g,"\\$&");return new RegExp(w,"i")}
async function checkUrlhaus(url){
 try{const r=await luxFetch("https://urlhaus-api.abuse.ch/v1/url/",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"url="+encodeURIComponent(url)},2500);
  if(!r.ok)return{state:"skip",detail:r.status===401?"Blocklist unreachable (API now requires a key)":"Blocklist unreachable (HTTP "+r.status+")"};
  const j=await r.json();
  if(j&&j.query_status==="ok")return{state:"bad",detail:"URLhaus lists it as "+(j.threat||"malware"),guilty:true};
  if(j&&j.error)return{state:"skip",detail:"Blocklist unreachable ("+j.error+")"};
  return{state:"clean",detail:"Not on malware blocklist"};
 }catch{return{state:"skip",detail:"Blocklist unreachable"}}
}
let opFeedCache={t:0,lines:null};
async function fetchOpenPhish(){
 const now=Date.now();
 if(opFeedCache.lines&&now-opFeedCache.t<600000)return opFeedCache.lines;
 const direct="https://openphish.com/feed.txt";
 try{const r=await luxFetch(direct,{},3000);if(r.ok){const txt=await r.text();
  const lines=txt.split(/\r?\n/).map(s=>s.trim()).filter(s=>/^https?:\/\//i.test(s));
  if(lines.length>10){opFeedCache={t:now,lines};return lines}}}catch(e){}
 return null;
}
function normPhishU(u){try{const p=new URL(u);return (p.hostname+p.pathname).replace(/\/+$/,"").toLowerCase()}catch(e){return String(u).trim().replace(/\/+$/,"").toLowerCase()}}
async function checkOpenPhish(url){
 try{const feed=await fetchOpenPhish();
  if(!feed)return{state:"skip",detail:"Phishing feed unreachable"};
  const t=normPhishU(url);
  if(feed.some(e=>normPhishU(e)===t))return{state:"bad",detail:"OpenPhish: URL is on the live active-phishing feed",guilty:true};
  return{state:"clean",detail:"Not on OpenPhish active-phishing feed"};
 }catch(e){return{state:"skip",detail:"Phishing feed unreachable"}}
}
async function fetchPageText(url){
 try{const r=await luxFetch("https://api.allorigins.win/get?url="+encodeURIComponent(url),{},3000);
  const j=await r.json();
  if(typeof(j&&j.contents)==="string"&&j.contents.length>200)return j.contents.slice(0,20000);
  return null;
 }catch{return null}
}
async function cloudCheck(url,key){
 if(!key)return null;
 try{const r=await luxFetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+key,{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({client:{clientId:"avastluxe",clientVersion:"1.0.0"},threatInfo:{threatTypes:["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],platformTypes:["ANY_PLATFORM"],threatEntryTypes:["URL"],threatEntries:[{url}]}})},2000);
  const j=await r.json();
  if(j&&j.matches&&j.matches.length)return{state:"bad",detail:"Google: confirmed "+j.matches[0].threatType,guilty:true};
  return{state:"clean",detail:"Google: no match"};
 }catch{return{state:"skip",detail:"Google unreachable"}}
}
async function deepVerify(rawUrl,opts){
 opts=opts||{};
 const onProgress=opts.onProgress||function(){};
 let url=String(rawUrl||"").trim();if(!/^https?:\/\//i.test(url))url="https://"+url.split(/\s/)[0];
 let host="";try{host=new URL(url).hostname.toLowerCase()}catch{host=url}
 const base=analyzeText(url);
 const sources=[{name:"Offline engine",state:base.verdict==="safe"?"clean":"warn",detail:(base.hits.find(h=>/never operates|impostor/i.test(h))||base.hits[0]||"no lure signals")}];
 onProgress("Offline engine",sources[0].state);
 let score=base.score;const hits=[...base.hits];
 const alEarly=(base.brandPen||0)>0&&base.brandAlleged?base.brandAlleged:null;
 const ackP=alEarly?Promise.resolve(officialAck(alEarly.official[0],rootOf(host))).catch(()=>null):Promise.resolve(null);
 const htmlP=fetchPageText(url);
 onProgress("Live DNS","run");
 const[dns,age,haus,phish,ackEarly]=await Promise.all([checkDns(host),checkDomainAge(host),checkUrlhaus(url),checkOpenPhish(url),ackP]);
 onProgress("Live DNS",dns.state);onProgress("Domain age",age.state);onProgress("Blocklist",haus.state);onProgress("Phishing feed",phish.state);
 sources.push({name:"Live DNS",...dns});if(dns.penalty){score+=dns.penalty;hits.push(dns.detail)}
 sources.push({name:"Domain age",...age});if(age.penalty){score+=age.penalty;hits.push(age.detail)}
 if(age.bonus&&base.verdict==="safe")score=Math.max(0,score-age.bonus);
 sources.push({name:"Blocklist",...haus});if(haus.guilty){score=100;hits.unshift(haus.detail)}
 sources.push({name:"Phishing feed",...phish});if(phish.guilty){score=100;hits.unshift(phish.detail)}
 onProgress("Page scan","run");
 const html=await htmlP;
 let contentPen=0;
 if(html){const t=html.toLowerCase();let pen=0;const ch=[];
  const creds=/<input[^>]*(password|otp|cvv)|type=["']?password|enter (your )?(otp|password|cvv|upi pin)/.test(t),money=/(pay|fee|deposit|upi|wallet|card|cvv|refundable)/.test(t);
  if(creds&&money){pen+=25;ch.push("Live page harvests secrets alongside payments")}
  else if(creds){pen+=12;ch.push("Live page asks for secret credentials")}
  if(/won|prize|lottery|congratulations/.test(t)&&/(fee|deposit|pay now|claim.*pay)/.test(t)){pen+=20;ch.push("Live page pairs prizes with payments")}
  sources.push({name:"Live page scan",state:pen>=20?"bad":pen>0?"warn":"clean",detail:ch[0]||"No harvest patterns in page"});
  if(pen){contentPen=pen;score+=pen;ch.forEach(h=>hits.push(h))}
 }else sources.push({name:"Live page scan",state:"skip",detail:"Page unreadable (blocked/JS-walled)"});
 onProgress("Page scan",sources[sources.length-1].state);
 let sbGuilty=false;
 onProgress("Google check","run");
 const sb=await cloudCheck(url,opts.apiKey||"");if(sb){sources.push({name:"Google Safe Browsing",...sb});onProgress("Google check",sb.state);if(sb.guilty){sbGuilty=true;score=100;hits.unshift(sb.detail)}}else onProgress("Google check","skip");
 let acquitted=false;
 onProgress("Ownership proof","run");
 if((base.brandPen||0)>0&&base.brandAlleged&&!haus.guilty&&!sbGuilty){
  const al=base.brandAlleged;let proof=null;
  if(age.org&&brandOrgRe(al).test(age.org))proof="Registry owner matches "+al.name+" ("+age.org.slice(0,70)+")";
  if(!proof&&/idrbt/i.test(age.registrar||"")&&host.endsWith(".bank.in"))proof="Vetted banking zone — registrar IDRBT issues .bank.in only to real Indian banks";
  if(!proof&&ackEarly)proof=ackEarly;
  if(proof){acquitted=true;score=Math.max(0,score-(base.brandPen||0)-contentPen);
   for(let i=hits.length-1;i>=0;i--)if(/never operates|impostor/i.test(hits[i]))hits.splice(i,1);
   hits.unshift("Ownership proven: "+proof);
   sources.push({name:"Ownership proof",state:"clean",detail:proof});
   sources[0]={name:"Offline engine",state:"clean",detail:"Impersonation allegation dismissed — "+proof};onProgress("Ownership proof","clean")}
  else{
   score=Math.max(score,60);
   if(!hits.some(h=>/FAKE SCAM/i.test(h)))hits.unshift("FAKE SCAM WEBSITE/LINK: wears "+al.name+"'s name with no ownership proof — the real "+al.name+" never operates from here. This is a fake scam website, url and link. Entering it risks stolen logins, OTPs and wallet drain.");
   if(!html&&!sources.some(s=>s.name==="Concealment test"))sources.push({name:"Concealment test",state:"bad",detail:"Brand alleged + no ownership proof + content hidden = fake scam"});
   onProgress("Ownership proof","bad")}
 }else onProgress("Ownership proof","skip");
 const reputable=base.trusted||(age.ageDays!==null&&age.ageDays>=730&&!dns.penalty);
 if(sources.some(s=>s.name==="Live page scan"&&s.state==="skip")&&!haus.guilty&&!sbGuilty&&!reputable&&!acquitted&&score<60){
  score=60;
  hits.unshift("FAKE SCAM WEBSITE/LINK: hides its page from security inspection, too new and unknown to verify, with no trusted reputation — treated as a fake scam. Entering it risks malware, stolen logins and wallet drain.");
  if(!sources.some(s=>s.name==="Concealment test"))sources.push({name:"Concealment test",state:"bad",detail:"Hidden page + no reputation = fake scam"});
 }
 onProgress("Concealment test",sources.some(s=>s.name==="Concealment test")?"bad":"clean");
 const hasBrand=hits.some(h=>/never operates|impostor/i.test(h));
 const pageHidden=sources.some(s=>s.name==="Live page scan"&&s.state==="skip");
 if((hasBrand||(pageHidden&&!reputable))&&!haus.guilty&&!sbGuilty&&!acquitted&&score<60){
  score=60;
  if(!hits.some(h=>/FAKE SCAM/i.test(h)))hits.unshift("FAKE SCAM WEBSITE/LINK: "+(hasBrand?"wears a trusted brand's name with no ownership proof":"hides its page with no verifiable reputation")+" — this is a fake scam website, url, link and phishing operation. Entering it risks stolen logins, OTPs and wallet drain.");
  if(!sources.some(s=>s.name==="Concealment test"))sources.push({name:"Concealment test",state:"bad",detail:"Single-signal rule: unrefuted brand theft or reputation-less hiding = fake scam"});
 }
 score=Math.min(100,Math.round(score));
 return{report:{url,host,score,verdict:score>=60?"scam":score>20?"suspicious":"safe",hits:[...new Set(hits)],trusted:base.trusted,kind:base.kind},sources};
}

// ── Worker lifecycle ────────────────────────────────────────────────────────
self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("activate",(e)=>{
 e.waitUntil((async()=>{
  await self.clients.claim();
  const clients=await self.clients.matchAll({type:"window"});
  clients.forEach(c=>c.postMessage({type:"SW_ACTIVE"}));
 })());
});

function blockPage(r){
 return"<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"+
 "<title>AvastLuxe blocked this</title><body style='margin:0;background:radial-gradient(1200px 600px at 50% -10%,#1a1430 0%,#06070B 60%);color:#F5F1E6;font-family:Segoe UI,system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px'>"+
 "<div style='max-width:480px;text-align:center'>"+
 "<div style='font-size:64px'>"+(r.verdict==="scam"?"⛔":"⚠️")+"</div>"+
 "<h1 style='color:"+(r.verdict==="scam"?"#FF4D6D":"#F6E27A")+";letter-spacing:2px'>"+(r.verdict==="scam"?"SCAM — BLOCKED":"SUSPICIOUS — PAUSED")+"</h1>"+
 "<div style='font-weight:800;margin:8px 0'>Risk "+r.score+"/100 — the page was never loaded</div>"+
 "<ul style='text-align:left;font-size:13px;color:#9A94A6;line-height:1.8'>"+r.hits.slice(0,6).map(h=>"<li>"+h+"</li>").join("")+"</ul>"+
 "<p style='font-size:13px;color:#9A94A6'>Go back — nothing was fetched from that site. If you really need it, open the official app instead.</p>"+
 "<a href='"+self.location.origin+"/avast-luxe-site/' style='display:inline-block;margin-top:8px;color:#06070B;background:linear-gradient(135deg,#F6E27A,#D4AF37);padding:12px 22px;border-radius:12px;text-decoration:none;font-weight:900'>← BACK TO SHIELD</a>"+
 "</div></body>";
}

// Middleman: any navigation a controlled page starts is screened instantly.
self.addEventListener("fetch",(e)=>{
 const url=e.request.url;
 if(e.request.mode!=="navigate"||!/^https?:/.test(url))return;
 if(url.includes("verdict")||url.includes("index.html")||url.includes("sw.js")||
    url.includes("manifest")||url.includes("icon-")||url.includes("proxy?"))return;
 let r;try{r=analyzeText(url)}catch{return}
 if(r.verdict==="safe")return; // genuine — let it load normally
 e.respondWith((async()=>{
  try{self.registration.showNotification(
   r.verdict==="scam"?"⛔ AvastLuxe BLOCKED a scam site":"⚠️ AvastLuxe paused a suspicious site",
   {body:"Risk "+r.score+"/100 — "+(r.hits[0]||"suspicious"),icon:"icon-192.png",tag:"lux-block-"+Date.now()}
  ).catch(()=>{})}catch{}
  return new Response(blockPage(r),{headers:{"Content-Type":"text/html; charset=utf-8"}});
 })());
});

// Background truth-test invoked by the page (progress + final verdict).
self.addEventListener("message",(e)=>{
 const d=e.data||{};

 if(d.type==="VERIFY"&&d.url){
  (async()=>{
   const t0=Date.now();
   try{
    const fwd=(name,state)=>{self.clients.matchAll({type:"window"}).then(all=>all.forEach(c=>c.postMessage({type:"PROGRESS",url:d.url,name,state})))};
    const deep=await deepVerify(d.url,{apiKey:d.apiKey||"",onProgress:fwd});
    deep.ms=Date.now()-t0;
    const all=await self.clients.matchAll({type:"window"});
    all.forEach(c=>c.postMessage({type:"VERDICT",url:d.url,selfTest:!!d.selfTest,deep}));
    const r=deep.report;
    if(r.verdict!=="safe"&&!d.selfTest){
     self.registration.showNotification(
      r.verdict==="scam"?"⛔ AvastLuxe: SCAM detected":"⚠️ AvastLuxe: suspicious link",
      {body:(r.host||"link")+" — risk "+r.score+"/100, checked in "+(deep.ms/1000).toFixed(1)+"s. Do not enter.",icon:"icon-192.png",tag:"lux-v-"+Date.now()}
     ).catch(()=>{})
    }
   }catch{}
  })();
  return;
 }
 if(d.type==="THREAT"&&d.report){
  self.registration.showNotification(
   d.report.verdict==="scam"?"⛔ AvastLuxe: SCAM found":"⚠️ AvastLuxe: suspicious link found",
   {body:(d.report.host||"link")+" — not safe, do not enter",icon:"icon-192.png",tag:"lux-threat"}
  ).catch(()=>{})
 }
 if(d.type==="SHIELD_ON"){
  self.registration.showNotification("🛡️ AvastLuxe Shield active",{
   body:"Background protection ON — testing continues with this tab minimized.",
   icon:"icon-192.png",tag:"lux-shield",renotify:false
  }).catch(()=>{})
 }
 if(d.type==="PING"){try{(e.source||{postMessage:function(){}}).postMessage({type:"PONG"})}catch{}}
});
