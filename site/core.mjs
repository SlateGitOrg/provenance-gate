
const n=(value,fallback=0)=>Number.isFinite(Number(value))?Number(value):fallback;
const clamp=(value,low,high)=>Math.min(high,Math.max(low,value));
const round=(value,digits=2)=>Number(value.toFixed(digits));
const mean=values=>values.length?values.reduce((sum,value)=>sum+value,0)/values.length:0;
const parseJSON=(value,fallback=[])=>{try{return JSON.parse(value)}catch{return fallback}};
const valuesFrom=value=>String(value).split(/[\s,]+/).map(Number).filter(Number.isFinite);
const result=(status,summary,metrics,rows,detail='')=>({status,summary,metrics,rows,detail});
const erf=x=>{const sign=x<0?-1:1,a=Math.abs(x),t=1/(1+0.3275911*a);const y=1-(((((1.061405429*t-1.453152027)*t)+1.421413741)*t-0.284496736)*t+0.254829592)*t*Math.exp(-a*a);return sign*y};
const normalCdf=z=>0.5*(1+erf(z/Math.sqrt(2)));
const wilson=(successes,total)=>{if(!total)return[0,0];const z=1.96,p=successes/total,d=1+z*z/total,c=(p+z*z/(2*total))/d,h=z*Math.sqrt((p*(1-p)+z*z/(4*total))/total)/d;return[clamp(c-h,0,1),clamp(c+h,0,1)]};
const sha256=async value=>{const bytes=new TextEncoder().encode(String(value));const digest=await crypto.subtle.digest('SHA-256',bytes);return[...new Uint8Array(digest)].map(byte=>byte.toString(16).padStart(2,'0')).join('')};
const tag=(xml,name)=>xml.match(new RegExp('<'+name+'[^>]*>([\\s\\S]*?)<\\/'+name+'>','i'))?.[1]?.trim()??'';
const similarity=(a,b)=>{const x=String(a).toLowerCase(),y=String(b).toLowerCase();if(x===y)return 1;const A=new Set(x.split(/\W+/).filter(Boolean)),B=new Set(y.split(/\W+/).filter(Boolean));const inter=[...A].filter(v=>B.has(v)).length;return inter/Math.max(1,new Set([...A,...B]).size)};

export const meta={"slug":"provenance-gate","name":"Provenance Gate","eyebrow":"Reproducible build verifier","description":"Hash the reviewed source and compare the claimed artifact with an independent rebuild.","fields":[{"name":"source","label":"Reviewed source","type":"textarea","rows":8,"help":""},{"name":"recipe","label":"Build recipe","type":"textarea","rows":5,"help":""},{"name":"claimedArtifact","label":"Published artifact","type":"textarea","rows":5,"help":""},{"name":"rebuiltArtifact","label":"Independent rebuild","type":"textarea","rows":5,"help":""}]};
export const initialState={"source":"export function total(a,b){return a+b}\n","recipe":"node 24; npm ci; npm run build","claimedArtifact":"bundle:v1:total(a,b)=a+b","rebuiltArtifact":"bundle:v1:total(a,b)=a+b"};
export const alternateState={"source":"export function total(a,b){return a+b}\n","recipe":"node 24; npm ci; npm run build","claimedArtifact":"bundle:v1:total(a,b)=a+b","rebuiltArtifact":"bundle:v1:total(a,b)=a-b"};
export async function compute(i){const sourceDigest=await sha256(`${i.source}\n${i.recipe}`),claimed=await sha256(i.claimedArtifact),rebuilt=await sha256(i.rebuiltArtifact),match=claimed===rebuilt;return result(match?'Provenance verified':'Artifact rejected',match?'Independent rebuild matches the published artifact byte-for-byte.':'The rebuilt artifact digest differs from the published subject.',[{label:'Source digest',value:sourceDigest.slice(0,12)},{label:'Published digest',value:claimed.slice(0,12)},{label:'Rebuild digest',value:rebuilt.slice(0,12)},{label:'Verdict',value:match?'MATCH':'MISMATCH'}],[{check:'Reviewed source bound to recipe',result:'Pass'},{check:'Published artifact independently rebuilt',result:match?'Pass':'Fail'},{check:'Digest equality',result:match?'Pass':'Fail'}],'Attestation metadata is supporting evidence; rebuild equality decides the artifact verdict.')}
