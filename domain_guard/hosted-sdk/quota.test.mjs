import assert from "node:assert/strict";
import {test} from "node:test";
import {createQuota,utcWindows,LIMITS,INITIAL_STATE,RESERVE} from "./quota.mjs";

const config={url:"https://example-quota.upstash.io",token:"test-only-credential-123",clock:()=>Date.UTC(2026,10,27,12)};
test("UTC windows cross month and year boundaries",()=>{
    assert.deepEqual(utcWindows(Date.UTC(2026,11,31,23,59)),[Date.UTC(2026,11,31),Date.UTC(2027,0,1),Date.UTC(2026,11,1),Date.UTC(2027,0,1)].map(x=>String(x/1000)));
    assert.deepEqual(LIMITS,{daily:10,monthly:100,cooldown:35});
    assert.equal(INITIAL_STATE,"v1:0:0:0:0:0");
});
test("quota issues one atomic POST, accepts exactly numeric success",async()=>{
    let count=0;
    const reserve=createQuota({...config,fetcher:async(url,opts)=>{
        count++;assert.equal(url,config.url);assert.equal(opts.method,"POST");assert.equal(opts.redirect,"error");assert.equal(opts.headers.Authorization,"Bearer "+config.token);
        const body=JSON.parse(opts.body);assert.deepEqual(body,["EVAL",RESERVE,"1","domainguard:scan-quota:v1",...utcWindows(config.clock())]);
        return new Response('{"result":1}',{status:200});
    }});
    assert.equal(await reserve(),true);assert.equal(count,1);
});
test("missing config and non-provider endpoints deny without network",async()=>{
    for(const url of [undefined,"http://example.upstash.io","https://evil.test","https://example.upstash.io.evil.test","https://u:p@example.upstash.io","https://example.upstash.io/private","https://example.upstash.io?token=x"]){
        let count=0;assert.equal(await createQuota({...config,url,fetcher:async()=>{count++;}})(),false);assert.equal(count,0);
    }
    assert.equal(await createQuota({...config,token:""})(),false);
});
test("outage, malformed body, quota reached, oversized and wrong type fail closed",async()=>{
    for(const [status,body] of [[429,'{"result":1}'],[503,'{}'],[200,'{"result":0}'],[200,'{"result":"1"}'],[200,'{"error":"failure"}'],[200,'{"result":1,"error":"failure"}'],[200,'{'],[200,'x'.repeat(1025)]]){
        let count=0;const reserve=createQuota({...config,fetcher:async()=>{count++;return new Response(body,{status});}});assert.equal(await reserve(),false);assert.equal(count,1);
    }
    assert.equal(await createQuota({...config,fetcher:async()=>{throw Error("timeout");}})(),false);
});
