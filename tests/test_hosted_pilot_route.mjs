import assert from "node:assert/strict";
import {test} from "node:test";
import handler from "../api/hosted-pilot.js";

function response() {
    return {headers:{},code:0,body:null,setHeader(key,value){this.headers[key]=value;},status(code){this.code=code;return this;},json(body){this.body=body;return this;}};
}

async function withConfig(values,run) {
    const keys=Object.keys(values);
    const prior=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
    try {
        for(const [key,value] of Object.entries(values)) value === undefined ? delete process.env[key] : process.env[key]=value;
        return await run();
    } finally {
        for(const [key,value] of Object.entries(prior)) value === undefined ? delete process.env[key] : process.env[key]=value;
    }
}

test("pilot denies admission without explicit restricted ACL verification",async()=>{
    const config={VERCEL_ENV:"preview",DOMAIN_GUARD_PILOT:"1",VERCEL_URL:"preview.vercel.app",DOMAIN_GUARD_QUOTA_TOKEN:"restricted-test-token",DOMAIN_GUARD_QUOTA_ACL_VERIFIED:undefined,UPSTASH_REDIS_REST_TOKEN:undefined};
    const req={method:"POST",headers:{origin:"https://preview.vercel.app","sec-fetch-site":"same-origin","content-type":"application/json","content-length":"43"},body:{domain:"domainguard-check.vercel.app"}};
    await withConfig(config,async()=>{
        const res=response();await handler(req,res);
        assert.equal(res.code,503);
        assert.deepEqual(res.body,{error:"Restricted quota credential required"});
    });
});

test("hosted route stays disabled without the preview activation flag",async()=>{
    const config={VERCEL_ENV:"preview",DOMAIN_GUARD_PILOT:undefined,VERCEL_URL:"preview.vercel.app"};
    await withConfig(config,async()=>{const res=response();await handler({method:"POST",headers:{},body:{}},res);assert.equal(res.code,404);});
});

test("arbitrary public hostname reaches the restricted credential gate",async()=>{
    const config={VERCEL_ENV:"preview",DOMAIN_GUARD_PILOT:"1",VERCEL_URL:"preview.vercel.app",DOMAIN_GUARD_QUOTA_ACL_VERIFIED:undefined};
    const req={method:"POST",headers:{origin:"https://preview.vercel.app","sec-fetch-site":"same-origin","content-type":"application/json","content-length":"30"},body:{domain:"other.example.com"}};
    await withConfig(config,async()=>{const res=response();await handler(req,res);assert.equal(res.code,503);});
});

test("pilot rejects a standard token even with ACL flag",async()=>{
    const config={VERCEL_ENV:"preview",DOMAIN_GUARD_PILOT:"1",VERCEL_URL:"preview.vercel.app",DOMAIN_GUARD_QUOTA_TOKEN:"same-token",DOMAIN_GUARD_QUOTA_ACL_VERIFIED:"1",UPSTASH_REDIS_REST_TOKEN:"same-token"};
    const req={method:"POST",headers:{origin:"https://preview.vercel.app","sec-fetch-site":"same-origin","content-type":"application/json","content-length":"43"},body:{domain:"domainguard-check.vercel.app"}};
    await withConfig(config,async()=>{const res=response();await handler(req,res);assert.equal(res.code,503);});
});

test("pilot rejects unsafe hostnames before quota or sandbox use",async()=>{
    const config={VERCEL_ENV:"preview",DOMAIN_GUARD_PILOT:"1",VERCEL_URL:"preview.vercel.app",DOMAIN_GUARD_QUOTA_TOKEN:"restricted-test-token",DOMAIN_GUARD_QUOTA_ACL_VERIFIED:"1",UPSTASH_REDIS_REST_TOKEN:undefined};
    const req={method:"POST",headers:{origin:"https://preview.vercel.app","sec-fetch-site":"same-origin","content-type":"application/json","content-length":"32"},body:{domain:"localhost"}};
    await withConfig(config,async()=>{const res=response();await handler(req,res);assert.equal(res.code,400);});
});
