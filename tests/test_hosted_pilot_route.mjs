import assert from "node:assert/strict";
import {test} from "node:test";
import {createHandler} from "../domain_guard/static/api/hosted-pilot.js";

const DOMAIN = "domainguard-check.vercel.app";
const HOST = "preview-123.vercel.app";
const paths = ["domain_guard/hosted_probe.py","domain_guard/checks/headers.py","domain_guard/checks/redirects.py","domain_guard/validation.py"];
const probe = {domain:DOMAIN,schema_version:1,scope:"hosted-web-probe",status:"complete",addresses:["1.1.1.1"],records:{},checks:{
    https:{status:"pass",message:"Verified HTTPS",status_code:200},
    tls:{status:"pass",message:"Verified TLS",expires:"2027-01-01",days_remaining:10},
    headers:{status:"info",message:"Observed headers",findings:[]},
    redirects:{status:"info",message:"No redirect"}
}};

function response() {
    return {headers:{},code:0,body:null,setHeader(key,value){this.headers[key]=value;},status(code){this.code=code;return this;},json(body){this.body=body;return this;}};
}

function request(domain=DOMAIN) {
    const body={domain};
    return {method:"POST",headers:{host:HOST,origin:"https://"+HOST,"sec-fetch-site":"same-origin","content-type":"application/json","content-length":String(Buffer.byteLength(JSON.stringify(body)))},body};
}

async function withConfig(overrides,run) {
    const config={VERCEL_ENV:"preview",VERCEL_URL:HOST,DOMAIN_GUARD_PILOT:"1",DOMAIN_GUARD_PILOT_ALLOWLIST:DOMAIN,
        DOMAIN_GUARD_QUOTA_ACL_VERIFIED:"1",DOMAIN_GUARD_QUOTA_TOKEN:"restricted-test-token",UPSTASH_REDIS_REST_TOKEN:"different-standard-token",UPSTASH_REDIS_REST_URL:"https://test.upstash.io",...overrides};
    const prior=Object.fromEntries(Object.keys(config).map(key=>[key,process.env[key]]));
    try {
        for(const [key,value] of Object.entries(config)) value === undefined ? delete process.env[key] : process.env[key]=value;
        return await run();
    } finally {
        for(const [key,value] of Object.entries(prior)) value === undefined ? delete process.env[key] : process.env[key]=value;
    }
}

function services({quota=true,address="1.1.1.1",output=probe,workerError=false,sandboxError=false,stopError=false}={}) {
    const calls={files:0,quota:0,dns:0,sandbox:0,stop:0};
    const handler=createHandler({
        loadFiles:async()=>{calls.files++;return Object.fromEntries(paths.map(path=>[path,Buffer.from("source")]));},
        quota:()=>async()=>{calls.quota++;return quota;},
        lookup:async()=>{calls.dns++;if(address instanceof Error) throw address;return address;},
        createSandbox:async()=>{calls.sandbox++;if(sandboxError) throw new Error("Provider unavailable");return {
            writeFiles:async()=>{},runCommand:async()=>({exitCode:workerError?1:0,stdout:async()=>JSON.stringify(output)}),
            stop:async()=>{calls.stop++;if(stopError) throw new Error("Cleanup unavailable");}
        };}
    });
    return {handler,calls};
}

async function invoke(handler,req=request()) {const res=response();await handler(req,res);return res;}

test("pilot is disabled by default and always disabled in production",async()=>{
    const {handler,calls}=services();
    await withConfig({DOMAIN_GUARD_PILOT:undefined},async()=>assert.equal((await invoke(handler)).code,404));
    await withConfig({VERCEL_ENV:"production"},async()=>assert.equal((await invoke(handler)).code,404));
    assert.equal(calls.files+calls.quota+calls.dns+calls.sandbox,0);
});

test("missing, malformed, and mismatched server allowlists deny before side effects",async()=>{
    const {handler,calls}=services();
    for(const value of [undefined,"",DOMAIN+",other.example.com","other.example.com"," "+DOMAIN]) {
        await withConfig({DOMAIN_GUARD_PILOT_ALLOWLIST:value},async()=>assert.equal((await invoke(handler)).code,503));
    }
    assert.equal(calls.files+calls.quota+calls.dns+calls.sandbox,0);
});

test("only the configured pilot hostname reaches quota and returns a valid worker result",async()=>{
    const {handler,calls}=services();
    await withConfig({},async()=>{const res=await invoke(handler);assert.equal(res.code,200);assert.deepEqual(res.body,probe);});
    assert.deepEqual(calls,{files:1,quota:1,dns:1,sandbox:1,stop:1});
});

test("other hostnames are denied before quota, DNS, and Sandbox",async()=>{
    const {handler,calls}=services();
    await withConfig({},async()=>assert.equal((await invoke(handler,request("other.example.com"))).code,403));
    assert.equal(calls.files+calls.quota+calls.dns+calls.sandbox,0);
});

test("malformed requests and untrusted routing headers fail before side effects",async()=>{
    const {handler,calls}=services();
    const bad=[[{...request(),method:"GET"},405],[{...request(),body:{domain:"localhost"}},400],
        [{...request(),body:{domain:DOMAIN,extra:true}},400],[{...request(),headers:{...request().headers,"content-length":"129"}},413],
        [{...request(),headers:{...request().headers,origin:"https://other.vercel.app"}},403],
        [{...request(),headers:{...request().headers,host:"other.vercel.app"}},403],
        [{...request(),headers:{...request().headers,"sec-fetch-site":"cross-site"}},403]];
    await withConfig({},async()=>{for(const [req,code] of bad) assert.equal((await invoke(handler,req)).code,code);});
    await withConfig({VERCEL_URL:"evil.example.com"},async()=>assert.equal((await invoke(handler)).code,403));
    assert.equal(calls.files+calls.quota+calls.dns+calls.sandbox,0);
});

test("missing or unrestricted quota credentials deny admission",async()=>{
    const {handler,calls}=services();
    await withConfig({DOMAIN_GUARD_QUOTA_ACL_VERIFIED:undefined},async()=>assert.equal((await invoke(handler)).code,503));
    await withConfig({DOMAIN_GUARD_QUOTA_TOKEN:"different-standard-token"},async()=>assert.equal((await invoke(handler)).code,503));
    assert.equal(calls.quota+calls.dns+calls.sandbox,0);
});

test("quota and DNS failures prevent Sandbox creation",async()=>{
    const quotaFailure=services({quota:false});
    await withConfig({},async()=>assert.equal((await invoke(quotaFailure.handler)).code,429));
    assert.equal(quotaFailure.calls.dns+quotaFailure.calls.sandbox,0);
    const dnsFailure=services({address:new Error("provider unavailable")});
    await withConfig({},async()=>assert.equal((await invoke(dnsFailure.handler)).code,503));
    assert.equal(dnsFailure.calls.quota,1);assert.equal(dnsFailure.calls.sandbox,0);
});

test("invalid or failed worker results are rejected and Sandbox is stopped",async()=>{
    for(const options of [{output:{...probe,domain:"other.example.com"}},{workerError:true}]) {
        const {handler,calls}=services(options);
        await withConfig({},async()=>assert.equal((await invoke(handler)).code,502));
        assert.equal(calls.sandbox,1);assert.equal(calls.stop,1);
    }
});

test("Sandbox provisioning and cleanup failures never return a successful report",async()=>{
    const provider=services({sandboxError:true});
    await withConfig({},async()=>assert.equal((await invoke(provider.handler)).code,503));
    assert.equal(provider.calls.sandbox,1);
    const cleanup=services({stopError:true});
    await withConfig({},async()=>assert.equal((await invoke(cleanup.handler)).code,503));
    assert.equal(cleanup.calls.stop,1);
});

test("bundled worker runs without runtime filesystem lookup",async()=>{
    const seen=[];
    let stopped=false;
    const handler=createHandler({
        quota:()=>async()=>true,
        lookup:async()=> "1.1.1.1",
        createSandbox:async()=>({
            writeFiles:async files=>{seen.push(...files);},
            runCommand:async()=>({exitCode:0,stdout:async()=>JSON.stringify(probe)}),
            stop:async()=>{stopped=true;}
        })
    });
    await withConfig({},async()=>{
        const res=await invoke(handler);
        assert.equal(res.code,200);
        assert.deepEqual(res.body,probe);
    });
    assert.equal(seen.length,paths.length);
    for(const path of paths) {
        const file=seen.find(item=>item.path===path);
        assert.ok(file && Buffer.isBuffer(file.content) && file.content.length>100);
    }
    assert.equal(stopped,true);
});
