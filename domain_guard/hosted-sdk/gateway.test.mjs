import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalDomain, publicIPv4, runPilot } from "./gateway.mjs";

function fixture(overrides = {}) {
    const events = [];
    const domain = "example.com", address = "8.8.8.8";
    const data = {domain, addresses: [address], schema_version: 1, scope: "hosted-web-probe", status: "complete", records: {}, checks: {https:{status:"pass",message:"Verified HTTPS HEAD response received",status_code:200},tls:{status:"pass",message:"TLS certificate and hostname verified",expires:"2027-01-01",days_remaining:35},headers:{status:"info",message:"Header observations",findings:[]},redirects:{status:"info",message:"No redirect observed"}}};
    const sandbox = {writeFiles: async files => {events.push("write"); assert.equal(files.length,4);}, runCommand: async (cmd,args) => {events.push("run"); assert.equal(cmd,"python3"); assert.deepEqual(args,["-m","domain_guard.hosted_probe",domain,address]); return {exitCode:0,stdout:async()=>JSON.stringify(data)};}, stop:async()=>{events.push("stop");}};
    const deps = {authorize:async()=>{events.push("authorize");return true;},reserve:async()=>{events.push("reserve");return true;},lookupApproved:async()=>{events.push("lookup");return address;},createSandbox:async opts=>{events.push("create");assert.deepEqual(opts.networkPolicy.subnets.allow,[address+"/32"]);assert.equal(opts.persistent,false);assert.equal(opts.timeout,30000);assert.deepEqual(opts.ports,[]);return sandbox;},workerFiles:Object.fromEntries(["domain_guard/hosted_probe.py","domain_guard/checks/headers.py","domain_guard/checks/redirects.py","domain_guard/validation.py"].map(p=>[p,Buffer.from("test")])),...overrides};
    return {events,domain,data,deps,sandbox};
}
test("strict hostname and public address validation",()=>{
    assert.ok(canonicalDomain("example.com"));assert.ok(publicIPv4("8.8.8.8"));
    for(const value of ["https://example.com","example.com:443","localhost","a.internal","a..com","xn--a.com","EXAMPLE.COM"]) assert.equal(canonicalDomain(value),false,value);
    for(const value of ["0.0.0.0","10.0.0.1","100.64.0.1","127.0.0.1","169.254.169.254","172.16.1.1","192.0.2.1","192.168.0.1","198.18.0.1","198.51.100.1","203.0.113.1","224.0.0.1","255.255.255.255","::ffff:8.8.8.8"]) assert.equal(publicIPv4(value),false,value);
});
test("authorization and quota failure prevent resource creation",async()=>{
    for(const overrides of [{authorize:async()=>false},{reserve:async()=>false},{reserve:undefined},{reserve:async()=>{throw Error("store unavailable");}}]){
        const f=fixture(overrides);await assert.rejects(runPilot(f.domain,f.deps));assert.ok(!f.events.includes("create"));
    }
});
test("screening failure consumes reservation but never creates a sandbox",async()=>{
    const f=fixture({lookupApproved:async()=>"127.0.0.1"});await assert.rejects(runPilot(f.domain,f.deps),{status:422});assert.deepEqual(f.events,["authorize","reserve"]);
});
test("authorized and reserved scan uses pinned policy and stops",async()=>{
    const f=fixture();assert.deepEqual(await runPilot(f.domain,f.deps),f.data);assert.deepEqual(f.events,["authorize","reserve","lookup","create","write","run","stop"]);
});
test("worker error and malformed results stop the sandbox",async()=>{
    for(const result of [{exitCode:1,stdout:async()=>""},{exitCode:0,stdout:async()=>JSON.stringify({domain:"other.com"})},{exitCode:0,stdout:async()=>"x".repeat(16385)}]){
        const f=fixture();f.sandbox.runCommand=async()=>result;await assert.rejects(runPilot(f.domain,f.deps));assert.equal(f.events.at(-1),"stop");
    }
});
test("untrusted probe fields and inconsistent outcomes are rejected",async()=>{
    const changes=[
        data=>{data.extra="ignored?";},
        data=>{data.records={TXT:{status:"found",values:["unexpected"]}};},
        data=>{data.checks.https.message="bad\r\nHeader: injected";},
        data=>{data.checks.https.status_code="200";},
        data=>{data.checks.tls.days_remaining=-1;},
        data=>{data.checks.headers.findings=Array(7).fill({name:"X",status:"info",message:"ok"});},
        data=>{data.checks.redirects.extra="unexpected";},
        data=>{data.status="incomplete";}
    ];
    for(const change of changes) {
        const f=fixture();const data=structuredClone(f.data);change(data);
        f.sandbox.runCommand=async()=>({exitCode:0,stdout:async()=>JSON.stringify(data)});
        await assert.rejects(runPilot(f.domain,f.deps),{status:502});
        assert.equal(f.events.at(-1),"stop");
    }
});
test("cleanup failure cannot be returned as success",async()=>{
    const f=fixture();f.sandbox.stop=async()=>{throw Error("cleanup failed");};await assert.rejects(runPilot(f.domain,f.deps),/cleanup failed/);
});
