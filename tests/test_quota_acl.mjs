import assert from "node:assert/strict";
import {test} from "node:test";
import {verifyQuotaAcl} from "../scripts/verify-quota-acl.mjs";

const url = "https://safe-example.upstash.io";
const token = "restricted-test-token";
const state = "v1:0:0:0:0:0";

test("ACL verification checks exact quota key and denies direct and Lua access elsewhere", async()=>{
    const calls=[];
    const request=async (_,options)=>{
        const args=JSON.parse(options.body);calls.push(args);
        const allowed=args.at(-1)==="domainguard:scan-quota:v1";
        return new Response(JSON.stringify(allowed?{result:state}:{error:"NOPERM No permissions to access a key"}));
    };
    const result=await verifyQuotaAcl({url,token,request});
    assert.equal(result.directReadDenied,true);
    assert.equal(result.luaReadDenied,true);
    assert.deepEqual(calls.map(call=>call[0]),["GET","EVAL","GET","EVAL"]);
    assert.equal(calls.some(call=>call.includes("SET")),false);
});

test("ACL verification fails closed for unrestricted tokens and false denial evidence",async()=>{
    await assert.rejects(verifyQuotaAcl({url,token,standardToken:token,request:()=>{throw new Error("network use");}}),/Restricted token/);
    const request=async (_,options)=>new Response(JSON.stringify({result:options.body.includes("acl-probe")?null:state}));
    await assert.rejects(verifyQuotaAcl({url,token,request}),/verification failed/);
});
