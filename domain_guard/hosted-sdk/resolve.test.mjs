import {test} from "node:test";
import assert from "node:assert/strict";
import {lookupApproved,publicIPv6} from "./resolve.mjs";

function fixture(a,aaaa,options={}) {
    const calls=[];
    const request=async (url,opts)=>{
        const u=new URL(url), name=u.searchParams.get("name"),type=Number(u.searchParams.get("type"));
        calls.push(type);
        assert.equal(u.origin,"https://dns.google");assert.equal(u.pathname,"/resolve");assert.equal(name,"example.com");assert.equal(opts.redirect,"error");
        const values=type===1?a:aaaa;
        if(values===null)return new Response("failure",{status:503});
        return Response.json({Status:0,TC:false,Question:[{name:name+".",type}],Answer:values.map(data=>({name:name+".",type,data})),...options});
    };
    return {request,calls};
}
test("both address families screened; one canonical public IPv4 selected",async()=>{
    const f=fixture(["93.184.216.34","8.8.8.8"],["2606:4700::1111"]);
    assert.equal(await lookupApproved("example.com",f.request),"8.8.8.8");assert.deepEqual(f.calls.sort(),[1,28]);
});
test("mixed public/private addresses and unsupported IPv6 fail closed",async()=>{
    for(const [a,aaaa] of [[["8.8.8.8","127.0.0.1"],[]],[["8.8.8.8"],["::1"]],[["8.8.8.8"],["::ffff:8.8.8.8"]],[[],["2606:4700::1111"]],[["8.8.8.8"],null],[["8.8.8.8"],["2001:db8::1"]],[["8.8.8.8"],["2002::1"]]]){
        assert.equal(await lookupApproved("example.com",fixture(a,aaaa).request),null);
    }
    assert.equal(publicIPv6("2606:4700::1111"),true);
    assert.equal(publicIPv6("fe80::1%eth0"),false);
});
test("reject inconsistent DNS response and invalid domain",async()=>{
    assert.equal(await lookupApproved("example.com",fixture(["8.8.8.8"],[],{TC:true}).request),null);
    const f=fixture([],[]);assert.equal(await lookupApproved("a.internal",f.request),null);assert.equal(f.calls.length,0);
});
