import { BlockList, isIP } from "node:net";
import { canonicalDomain, publicIPv4 } from "./gateway.mjs";
import { query } from "../public-dns.mjs";

const permitted = new BlockList();
permitted.addSubnet("2000::",3,"ipv6");
const excluded = new BlockList();
for(const [address,prefix] of [["2001::",23],["2001:db8::",32],["2002::",16],["3fff::",20]]) excluded.addSubnet(address,prefix,"ipv6");

export function publicIPv6(address) {
    return typeof address === "string" && !address.includes("%") && isIP(address) === 6 && permitted.check(address,"ipv6") && !excluded.check(address,"ipv6");
}

export async function lookupApproved(domain, request=fetch) {
    if(!canonicalDomain(domain)) return null;
    const signal=AbortSignal.timeout(6000);
    const [a,aaaa]=await Promise.all([query(domain,"A",signal,request),query(domain,"AAAA",signal,request)]);
    for(const [record,valid] of [[a,publicIPv4],[aaaa,publicIPv6]]) {
        if(!["found","missing"].includes(record.status) || !Array.isArray(record.values) || (record.status==="found")!==Boolean(record.values.length) || !record.values.every(valid)) return null;
    }
    if(a.values.length+aaaa.values.length>32 || a.values.length===0) return null;
    return [...new Set(a.values)].sort()[0];
}
