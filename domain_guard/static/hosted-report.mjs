import { normalizeDomain } from "./input.mjs";

const PILOT_DOMAIN = "domainguard-check.vercel.app";
const CHECKS = ["https", "tls", "headers", "redirects"];
const STATES = new Set(["pass", "fail", "info", "warning", "unavailable", "incomplete"]);

export function canRequestHosted(domain, site) {
    return domain === PILOT_DOMAIN && site.protocol === "https:" && site.hostname.endsWith(".vercel.app") && site.hostname !== PILOT_DOMAIN;
}

export function mergeHosted(dns, probe) {
    if(normalizeDomain(dns?.domain) !== PILOT_DOMAIN || probe?.domain !== dns.domain ||
       probe?.scope !== "hosted-web-probe" || probe?.schema_version !== 1 ||
       !["complete", "incomplete"].includes(probe?.status) || !Array.isArray(probe?.addresses) ||
       probe.addresses.length !== 1 || !probe.checks || typeof probe.checks !== "object" ||
       Object.keys(probe.checks).sort().join(",") !== CHECKS.slice().sort().join(",") ||
       CHECKS.some(key => !STATES.has(probe.checks[key]?.status))) {
        throw new Error("Invalid hosted probe result");
    }
    return {
        ...dns, scope: "hosted-combined", status: dns.status === "complete" && probe.status === "complete" ? "complete" : "incomplete",
        addresses: probe.addresses.slice(), checks: {...dns.checks, ...probe.checks},
        sources: {dns: "Google Public DNS", website: "isolated hosted preview probe"}
    };
}

export async function requestHosted(domain, signal, request = fetch) {
    const response = await request("/api/hosted-pilot", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({domain}),
        credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.any([signal, AbortSignal.timeout(40000)])
    });
    if(!response.ok) throw new Error("Hosted website checks unavailable");
    if(!response.body) throw new Error("Empty hosted probe response");
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", {fatal: true});
    let size = 0, content = "";
    try {
        while(true) {
            const {done, value} = await reader.read();
            if(done) break;
            size += value.byteLength;
            if(size > 16384) throw new Error("Hosted probe response too large");
            content += decoder.decode(value, {stream: true});
        }
        return JSON.parse(content + decoder.decode());
    } finally {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
    }
}
