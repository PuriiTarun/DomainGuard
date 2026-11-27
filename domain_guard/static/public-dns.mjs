import { normalizeDomain } from "./input.mjs";

const TYPES = {A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CAA: 257, SOA: 6};
const PREFIXES = {dmarc: "_dmarc.", mta_sts: "_mta-sts.", tlsrpt: "_smtp._tls."};
const VERSIONS = {dmarc: "v=dmarc1", mta_sts: "v=stsv1", tlsrpt: "v=tlsrptv1"};
const encoder = new TextEncoder();
const bytes = value => encoder.encode(value).length;
const empty = status => ({status, values: []});
const canonical = value => typeof value === "string" ? value.toLowerCase().replace(/\.$/, "") : "";

// Decode the quoted TXT chunks from Google's JSON presentation format.
export function decodeTxt(value) {
    if(!value.startsWith('"')) return value;
    let result = "", index = 0;
    while(index < value.length) {
        while(value[index] === " ") index++;
        if(index === value.length) break;
        if(value[index++] !== '"') return null;
        while(index < value.length && value[index] !== '"') {
            if(value[index] === "\\") {
                index++;
                if(index >= value.length) return null;
                const decimal = value.slice(index, index + 3);
                if(/^\d{3}$/.test(decimal)) {
                    const number = Number(decimal);
                    if(number > 127 || number < 32 || number === 127) return null;
                    result += String.fromCharCode(number); index += 3;
                } else result += value[index++];
            } else result += value[index++];
        }
        if(value[index++] !== '"') return null;
    }
    return result;
}

export function parseDns(data, name, type) {
    if(!data || data.TC !== false || !Array.isArray(data.Question) || data.Question.length !== 1 || canonical(data.Question[0]?.name) !== canonical(name) || data.Question[0]?.type !== TYPES[type]) return empty("error");
    if(data.Status === 3) return empty("nxdomain");
    if(data.Status !== 0) return empty("error");
    const answers = data.Answer ?? [];
    if(!Array.isArray(answers) || answers.length > 64) return empty("error");
    // Only accept direct records or a bounded, unambiguous CNAME chain from the question.
    const visited = new Set();
    let owner = canonical(name);
    for(let hop = 0; hop < 8; hop++) {
        if(visited.has(owner)) return empty("error");
        visited.add(owner);
        const matching = answers.filter(record => canonical(record?.name) === owner);
        const aliases = matching.filter(record => record.type === 5);
        const records = matching.filter(record => record.type === TYPES[type]);
        if(aliases.length) {
            if(aliases.length !== 1 || records.length || typeof aliases[0].data !== "string") return empty("error");
            owner = canonical(aliases[0].data);
            if(!normalizeDomain(owner)) return empty("error");
            continue;
        }
        if(!records.length && answers.some(record => record?.type === TYPES[type])) return empty("error");
        let total = 0;
        const values = [];
        for(const record of records) {
            if(typeof record.data !== "string" || bytes(record.data) > 2048) return empty("error");
            const value = type === "TXT" ? decodeTxt(record.data) : record.data;
            if(value === null || bytes(value) > 2048) return empty("error");
            total += bytes(value);
            if(total > 4096) return empty("error");
            values.push(value);
        }
        return {status: values.length ? "found" : "missing", values};
    }
    return empty("error");
}

async function boundedJson(response) {
    if(!response.ok || !response.body) throw new Error("Resolver unavailable");
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", {fatal: true});
    let total = 0, content = "";
    try {
        while(true) {
            const {done, value} = await reader.read();
            if(done) break;
            total += value.byteLength;
            if(total > 65536) throw new Error("DNS response too large");
            content += decoder.decode(value, {stream: true});
        }
        return JSON.parse(content + decoder.decode());
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

async function query(name, type, signal, request) {
    if(name.length > 253 || signal.aborted) return empty("incomplete");
    const url = new URL("https://dns.google/resolve");
    url.search = new URLSearchParams({name, type: String(TYPES[type]), edns_client_subnet: "0.0.0.0/0"});
    try {
        const response = await request(url.toString(), {method: "GET", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", signal: AbortSignal.any([signal, AbortSignal.timeout(5000)])});
        return parseDns(await boundedJson(response), name, type);
    } catch { return empty(signal.aborted ? "incomplete" : "error"); }
}

function emailRecord(record, kind) {
    if(!["found", "missing"].includes(record.status)) return empty(record.status);
    const values = record.values.filter(value => {
        const text = value.trim().toLowerCase();
        return kind === "spf" ? /^v=spf1(?:\s|$)/.test(text) : text.split(";", 1)[0].trim() === VERSIONS[kind];
    });
    const result = {status: values.length > 1 ? "multiple" : values.length ? "found" : "missing", values};
    if(kind === "spf" && values.length === 1 && values[0].trim().split(/\s+/).slice(1).some(term => /^(?:\+)?all$/i.test(term))) result.findings = [{name: "All mechanism", status: "warning", message: "Permissive all mechanism published; full SPF syntax was not evaluated"}];
    if(kind === "dmarc" && values.length === 1) {
        const policies = values[0].toLowerCase().split(";").map(tag => tag.trim()).filter(tag => /^p\s*=/.test(tag));
        if(policies.length !== 1 || !/^p\s*=\s*(none|quarantine|reject)$/.test(policies[0])) result.findings = [{name: "Published policy", status: "warning", message: "Missing, repeated or unrecognized p tag; effective policy not determined"}];
    }
    return result;
}

export async function scanPublicDns(value, cancellation, request = fetch) {
    const domain = normalizeDomain(value);
    if(!domain) throw new Error("Invalid domain");
    const signal = AbortSignal.any([cancellation, AbortSignal.timeout(20000)]);
    const tasks = [...Object.keys(TYPES).map(type => [type, domain, type]), ...Object.entries(PREFIXES).map(([key, prefix]) => [key, prefix + domain, "TXT"])];
    const results = {};
    for(let index = 0; index < tasks.length; index += 2) {
        if(cancellation.aborted) throw new DOMException("Cancelled", "AbortError");
        await Promise.all(tasks.slice(index, index + 2).map(async ([key, name, type]) => { results[key] = await query(name, type, signal, request); }));
    }
    if(cancellation.aborted) throw new DOMException("Cancelled", "AbortError");
    const records = Object.fromEntries(Object.keys(TYPES).map(type => [type, results[type]]));
    const email = {spf: emailRecord(records.TXT, "spf"), ...Object.fromEntries(Object.keys(PREFIXES).map(key => [key, emailRecord(results[key], key)]))};
    const skipped = {status: "skipped", message: "Not assessed online. Run the local Python scanner for this check."};
    const checks = Object.fromEntries(["https", "tls", "headers", "redirects"].map(key => [key, {...skipped}]));
    const status = Object.entries(results).every(([key, item]) => item.status === "found" || item.status === "missing" || (Object.hasOwn(PREFIXES, key) && item.status === "nxdomain")) ? "complete" : "incomplete";
    const report = {domain, schema_version: 1, scope: "dns-email", resolver: "Google Public DNS", status, addresses: [], checks, records, ...email};
    if(bytes(JSON.stringify(report)) > 65536) return {...report, status: "incomplete", records: {}, spf: empty("incomplete"), dmarc: empty("incomplete"), mta_sts: empty("incomplete"), tlsrpt: empty("incomplete"), checks: {...checks, output: {status: "incomplete", message: "Report exceeded its size limit"}}};
    return report;
}
