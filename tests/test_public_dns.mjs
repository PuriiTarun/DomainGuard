import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeTxt, parseDns, scanPublicDns } from "../domain_guard/static/public-dns.mjs";
import { exportReport } from "../domain_guard/static/report.mjs";
import { actionDocument } from "../domain_guard/static/action-plan.mjs";

function answer(name, type, records = [], status = 0) {
    return {Status: status, TC: false, Question: [{name: name + ".", type}], Answer: records};
}
function record(name, type, data) { return {name: name + ".", type, data}; }

test("quoted DNS TXT chunks join and malformed encodings fail closed", () => {
    assert.equal(decodeTxt('"v=spf1 ""-all"'), "v=spf1 -all");
    assert.equal(decodeTxt('"v=spf1 \\045all"'), "v=spf1 -all");
    assert.equal(decodeTxt('"unclosed'), null);
    assert.equal(decodeTxt('"invalid\\999"'), null);
});

test("resolver answers must match the question and a bounded alias chain", () => {
    const data = answer("example.com", 1, [record("example.com", 5, "www.example.com."), record("www.example.com", 1, "192.0.2.1")]);
    assert.deepEqual(parseDns(data, "example.com", "A"), {status: "found", values: ["192.0.2.1"]});
    assert.equal(parseDns(data, "other.example", "A").status, "error");
    assert.equal(parseDns({...data, TC: true}, "example.com", "A").status, "error");
    assert.equal(parseDns(answer("example.com", 1, [record("example.com", 5, "example.com.")]), "example.com", "A").status, "error");
    assert.equal(parseDns(answer("example.com", 1, [record("other.com", 1, "192.0.2.1")]), "example.com", "A").status, "error");
    assert.equal(parseDns(answer("example.com", 1, [], 3), "example.com", "A").status, "nxdomain");
    assert.equal(parseDns(answer("example.com", 1, [], 2), "example.com", "A").status, "error");
    assert.equal(parseDns(answer("example.com", 16, [record("example.com", 16, "x".repeat(2049))]), "example.com", "TXT").status, "error");
});

test("online mode queries only the fixed resolver, never target hosts, and labels partial scope", async () => {
    const requests = [];
    const report = await scanPublicDns(" EXAMPLE.COM ", new AbortController().signal, async (url, options) => {
        requests.push({url, options});
        const target = new URL(url), name = target.searchParams.get("name"), type = Number(target.searchParams.get("type"));
        let records = [];
        if(name === "example.com" && type === 16) records = [record(name, type, '"v=spf1 +all"')];
        if(name === "_dmarc.example.com") records = [record(name, type, '"v=DMARC1; p=reject"')];
        return new Response(JSON.stringify(answer(name, type, records)));
    });
    assert.equal(requests.length, 10);
    assert.ok(requests.every(({url, options}) => new URL(url).origin === "https://dns.google" && new URL(url).pathname === "/resolve" && new URL(url).searchParams.get("edns_client_subnet") === "0.0.0.0/0" && options.credentials === "omit" && options.redirect === "error" && options.referrerPolicy === "no-referrer"));
    assert.equal(report.scope, "dns-email");
    assert.equal(report.status, "complete");
    assert.equal(report.spf.findings[0].status, "warning");
    assert.equal(report.dmarc.status, "found");
    assert.deepEqual(report.addresses, []);
    assert.ok(Object.values(report.checks).every(check => check.status === "skipped"));
    assert.equal(exportReport(report, false).source, "public-dns");
    assert.match(actionDocument(report), /Live public DNS observations only/);
});

test("invalid names, oversized replies, network errors and cancellation fail safely", async () => {
    let calls = 0;
    const request = async () => { calls++; return new Response("x".repeat(65537)); };
    await assert.rejects(scanPublicDns("https://example.com/", new AbortController().signal, request), /Invalid domain/);
    assert.equal(calls, 0);
    const failed = await scanPublicDns("example.com", new AbortController().signal, request);
    assert.equal(failed.status, "incomplete");
    assert.equal(failed.records.A.status, "error");
    const cancelled = new AbortController(); cancelled.abort();
    await assert.rejects(scanPublicDns("example.com", cancelled.signal, request), {name: "AbortError"});
    const error = await scanPublicDns("example.com", new AbortController().signal, async () => { throw Error("blocked"); });
    assert.equal(error.status, "incomplete");
});
