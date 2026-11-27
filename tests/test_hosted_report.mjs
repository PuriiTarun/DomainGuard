import assert from "node:assert/strict";
import { test } from "node:test";
import { canRequestHosted, mergeHosted, requestHosted } from "../domain_guard/static/hosted-report.mjs";
import { exportReport } from "../domain_guard/static/report.mjs";
import { actionDocument } from "../domain_guard/static/action-plan.mjs";
import { describeReport } from "../domain_guard/static/render.mjs";

const domain = "domainguard-check.vercel.app";
const dns = {domain, scope: "dns-email", status: "complete", records: {A: {status: "found", values: ["1.1.1.1"]}}, checks: {https: {status: "skipped"}, tls: {status: "skipped"}, headers: {status: "skipped"}, redirects: {status: "skipped"}}, spf: {status: "missing"}};
const probe = {domain, schema_version: 1, scope: "hosted-web-probe", status: "complete", addresses: ["1.1.1.1"], checks: {https: {status: "pass", status_code: 200}, tls: {status: "pass", expires: "2027-01-01", days_remaining: 40}, headers: {status: "warning", findings: [{name: "X-Content-Type-Options", status: "warning", message: "Missing"}]}, redirects: {status: "info"}}, records: {}};

test("public site accepts valid hosted domains while preview remains pilot-only", () => {
    assert.equal(canRequestHosted(domain, {protocol: "https:", hostname: "preview-123.vercel.app"}), true);
    assert.equal(canRequestHosted(domain, {protocol: "https:", hostname: domain}), true);
    assert.equal(canRequestHosted("owner-approved.org", {protocol: "https:", hostname: domain}), true);
    assert.equal(canRequestHosted("other.example.com", {protocol: "https:", hostname: "preview-123.vercel.app"}), false);
    assert.equal(canRequestHosted("localhost", {protocol: "https:", hostname: "preview-123.vercel.app"}), false);
    assert.equal(canRequestHosted(domain, {protocol: "http:", hostname: "preview-123.vercel.app"}), false);
});

test("same-domain hosted observations merge with DNS and retain export provenance", () => {
    const combined = mergeHosted(dns, probe);
    assert.equal(combined.scope, "hosted-combined");
    assert.equal(combined.status, "complete");
    assert.equal(combined.records.A.status, "found");
    assert.equal(combined.checks.tls.status, "pass");
    assert.equal(combined.sources.website, "isolated hosted website probe");
    assert.equal(exportReport(combined, false).source, "hosted-website");
    assert.match(actionDocument(combined), /isolated HTTPS website observations/);
    const view = describeReport(combined);
    assert.equal(view.groups.find(group => group.name === "HTTPS & TLS").items.length, 4);
});

test("invalid, mismatched and incomplete probe responses fail closed", () => {
    for(const change of [{domain: "other.example.com"}, {scope: "local-scan"}, {checks: {https: {status: "pass"}}}]) {
        assert.throws(() => mergeHosted(dns, {...probe, ...change}), /Invalid hosted probe result/);
    }
    assert.equal(mergeHosted(dns, {...probe, status: "incomplete"}).status, "incomplete");
    assert.equal(mergeHosted({...dns, status: "incomplete"}, probe).status, "incomplete");
    const another = "other.example.com";
    assert.equal(mergeHosted({...dns, domain: another}, {...probe, domain: another}).domain, another);
});

test("hosted request is bounded and denied responses stay unavailable", async () => {
    const controller = new AbortController();
    const observed = [];
    const result = await requestHosted(domain, controller.signal, async (url, options) => {
        observed.push({url, options});
        return new Response(JSON.stringify(probe));
    });
    assert.equal(result.scope, "hosted-web-probe");
    assert.equal(observed[0].url, "/api/hosted-pilot");
    assert.deepEqual(JSON.parse(observed[0].options.body), {domain});
    await assert.rejects(requestHosted(domain, controller.signal, async () => new Response("", {status: 503})), /unavailable/);
    await assert.rejects(requestHosted(domain, controller.signal, async () => new Response("x".repeat(16385))), /too large/);
});

test("abort signal cancels pending hosted request", async () => {
    const controller = new AbortController();
    const pending = requestHosted(domain, controller.signal, async (_, options) => new Promise((resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new DOMException("Cancelled", "AbortError")), {once: true});
    }));
    controller.abort();
    await assert.rejects(pending, {name: "AbortError"});
});
