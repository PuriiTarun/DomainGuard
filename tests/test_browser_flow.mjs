import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { exportReport } from "../domain_guard/static/report.mjs";
import { normalizeDomain } from "../domain_guard/static/input.mjs";

function fixture() {
    const nodes = new Map();
    function node() {
        return {textContent: "", value: "", hidden: false, disabled: true, children: [], handlers: {}, attributes: {},
            setAttribute(name, value) { this.attributes[name] = value; },
            append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; },
            addEventListener(event, callback) { this.handlers[event] = callback; }, focus() {}, scrollIntoView() {}};
    }
    globalThis.document = {
        documentElement: {dataset: {}},
        createElement() { return node(); },
        getElementById(id) { if(!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); }
    };
    return id => document.getElementById(id);
}

function restore() {
    delete globalThis.document;
    delete globalThis.location;
}

test("copied reports distinguish demonstration from actual scan data", () => {
    const report = {domain: "example.com"};
    assert.deepEqual(exportReport(report, true), {source: "synthetic-example", report});
    assert.deepEqual(exportReport(report, false), {source: "local-scan", report});
});

test("special-use names and oversized input are rejected in the frontend", () => {
    for(const name of ["home.arpa", "host.localdomain", "host.alt", "host.corp", "host.intranet", "host.private", " ".repeat(512) + "example.com"]) assert.equal(normalizeDomain(name), null);
});

test("non-loopback HTTP demonstration never calls an API", async () => {
    const get = fixture();
    const originalFetch = globalThis.fetch;
    globalThis.location = {protocol: "http:", hostname: "demo.example.com"};
    let requests = 0;
    globalThis.fetch = () => { requests++; throw new Error("Unexpected request"); };
    try {
        const {ready} = await import("../domain_guard/static/app.mjs?static-test");
        await ready;
        assert.equal(get("scan-button").disabled, true);
        await get("scan-form").handlers.submit({preventDefault() {}});
        get("demo-button").handlers.click();
        assert.equal(requests, 0);
        assert.equal(get("result-kind").textContent, "Example report (not a live scan)");
        assert.equal(get("results").hidden, false);
        get("filter-review").handlers.click();
        assert.equal(get("filter-review").attributes["aria-pressed"], "true");
        assert.match(get("filter-status").textContent, /warnings or failures/);
        assert.equal(get("theme-toggle").handlers.click, undefined);
    } finally { globalThis.fetch = originalFetch; restore(); }
});

test("local workflow submits a normalized hostname and uses private bearer access", async () => {
    const get = fixture();
    const originalFetch = globalThis.fetch;
    globalThis.location = {protocol: "http:", hostname: "127.0.0.1"};
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({url, options});
        if(url === "/api/scans") {
            assert.equal(get("scan-button").attributes["data-state"], "busy");
            assert.equal(get("scan-button").disabled, true);
            assert.equal(get("domain").readOnly, true);
        }
        const data = url === "/api/capabilities" ? {live_scans: true} : url === "/api/scans" ? {id: "test-id", access_token: "test-token"} : {status: "complete", result: {domain: "example.com", status: "complete", checks: {https: {status: "pass"}}}};
        return {ok: true, status: 200, json: async () => data};
    };
    try {
        const {ready} = await import("../domain_guard/static/app.mjs?local-test");
        await ready;
        assert.equal(get("scan-button").disabled, false);
        get("domain").value = " EXAMPLE.COM ";
        await get("scan-form").handlers.submit({preventDefault() {}});
        assert.deepEqual(requests.map(item => item.url), ["/api/capabilities", "/api/scans", "/api/scans/test-id"]);
        assert.deepEqual(JSON.parse(requests[1].options.body), {domain: "example.com"});
        assert.equal(requests[2].options.headers.Authorization, "Bearer test-token");
        assert.equal(get("result-kind").textContent, "Local scan result");
        assert.equal(get("scan-button").attributes["data-state"], "done");
        assert.match(get("scan-button").textContent, /✓/);
        assert.equal(get("domain").readOnly, false);
        assert.equal(get("scan-button").disabled, false);
    } finally { globalThis.fetch = originalFetch; restore(); }
});

test("website uses one dark theme and local Geist typography", () => {
    const html = readFileSync(new URL("../domain_guard/static/index.html", import.meta.url), "utf8");
    const css = readFileSync(new URL("../domain_guard/static/styles.css", import.meta.url), "utf8");
    assert.match(html, /name="color-scheme" content="dark"/);
    assert.doesNotMatch(html, /theme-toggle|theme-text/);
    assert.doesNotMatch(css, /data-theme|prefers-color-scheme|ui-monospace/);
    assert.match(css, /font-family:Geist/);
    assert.match(css, /--paper:#111111/);
    assert.match(css, /--signal:#C9EF35/);
    assert.match(css, /--pink:#ff2e93/);
});

test("hosted browser DNS mode submits to resolver only on explicit action", async () => {
    const get = fixture();
    const originalFetch = globalThis.fetch;
    globalThis.location = {protocol: "https:", hostname: "demo.example.com"};
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({url, options});
        const target = new URL(url);
        assert.equal(target.origin, "https://dns.google");
        return new Response(JSON.stringify({Status: 0, TC: false, Question: [{name: target.searchParams.get("name") + ".", type: Number(target.searchParams.get("type"))}]}));
    };
    try {
        const {ready} = await import("../domain_guard/static/app.mjs?hosted-dns-test");
        await ready;
        assert.equal(get("scan-button").disabled, false);
        assert.equal(get("resolver-notice").hidden, false);
        assert.equal(requests.length, 0);
        get("domain").value = "example.com";
        await get("scan-form").handlers.submit({preventDefault() {}});
        assert.equal(requests.length, 10);
        assert.equal(get("result-kind").textContent, "Live DNS and email observations");
        assert.match(get("result-subtitle").textContent, /were not assessed/);
        assert.equal(get("scan-button").disabled, false);
        assert.equal(get("domain").readOnly, false);
        await get("scan-form").handlers.submit({preventDefault() {}});
        assert.equal(requests.length, 10);
    } finally { globalThis.fetch = originalFetch; restore(); }
});
