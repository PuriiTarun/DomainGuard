import assert from "node:assert/strict";
import { test } from "node:test";
import { demoReport } from "../domain_guard/static/demo.mjs";
import { normalizeDomain } from "../domain_guard/static/input.mjs";
import { describeReport, renderReport } from "../domain_guard/static/render.mjs";

test("domain input accepts only the documented ASCII hostname shape", () => {
    assert.equal(normalizeDomain(" EXAMPLE.COM "), "example.com");
    for(const value of ["", "localhost", "http://example.com", "example.com:443", "127.0.0.1", "example.com/", "éxample.com", "xn--bcher-kva.example", "example.com\x1b[31m", "example.com."]) {
        assert.equal(normalizeDomain(value), null, value);
    }
});

test("report description distinguishes absent, failed, and verified checks", () => {
    const view = describeReport(demoReport);
    assert.equal(view.domain, "example.com");
    assert.equal(view.groups.length, 3);
    assert.equal(view.groups[0].items[1].label, "Not found");
    assert.equal(view.groups[1].items[0].label, "Verified");
    assert.equal(view.groups[2].items[1].label, "Not found");
});

test("untrusted DNS values are assigned as text, never parsed as HTML", () => {
    const nodes = new Map();
    const created = [];
    globalThis.document = {
        createElement(tag) {
            const node = {tag, className: "", textContent: "", children: [], append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; }};
            created.push(node);
            return node;
        },
        getElementById(id) {
            if(!nodes.has(id)) nodes.set(id, {textContent: "", hidden: true, children: [], append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; }});
            return nodes.get(id);
        }
    };
    const payload = "<img src=x onerror=alert(1)>";
    renderReport({domain: "example.com", status: "complete", records: {TXT: {status: "found", values: [payload]}}});
    assert.ok(created.some(node => node.tag === "li" && node.textContent === payload));
    assert.ok(!created.some(node => node.tag === "img"));
    assert.equal(nodes.get("results").hidden, false);
    delete globalThis.document;
});

test("real engine statuses and unsafe status keys are handled", () => {
    const view = describeReport({domain: "example.com", checks: {https: {status: "pass"}, tls: {status: "fail"}, headers: {status: "constructor"}}});
    assert.deepEqual(view.groups[0].items.map(item => item.label), ["Verified", "Failed", "Unavailable"]);
    assert.equal(normalizeDomain("\nexample.com"), null);
    assert.equal(normalizeDomain("\u212a.com"), null);
    assert.equal(normalizeDomain("example.internal"), null);
});
