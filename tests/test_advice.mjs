import assert from "node:assert/strict";
import { test } from "node:test";
import { formatActionPlan, recommendations } from "../domain_guard/static/advice.mjs";

test("only observed header warnings become specific advice", () => {
    const report = {status: "complete", checks: {headers: {findings: [{name: "Content-Security-Policy", status: "warning"}, {name: "X-Frame-Options", status: "pass"}, {name: "constructor", status: "warning"}]}}};
    assert.deepEqual(recommendations(report).map(item => item.title), ["Review your browser content policy"]);
});

test("optional records do not become confirmed failures", () => {
    const result = recommendations({status: "complete", records: {AAAA: {status: "missing"}, CAA: {status: "missing"}}, mta_sts: {status: "missing"}});
    assert.equal(result.length, 1);
    assert.equal(result[0].priority, "Optional");
});

test("incomplete and rejected reports do not imply security", () => {
    assert.equal(recommendations({status: "incomplete"})[0].title, "Retry unavailable checks");
    assert.equal(recommendations({status: "rejected", spf: {status: "missing"}}).length, 1);
});

test("certificate expiry guidance is based on a verified certificate", () => {
    const result = recommendations({status: "complete", checks: {tls: {status: "pass", days_remaining: 12}}});
    assert.equal(result[0].title, "Confirm certificate renewal");
    assert.equal(recommendations({status: "complete", checks: {tls: {status: "unavailable", days_remaining: 12}}}).length, 0);
});

test("downloaded action plan preserves provenance and does not copy untrusted raw records", () => {
    const result = formatActionPlan({domain: "example.com\nFAKE", status: "incomplete", records: {TXT: {values: ["untrusted-value"]}}}, true);
    assert.match(result, /Example report \(not a live scan\)/);
    assert.match(result, /Domain: example.com\?FAKE/);
    assert.match(result, /Retry unavailable checks/);
    assert.doesNotMatch(result, /untrusted-value/);
});
