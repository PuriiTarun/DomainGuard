import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { actionDocument, actionSteps, reportFilename } from "../domain_guard/static/action-plan.mjs";

const read = name => readFileSync(new URL(`../domain_guard/static/${name}`, import.meta.url), "utf8");

test("action filenames use only normalized safe domain labels", () => {
    assert.equal(reportFilename({domain:"EXAMPLE.COM"}, "action-plan", "html"), "example.com-action-plan-by-domainguard.html");
    assert.equal(reportFilename({domain:"../../evil.html"}, "action-plan", "html"), "domain-action-plan-by-domainguard.html");
    assert.equal(reportFilename({domain:"example.com"}, "report", "json"), "example.com-report-by-domainguard.json");
});

test("action export is self-contained and does not include hostile raw records", () => {
    const value = '<img src=x onerror="alert(1)">';
    const html = actionDocument({domain:value, status:"incomplete", records:{TXT:{values:[value]}}}, true);
    assert.ok(!html.includes(value));
    assert.doesNotMatch(html, /<script|<iframe|<img|https?:\/\//i);
    assert.match(html, /Example report, not a live scan/);
    assert.match(html, /How to verify:/);
    assert.match(html, /Who can help:/);
    const style = html.match(/<style>(.*?)<\/style>/s)[1];
    assert.ok(html.includes(`sha256-${createHash("sha256").update(style).digest("base64")}`));
});

test("action steps identify the relevant provider and a retest", () => {
    assert.equal(actionSteps({title:"Confirm certificate renewal"}).owner, "Hosting provider");
    assert.match(actionSteps({title:"Review your browser content policy"}).verify, /Content-Security-Policy/);
});

test("site includes real policy links, no external assets, and restrained scan controls", () => {
    const html = read("index.html");
    const css = read("styles.css");
    assert.match(html, /href="\.\/privacy.html"/);
    assert.match(html, /href="\.\/terms.html"/);
    assert.match(html, /Domain Security Checker/);
    assert.doesNotMatch(html, /DOMAIN INSPECTION TOOL|diagram-title|<script[^>]+src="https?:/);
    assert.match(css, /-webkit-autofill/);
    assert.match(css, /data-state="busy"/);
    for(const file of ["index.html", "privacy.html", "terms.html", "app.mjs", "render.mjs", "advice.mjs", "action-plan.mjs"]) assert.doesNotMatch(read(file), /[\u2013\u2014]/, file);
});
