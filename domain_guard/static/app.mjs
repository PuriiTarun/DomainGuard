import { demoReport } from "./demo.mjs";
import { normalizeDomain } from "./input.mjs";
import { renderReport } from "./render.mjs";
import { exportReport } from "./report.mjs";
import { actionDocument, reportFilename } from "./action-plan.mjs";
import { canRequestHosted, mergeHosted, requestHosted } from "./hosted-report.mjs";

const form = document.getElementById("scan-form");
const input = document.getElementById("domain");
const error = document.getElementById("domain-error");
const status = document.getElementById("scan-status");
const submit = document.getElementById("scan-button");
const mode = document.getElementById("mode-label");
let active = null;
let lastReport = null;
let selectedFilter = "all";
let liveEnabled = false;
let activeJob = null;
let publicDns = null;
let nextDnsCheck = 0;
const cancel = document.getElementById("cancel-scan");
const demo = document.getElementById("demo-button");

function buttonState(state, label) {
    submit.setAttribute("data-state", state);
    submit.textContent = label;
    form.setAttribute("aria-busy", String(state === "busy"));
}

async function readJson(response) {
    try { return await response.json(); } catch { return {}; }
}

async function loadMode() {
    if(location.protocol === "https:") {
        try {
            publicDns = (await import("./public-dns.mjs")).scanPublicDns;
            liveEnabled = true;
            mode.textContent = location.hostname === "domainguard-check.vercel.app" ? "Live DNS and limited website checks" : "Live DNS and email checks";
            document.getElementById("intro").textContent = location.hostname === "domainguard-check.vercel.app" ? "Check public DNS and email authentication records, plus HTTPS, TLS and security headers when scan capacity permits." : "Check public DNS and email settings; the protected pilot checks only DomainGuard's own hostname.";
            document.getElementById("resolver-notice").hidden = false;
            submit.disabled = false;
            buttonState("idle", "Check DNS ↗");
            return;
        } catch { /* Fail closed if the hosted module is unavailable. */ }
    }
    try {
        if(location.protocol !== "http:" || location.hostname !== "127.0.0.1") throw new Error("Static mode");
        const response = await fetch("/api/capabilities", {cache: "no-store", signal: AbortSignal.timeout(5000)});
        if(!response.ok) throw new Error("API unavailable");
        const capabilities = await readJson(response);
        if(capabilities.live_scans === true) {
            liveEnabled = true;
            mode.textContent = "Local scans enabled";
            submit.disabled = false;
            status.textContent = "";
            return;
        }
    } catch { /* A static demonstration has no API. */ }
    mode.textContent = "Demonstration only";
    submit.disabled = true;
    status.textContent = "Live checks are disabled. You can explore the example report instead.";
}

function showReport(data, synthetic) {
    lastReport = exportReport(data, synthetic);
    setFilter("all");
    document.getElementById("results").scrollIntoView({block: "start"});
    document.getElementById("results-title").focus({preventScroll: true});
}

function messageFor(response, data) {
    if(response.status === 429) return "Scan limit reached. Please try again later.";
    if(response.status === 503) return "The local scan service is at capacity or disabled.";
    if(response.status === 400) return typeof data.error === "string" ? data.error : "Enter a valid domain name.";
    return "The scan could not be completed. Please try again.";
}

async function poll(id, token, signal) {
    const deadline = Date.now() + 130000;
    while(Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 700));
        if(signal.aborted) throw new DOMException("Cancelled", "AbortError");
        const response = await fetch(`/api/scans/${encodeURIComponent(id)}`, {headers: {Authorization: `Bearer ${token}`}, signal, cache: "no-store"});
        const data = await readJson(response);
        if(!response.ok) throw new Error(messageFor(response, data));
        if(data.status === "complete") return data;
        if(data.status === "failed" || data.status === "cancelled") throw new Error(typeof data.error === "string" ? data.error : "The scan did not finish.");
        const running = data.status === "running";
        buttonState("busy", running ? "Checking domain" : "Waiting in queue");
        status.textContent = running ? "Checking DNS, website and email settings." : "Waiting for a scan slot.";
    }
    throw new Error("The scan timed out. Please try again later.");
}

async function cancelScan() {
    if(active) active.abort();
    if(activeJob) {
        const {id, token} = activeJob;
        activeJob = null;
        try { await fetch(`/api/scans/${encodeURIComponent(id)}`, {method: "DELETE", headers: {Authorization: `Bearer ${token}`}, signal: AbortSignal.timeout(5000)}); } catch { /* Local worker still has its own deadline. */ }
    }
}

async function runPublicDns(domain) {
    if(Date.now() < nextDnsCheck) { status.textContent = "Wait a few seconds before checking again."; return; }
    active = new AbortController();
    nextDnsCheck = Date.now() + 5000;
    cancel.hidden = false;
    submit.disabled = true; demo.disabled = true; input.readOnly = true;
    buttonState("busy", "Checking DNS");
    status.textContent = "Checking public DNS and email records.";
    document.getElementById("results").hidden = true;
    let completed = false;
    try {
        let report = await publicDns(domain, active.signal);
        if(active.signal.aborted) return;
        let hosted = false;
        if(canRequestHosted(domain, location)) {
            status.textContent = "DNS complete. Checking website settings in an isolated worker.";
            try {
                report = mergeHosted(report, await requestHosted(domain, active.signal));
                hosted = true;
            } catch(cause) {
                if(cause?.name === "AbortError") throw cause;
                if(active.signal.aborted) return;
            }
        }
        if(active.signal.aborted) return;
        showReport(report, false);
        completed = true;
        status.textContent = hosted ? "DNS and website observations ready." : "DNS report ready. Website checks were unavailable or not attempted.";
        buttonState("done", "✓ Check again");
    } catch(error) {
        if(error.name !== "AbortError") status.textContent = "The DNS check could not be completed. Try again later.";
    } finally {
        active = null; cancel.hidden = true; submit.disabled = false; demo.disabled = false; input.readOnly = false;
        if(!completed) buttonState("idle", "Check DNS ↗");
    }
}

async function runScan(event) {
    event.preventDefault();
    if(!liveEnabled || active) return;
    error.textContent = "";
    const domain = normalizeDomain(input.value);
    if(!domain) { error.textContent = "Enter a domain name such as example.com. URLs and IP addresses are not accepted."; input.focus(); return; }
    if(publicDns) { await runPublicDns(domain); return; }
    active = new AbortController();
    const timer = setTimeout(() => { void cancelScan(); status.textContent = "Scan timed out."; }, 135000);
    cancel.hidden = false;
    submit.disabled = true;
    demo.disabled = true;
    input.readOnly = true;
    buttonState("busy", "Starting check");
    status.textContent = "";
    let completed = false;
    document.getElementById("results").hidden = true;
    try {
        const response = await fetch("/api/scans", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({domain}), signal: active.signal, cache: "no-store"});
        const data = await readJson(response);
        if(!response.ok) throw new Error(messageFor(response, data));
        if(typeof data.id !== "string" || typeof data.access_token !== "string") throw new Error("The server returned an incomplete scan response.");
        activeJob = {id: data.id, token: data.access_token};
        if(active.signal.aborted) throw new DOMException("Cancelled", "AbortError");
        buttonState("busy", "Waiting in queue");
        const outcome = await poll(data.id, data.access_token, active.signal);
        if(active.signal.aborted) throw new DOMException("Cancelled", "AbortError");
        if(!outcome.result) throw new Error("No result was returned for this scan.");
        activeJob = null;
        showReport(outcome.result, false);
        completed = true;
        buttonState("done", "✓ Check again");
        status.textContent = "Report ready. See your results below.";
    } catch(cause) {
        if(cause.name !== "AbortError") status.textContent = cause instanceof Error ? cause.message : "The scan could not be completed.";
    } finally {
        clearTimeout(timer); await cancelScan(); active = null; cancel.hidden = true;
        submit.disabled = !liveEnabled; demo.disabled = false; input.readOnly = false;
        if(!completed) buttonState("idle", "Check domain ↗");
    }
}

function setFilter(filter) {
    if(!lastReport) return;
    selectedFilter = filter;
    const all = document.getElementById("filter-all");
    const review = document.getElementById("filter-review");
    all.setAttribute("aria-pressed", String(filter === "all"));
    review.setAttribute("aria-pressed", String(filter === "review"));
    renderReport(lastReport.report, lastReport.source === "synthetic-example", filter);
}

document.getElementById("filter-all").addEventListener("click", () => setFilter("all"));
document.getElementById("filter-review").addEventListener("click", () => setFilter("review"));
form.addEventListener("submit", runScan);
cancel.addEventListener("click", () => { void cancelScan(); status.textContent = publicDns ? "Stopped waiting for this report. A hosted probe already started may finish within its time limit." : "Scan cancellation requested."; });
demo.addEventListener("click", () => { if(active) return; showReport(demoReport, true); status.textContent = "Showing sample data. No live check was run."; });
input.addEventListener("input", () => { if(!active) buttonState("idle", publicDns ? "Check DNS ↗" : "Check domain ↗"); });
document.getElementById("print-report").addEventListener("click", () => {
    if(!lastReport) return;
    const previous = selectedFilter;
    setFilter("all");
    try { window.print(); } finally { if(previous !== "all") setFilter(previous); }
});
document.getElementById("copy-json").addEventListener("click", async () => {
    if(!lastReport) return;
    try { await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2)); status.textContent = "Report JSON copied."; }
    catch { status.textContent = "Copy failed. Your browser may block clipboard access."; }
});
function download(content, type, filename) {
    const blob = new Blob([content], {type});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
document.getElementById("download-json").addEventListener("click", () => {
    if(lastReport) download(JSON.stringify(lastReport, null, 2), "application/json", reportFilename(lastReport.report, "report", "json"));
});
document.getElementById("download-plan").addEventListener("click", () => {
    if(lastReport) download(actionDocument(lastReport.report, lastReport.source === "synthetic-example"), "text/html;charset=utf-8", reportFilename(lastReport.report, "action-plan", "html"));
});
export const ready = loadMode();
