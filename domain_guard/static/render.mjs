import { explanations, recommendations } from "./advice.mjs";
import { actionSteps } from "./action-plan.mjs";

// Result data is untrusted. Render every value as a text node.

const recordNames = {A: "IPv4 addresses (A)", AAAA: "IPv6 addresses (AAAA)", MX: "Mail servers (MX)", NS: "Name servers (NS)", TXT: "Text records (TXT)", CAA: "Certificate issuers (CAA)", SOA: "DNS zone information (SOA)"};
const names = {address: "Public addresses", https: "HTTPS", tls: "TLS certificate", headers: "Security headers", redirects: "Redirects", output: "Output budget", spf: "SPF", dmarc: "DMARC", mta_sts: "MTA-STS", tlsrpt: "SMTP TLS reporting"};
const states = {
    pass: ["Verified", "ok"], fail: ["Failed", "problem"], info: ["Observed", "unknown"], ok: ["Verified", "ok"], found: ["Found", "ok"], success: ["Verified", "ok"],
    multiple: ["Multiple records", "warning"], warning: ["Warning", "warning"],
    failed: ["Failed", "problem"], rejected: ["Rejected", "problem"], invalid: ["Invalid", "problem"],
    missing: ["Not found", "unknown"], nxdomain: ["DNS name not found", "unknown"],
    error: ["Unavailable", "unknown"], incomplete: ["Incomplete", "unknown"], unknown: ["Unavailable", "unknown"],
    unavailable: ["Unavailable", "unknown"], skipped: ["Not assessed", "unknown"]
};

function text(value, max = 400) {
    if(value === null || value === undefined) return "";
    return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "?").slice(0, max);
}

export function describeReport(report) {
    const data = report && typeof report === "object" ? report : {};
    const checks = data.checks && typeof data.checks === "object" ? data.checks : {};
    const records = data.records && typeof data.records === "object" ? data.records : {};
    const groups = [];
    const dns = Object.entries(records).slice(0, 8).map(([name, value]) => ({name: Object.hasOwn(recordNames, name) ? recordNames[name] : name, key: name, ...readCheck(value)}));
    if(dns.length) groups.push({name: "DNS records", items: dns});
    const web = ["address", "https", "tls", "headers", "redirects", "output"].filter(key => checks[key]).map(key => ({name: names[key], key, ...readCheck(checks[key])}));
    const addressCheck = web.find(item => item.key === "address");
    if(addressCheck?.kind === "ok" && Array.isArray(data.addresses)) {
        const screened = data.addresses.slice(0, 16).map(value => text(value, 80));
        if(screened.length) addressCheck.details.push(`Screened DNS addresses: ${screened.join(", ")}`);
        if(data.addresses.length > 16) addressCheck.details.push("More screened addresses are available in the JSON report.");
        addressCheck.details.push("The HTTPS and TLS checks use one screened address, not every address listed.");
    }
    if(web.length) groups.push({name: "HTTPS & TLS", items: web});
    const email = ["spf", "dmarc", "mta_sts", "tlsrpt"].filter(key => data[key]).map(key => ({name: names[key], key, ...readCheck(data[key])}));
    if(email.length) groups.push({name: "Email records", items: email});
    return {domain: text(data.domain, 253), status: text(data.status, 32), addresses: Array.isArray(data.addresses) ? data.addresses.slice(0, 16).map(v => text(v, 80)) : [], groups};
}

function readCheck(value) {
    const item = value && typeof value === "object" ? value : {};
    const status = text(item.status, 32).toLowerCase();
    const [label, baseKind] = Object.hasOwn(states, status) ? states[status] : ["Unavailable", "unknown"];
    const policyWarning = status === "found" && Array.isArray(item.findings) && item.findings.some(finding => finding?.status === "warning");
    const kind = policyWarning ? "warning" : baseKind;
    const details = Array.isArray(item.values) ? item.values.slice(0, 30).map(v => text(v)) : [];
    if(Array.isArray(item.values) && item.values.length > 30) details.push(`${item.values.length - 30} more values in the JSON report`);
    if(item.message) details.unshift(text(item.message));
    if(Array.isArray(item.findings)) {
        for(const finding of item.findings.slice(0, 12)) {
            if(!finding || typeof finding !== "object") continue;
            const label = Object.hasOwn(states, finding.status) ? states[finding.status][0] : "Unavailable";
            details.push(`${text(finding.name, 80)} | ${label}: ${text(finding.message)}`);
        }
    }
    if(Number.isInteger(item.status_code)) details.push(`HTTP ${item.status_code}`);
    if(item.expires) details.push(`Expires ${text(item.expires, 40)}`);
    if(Number.isInteger(item.days_remaining)) details.push(`${item.days_remaining} days remaining`);
    return {label, kind, details};
}

function plainOutcome(item) {
    if(item.key === "tls" && item.kind === "ok") {
        const expiry = item.details.find(value => value.startsWith("Expires "));
        const remaining = item.details.find(value => /^\d+ days remaining$/.test(value));
        return ["A trusted certificate was verified.", expiry ? expiry.replace("Expires ", "Expires on ") + "." : "", remaining ? remaining + "." : ""].filter(Boolean).join(" ");
    }
    if(item.key === "https" && item.kind === "ok") return "The website responded over HTTPS. " + (item.details.find(value => /^HTTP \d+$/.test(value)) || "");
    if(item.key === "headers") {
        const warnings = item.details.filter(value => value.includes(" | Warning: ")).length;
        if(warnings) return `${warnings} browser security setting${warnings === 1 ? "" : "s"} worth reviewing. See the suggestions below.`;
    }
    if(item.label === "Not found" || item.label === "DNS name not found") {
        if(["AAAA", "CAA", "mta_sts", "tlsrpt"].includes(item.key)) return "Not published. This setting is optional in many configurations.";
        if(item.key === "MX") return "No explicit mail server record was found. This alone does not prove email is unavailable.";
        return "No matching record was found at the name checked.";
    }
    if(item.kind === "problem") return "This check could not verify the expected configuration. Review the technical details.";
    if(item.label === "Not assessed") return "This check is outside the assessment scope. No result was measured.";
    if(["Unavailable", "Incomplete"].includes(item.label)) return "This check could not be completed. Its result is not known.";
    if(item.kind === "warning") return "A configuration detail is worth reviewing; this is not proof of a vulnerability.";
    if(item.label === "Found") {
        if(item.key === "spf" || item.key === "dmarc") return "A published policy was found. This does not verify that email passes authentication.";
        if(item.key === "mta_sts" || item.key === "tlsrpt") return "A discovery record was found. The underlying policy or delivery process was not tested.";
        if(item.key === "A") return "This domain has an IPv4 address published for connections.";
        if(item.key === "AAAA") return "This domain has an IPv6 address published for connections.";
        if(item.key === "MX") return "Mail server records are published. Delivery was not tested.";
        if(item.key === "NS") return "Name servers are published for this domain.";
        if(item.key === "TXT") return "Text settings are published by one or more services.";
        if(item.key === "CAA") return "Certificate authority restrictions are published.";
        if(item.key === "SOA") return "DNS zone information was returned.";
        return "A matching record was found.";
    }
    return "See the observed values below for details.";
}

function element(name, className, value) {
    const node = document.createElement(name);
    if(className) node.className = className;
    if(value !== undefined) node.textContent = text(value);
    return node;
}

function addSummary(container, label, value) {
    const card = element("div", "summary-card");
    card.append(element("span", "label", label), element("strong", "value", value));
    container.append(card);
}

export function renderReport(report, synthetic = false, filter = "all") {
    const view = describeReport(report);
    const summary = document.getElementById("summary-grid");
    const groups = document.getElementById("result-groups");
    summary.replaceChildren();
    groups.replaceChildren();
    document.getElementById("result-kind").textContent = synthetic ? "Example report (not a live scan)" : report?.scope === "dns-email" ? "Live DNS and email observations" : report?.scope === "hosted-combined" ? "DNS and website observations" : "Local scan result";
    document.getElementById("results-title").textContent = view.domain || "Assessment results";
    document.getElementById("result-subtitle").textContent = synthetic ? "Sample data for learning how to read the report." : report?.scope === "dns-email" ? "Public DNS observations via Google Public DNS. HTTPS, TLS, headers and redirects were not assessed." : report?.scope === "hosted-combined" ? "DNS observations from Google Public DNS; website observations from an isolated HTTPS HEAD probe of this domain." : "Configuration observed during this scan.";
    addSummary(summary, report?.scope === "dns-email" && !synthetic ? "DNS assessment" : report?.scope === "hosted-combined" ? "Hosted assessment" : "Assessment", view.status === "complete" ? "Complete" : view.status === "rejected" ? "Rejected" : "Incomplete");
    const items = view.groups.flatMap(group => group.items);
    const actions = recommendations(report);
    addSummary(summary, "Suggested actions", actions.length);
    const skipped = items.filter(item => item.label === "Not assessed").length;
    addSummary(summary, "Checks attempted", items.length - skipped);
    const attention = items.filter(item => ["warning", "problem"].includes(item.kind)).length;
    const brief = attention ? `${attention} check${attention === 1 ? " has" : "s have"} warnings or failures. Start with the recommended actions.` : "No warning or failure was recorded in these checks. Review missing and unavailable results separately.";
    document.getElementById("report-brief-text").textContent = brief + (skipped ? ` ${skipped} checks were outside the assessment scope.` : "");
    const visible = items.filter(item => filter !== "review" || ["warning", "problem"].includes(item.kind));
    document.getElementById("filter-status").textContent = `Showing ${visible.length} of ${items.length} checks${filter === "review" ? " with warnings or failures" : ""}.`;
    if(!visible.length) groups.append(element("p", "no-actions", "No warnings or failures in the selected checks. Review unavailable or missing results and the recommendations separately."));
    for(const group of view.groups) {
        const selected = group.items.filter(item => visible.includes(item));
        if(!selected.length) continue;
        const section = element("section", "result-group");
        section.append(element("h4", "group-title", group.name));
        for(const item of selected) {
            const row = element("div", "finding");
            const value = element("div", "finding-value");
            value.append(element("span", `status-tag ${item.kind}`, item.label));
            value.append(element("p", "finding-outcome", plainOutcome(item)));
            if(Object.hasOwn(explanations, item.key)) value.append(element("p", "finding-explanation", explanations[item.key]));
            if(item.details.length) {
                const list = element("ul", "evidence-list");
                for(const detail of item.details) list.append(element("li", "", detail));
                const detail = element("details", "technical");
                detail.append(element("summary", "", `Technical evidence (${item.details.length})`), list);
                value.append(detail);
            }
            row.append(element("div", "finding-label", item.name), value);
            section.append(row);
        }
        groups.append(section);
    }
    const target = document.getElementById("recommendations");
    target.replaceChildren();
    if(actions.length) {
        const list = element("ol", "recommendation-list");
        for(const action of actions) {
            const row = element("li", "recommendation");
            const content = element("div");
            const steps = actionSteps(action);
            content.append(element("h4", "", action.title), element("span", "recommendation-owner", `Who can help: ${steps.owner}`), element("p", "", action.detail), element("p", "recommendation-verify", `How to verify: ${steps.verify}`));
            row.append(element("span", "recommendation-priority", action.priority), content);
            list.append(row);
        }
        target.append(list);
    } else target.append(element("p", "no-actions", "No specific changes were identified by these checks. This does not establish that the domain is secure."));
    document.getElementById("results").hidden = false;
    return view;
}
