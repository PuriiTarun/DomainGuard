// Recommendations describe the observed configuration, not a vulnerability verdict.
export const explanations = Object.freeze({
    A: "The IPv4 addresses your domain points to.", AAAA: "The IPv6 addresses your domain points to. IPv6 is optional for many sites.",
    MX: "Where incoming email for this domain is delivered.", NS: "The servers responsible for your domain's DNS settings.",
    TXT: "Text records used by services to publish settings and verify ownership.", CAA: "An optional record that limits which certificate authorities may issue certificates.",
    SOA: "Administrative information about the DNS zone.", address: "Checks whether resolved destinations are public addresses permitted by this tool.",
    https: "Checks whether this domain answers over an encrypted connection. It does not test every page.",
    tls: "Checks whether the certificate is trusted, matches the domain and is within its validity period.",
    headers: "Settings sent to browsers that can help limit certain kinds of attacks.", redirects: "Checks the first HTTPS response for a redirect, without following it.",
    output: "Indicates whether the report exceeded its size limit.", spf: "Publishes which systems are allowed to send email for a domain.",
    dmarc: "Publishes instructions for handling messages that fail email authentication.",
    mta_sts: "Optional email transport policy discovery. The policy itself is not tested.",
    tlsrpt: "Optional DNS setting for receiving reports about email transport encryption failures."
});

const headerAdvice = Object.freeze({
    "Content-Security-Policy": ["Review your browser content policy", "Ask your web developer to inventory the scripts, styles and other resources the site uses. Draft a Content Security Policy (CSP), test it in report-only mode, fix unexpected violations, then enable enforcement. Do not paste a generic policy into production."],
    "X-Frame-Options": ["Review protection against embedding", "Decide which websites, if any, are allowed to embed your pages. Ask your developer to configure CSP frame-ancestors or an appropriate X-Frame-Options header. Test legitimate embeds before enforcing the change."],
    "Strict-Transport-Security": ["Review HTTPS enforcement", "After confirming HTTPS works throughout the intended scope, configure a positive HSTS max-age. Enable subdomain coverage only after checking those subdomains."],
    "X-Content-Type-Options": ["Review browser file handling", "Ask your hosting provider to configure X-Content-Type-Options: nosniff and ensure resources are served with correct content types."]
});

export function recommendations(report) {
    const actions = [];
    const add = (priority, title, detail) => actions.push({priority, title, detail});
    const checks = report?.checks || {};
    if(report?.status === "rejected" || checks.address?.status === "rejected") {
        add("Check first", "Confirm the domain can be assessed", "This tool did not approve the destination. Check your domain name and public DNS configuration; do not bypass its network safety controls.");
        return actions;
    }
    const tls = checks.tls || {};
    if(tls.status === "fail" || tls.status === "failed") add("Check first", "Review the HTTPS certificate", "Ask your hosting provider to verify the certificate's validity, trust chain and hostname coverage. Do not disable certificate verification.");
    else if(["ok", "pass", "success"].includes(tls.status) && Number.isInteger(tls.days_remaining) && tls.days_remaining <= 30 && tls.days_remaining >= 0) add("Plan renewal", "Confirm certificate renewal", "Check that automatic renewal is enabled, or schedule renewal with your hosting provider before the certificate expires.");
    if(["fail", "failed", "unavailable", "incomplete"].includes(checks.https?.status) && !actions.some(item => item.title === "Review the HTTPS certificate")) add("Check first", "Review HTTPS connectivity", "Try opening the site normally and ask your hosting provider to review HTTPS if the problem persists. A failed check here can also be caused by a network or scan limitation.");
    const seen = new Set();
    if(Array.isArray(checks.headers?.findings)) {
        for(const finding of checks.headers.findings.slice(0, 12)) {
            if(finding?.status !== "warning" || !Object.hasOwn(headerAdvice, finding.name) || seen.has(finding.name)) continue;
            seen.add(finding.name);
            add("Review", ...headerAdvice[finding.name]);
        }
    }
    if(checks.redirects?.status === "warning") add("Review", "Review the redirect configuration", "Inspect the Location response and confirm the intended destination and HTTPS settings with your host. DomainGuard did not follow the redirect.");
    for(const [key, name] of [["spf", "SPF"], ["dmarc", "DMARC"]]) {
        const item = report?.[key];
        if(!item) continue;
        if(item.status === "multiple") add("Review", `Review duplicate ${name} records`, `Ask your email administrator to consolidate conflicting ${name} records into a single appropriate policy. Check all legitimate senders before changing DNS.`);
        else if(["missing", "nxdomain"].includes(item.status)) add("If you use email", `Check whether ${name} is configured`, `No matching ${name} record was found at the checked name. Ask your email provider whether a record is needed; this check does not establish the effective policy.`);
        else if(item.status === "found" && Array.isArray(item.findings) && item.findings.some(f => f?.status === "warning")) add("Review", `Review the ${name} policy`, `The published record contains a policy observation worth reviewing. Ask your email administrator to validate its syntax and legitimate senders before changing it.`);
    }
    if(["mta_sts", "tlsrpt"].some(key => ["missing", "nxdomain"].includes(report?.[key]?.status))) add("Optional", "Consider email transport protections", "If this domain receives email, ask your mail provider whether it supports MTA-STS and SMTP TLS reporting. Plan and test the policy before enforcing it. These optional records are not a vulnerability by themselves.");
    if(report?.status === "incomplete") add("Check again", "Retry unavailable checks", "Some information could not be determined. Retry later and investigate persistent failures with your provider; unavailable does not mean safe or unsafe.");
    const priorities = ["Check first", "Check again", "Plan renewal", "Review", "If you use email", "Optional"];
    return actions.sort((a, b) => priorities.indexOf(a.priority) - priorities.indexOf(b.priority));
}

export function formatActionPlan(report, synthetic = false) {
    const actions = recommendations(report);
    const domain = typeof report?.domain === "string" ? report.domain.replace(/[^a-zA-Z0-9.-]/g, "?").slice(0, 253) : "Unknown domain";
    const lines = ["Action plan by DomainGuard", `Domain: ${domain}`, synthetic ? "Source: Example report (not a live scan)" : report?.scope === "dns-email" ? "Source: Live public DNS observations only; HTTPS, TLS and headers not assessed" : "Source: Local scan", "", "Configuration observations, not a security certification.", ""];
    for(const [index, action] of actions.entries()) lines.push(`${index + 1}. ${action.title} (${action.priority})`, action.detail, "");
    if(!actions.length) lines.push("No specific changes were identified. This does not establish that the domain is secure.", "");
    lines.push("Test changes before applying them to a live website or email service.");
    return lines.join("\n") + "\n";
}
