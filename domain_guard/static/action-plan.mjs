import { recommendations } from "./advice.mjs";
import { normalizeDomain } from "./input.mjs";

const instructions = Object.freeze({
    "Review your browser content policy": ["Website developer", "Retest the affected pages and confirm the enforcing Content-Security-Policy header appears without breaking required resources."],
    "Review protection against embedding": ["Website developer", "Confirm the intended frame restriction is returned by the server and legitimate embeds continue to work."],
    "Review HTTPS enforcement": ["Hosting provider or web developer", "Verify HTTPS across the intended scope, then confirm a valid positive Strict-Transport-Security max-age is returned."],
    "Review browser file handling": ["Hosting provider or web developer", "Confirm nosniff is returned and the site still serves scripts, styles and other files with the correct content types."],
    "Review the HTTPS certificate": ["Hosting provider", "Confirm normal browser access without certificate errors and run this check again."],
    "Confirm certificate renewal": ["Hosting provider", "Check the renewal status in the hosting dashboard, then rescan after renewal to confirm the new expiry date."],
    "Review HTTPS connectivity": ["Hosting provider", "Verify connectivity from a normal browser and repeat the check. Investigate persistent failures."],
    "Review the redirect configuration": ["Website developer", "Verify the intended redirect in a browser and rerun the check. This report does not follow the redirect chain."],
    "Consider email transport protections": ["Email administrator", "Confirm provider support, test the policy and check that discovery records and reporting are configured as intended."],
    "Retry unavailable checks": ["Domain or hosting administrator", "Repeat the check later and investigate any unavailable results that persist."],
    "Confirm the domain can be assessed": ["Domain administrator", "Verify the hostname and public DNS configuration. Do not bypass the destination restrictions."]
});

export function actionSteps(action) {
    const entry = Object.hasOwn(instructions, action.title) ? instructions[action.title] : null;
    if(entry) return {owner: entry[0], verify: entry[1]};
    return {owner: "Email administrator", verify: "Validate the published policy with your provider, test authorized mail delivery and repeat the DNS check."};
}

export function reportFilename(report, type, extension) {
    const domain = typeof report?.domain === "string" ? normalizeDomain(report.domain) : null;
    const stem = domain && domain.length <= 100 ? domain : "domain";
    const kind = type === "action-plan" ? "action-plan" : "report";
    const suffix = extension === "html" ? "html" : "json";
    return `${stem}-${kind}-by-domainguard.${suffix}`;
}

function escape(value) {
    return String(value).replace(/[&<>"']/g, char => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"})[char]);
}

export function actionDocument(report, synthetic = false) {
    const domain = typeof report?.domain === "string" ? normalizeDomain(report.domain) : null;
    const title = escape(domain || "Unknown domain");
    const source = synthetic ? "Example report, not a live scan" : report?.scope === "dns-email" ? "Live public DNS observations only; HTTPS, TLS and headers not assessed" : report?.scope === "hosted-combined" ? "Protected preview: public DNS and isolated website observations for this domain only" : "Local scan";
    const actions = recommendations(report);
    const items = actions.map((action, index) => {
        const steps = actionSteps(action);
        return `<section><p class="priority">${index + 1}. ${escape(action.priority)}</p><h2>${escape(action.title)}</h2><p><b>Who can help:</b> ${escape(steps.owner)}</p><p><b>Recommended change:</b> ${escape(action.detail)}</p><p><b>How to verify:</b> ${escape(steps.verify)}</p></section>`;
    }).join("");
    const body = items || "<p>No specific changes were identified. This does not establish that the domain is secure.</p>";
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-rcdTe2yRmwvE+d0T2ix1tXKjE1bI8I9a8C7nWlW+LuY='; base-uri 'none'; form-action 'none'"><title>${title} | Action plan by DomainGuard</title><style>body{font:15px/1.6 system-ui,sans-serif;color:#111;background:#fff;max-width:760px;margin:40px auto;padding:0 20px}header{border-top:8px solid #C9EF35;padding-top:20px}h1{font-size:32px;overflow-wrap:anywhere;line-height:1.1}h2{font-size:20px;margin:4px 0 12px}.priority{font-weight:bold;margin:0}section{border-top:1px solid #aaa;padding:20px 0;break-inside:avoid}footer{border-top:1px solid #aaa;margin-top:30px;padding-top:10px}p{margin:8px 0}@media print{body{margin:0;padding:0}}</style></head><body><header><p><b>DomainGuard / Action plan</b></p><h1>${title}</h1><p>${source} | ${actions.length} suggested actions</p><p>Use this document to discuss configuration changes with your provider. It is not a security certification or a guarantee. Some recommendations are optional.</p></header><main>${body}</main><footer><p>Back up existing settings, test changes in a controlled environment and confirm normal operation before deploying them. Keep this report private if it contains information you do not wish to share.</p><p>Action plan by DomainGuard</p></footer></body></html>`;
}
