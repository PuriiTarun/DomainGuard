// Fixed demonstration data. No external request is made to produce this report.

export const demoReport = Object.freeze({
    domain: "example.com",
    schema_version: 1,
    status: "incomplete",
    addresses: ["93.184.215.14"],
    checks: {
        https: {status: "ok", status_code: 200, message: "Verified HTTPS connection completed"},
        tls: {status: "ok", expires: "2027-06-01", days_remaining: 187, message: "Certificate verified for example.com"},
        headers: {status: "warning", message: "Illustrative security header observations", findings: [
            {name: "Strict-Transport-Security", status: "pass", message: "Positive HSTS max-age observed"},
            {name: "Content-Security-Policy", status: "warning", message: "No enforcing CSP observed"},
            {name: "X-Frame-Options", status: "warning", message: "No recognized frame restriction observed"}
        ]},
        redirects: {status: "unknown", message: "Redirects were not followed"}
    },
    records: {
        A: {status: "found", values: ["93.184.215.14"]},
        AAAA: {status: "missing", values: []},
        MX: {status: "found", values: ["10 mail.example.com."]},
        NS: {status: "found", values: ["ns1.example.com.", "ns2.example.com."]},
        TXT: {status: "found", values: ["v=spf1 -all"]}
    },
    spf: {status: "found", values: ["v=spf1 -all"]},
    dmarc: {status: "missing", values: []},
    mta_sts: {status: "missing", values: []},
    tlsrpt: {status: "missing", values: []}
});
