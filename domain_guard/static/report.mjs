export function exportReport(report, synthetic) {
    // The source label stays with a copied report, not only the visible page.
    return {source: synthetic ? "synthetic-example" : report?.scope === "dns-email" ? "public-dns" : report?.scope === "hosted-combined" ? "hosted-preview" : "local-scan", report};
}
