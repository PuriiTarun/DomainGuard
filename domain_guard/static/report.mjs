export function exportReport(report, synthetic) {
    // The source label stays with a copied report, not only the visible page.
    return {source: synthetic ? "synthetic-example" : "local-scan", report};
}
