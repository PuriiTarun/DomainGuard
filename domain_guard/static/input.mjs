export function normalizeDomain(value) {
    if(typeof value !== "string" || value.length > 512 || /[^\x20-\x7e]/.test(value)) return null;
    const name = value.trim().toLowerCase();
    if(name.length > 253 || name.length < 4 || !/^[a-z0-9.-]+$/.test(name)) return null;
    const labels = name.split(".");
    if(labels.length < 2 || !/^[a-z]{2,63}$/.test(labels.at(-1))) return null;
    if(labels.some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
    if(labels.some(label => label.startsWith("xn--"))) return null;
    if(["localhost", "local", "internal", "invalid", "test", "onion", "home", "lan", "example", "arpa", "alt", "localdomain", "corp", "intranet", "private"].includes(labels.at(-1))) return null;
    return name;
}
