import { isIP } from "node:net";

const blocked = [[0,0,0,0,8],[10,0,0,0,8],[100,64,0,0,10],[127,0,0,0,8],[169,254,0,0,16],[172,16,0,0,12],[192,0,0,0,24],[192,0,2,0,24],[192,88,99,0,24],[192,168,0,0,16],[198,18,0,0,15],[198,51,100,0,24],[203,0,113,0,24],[224,0,0,0,4],[240,0,0,0,4]];
const denied = blocked.map(([a,b,c,d,bits]) => `${a}.${b}.${c}.${d}/${bits}`);
const ipv4Number = address => address.split(".").reduce((value, part) => (value * 256 + Number(part)) >>> 0, 0);
const workerPaths = ["domain_guard/hosted_probe.py", "domain_guard/checks/headers.py", "domain_guard/checks/redirects.py", "domain_guard/validation.py"];

export function publicIPv4(address) {
    if(typeof address !== "string" || isIP(address) !== 4) return false;
    const value = ipv4Number(address);
    return !blocked.some(([a,b,c,d,bits]) => {
        const mask = (0xffffffff << (32 - bits)) >>> 0;
        return ((value & mask) >>> 0) === ((ipv4Number(`${a}.${b}.${c}.${d}`) & mask) >>> 0);
    });
}

export function canonicalDomain(value) {
    if(typeof value !== "string" || value.length > 253 || !/^[a-z0-9.-]+$/.test(value)) return false;
    const labels = value.split(".");
    const suffix = labels.at(-1);
    if(labels.length < 2 || !/^[a-z]{2,63}$/.test(suffix) || ["localhost","local","internal","invalid","test","onion","home","lan","example","arpa","alt","localdomain","corp","intranet","private"].includes(suffix)) return false;
    return labels.every(label => label.length <= 63 && !label.startsWith("xn--") && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

export class GatewayError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

// No HTTP endpoint or public mode is enabled by this module. Admission and DNS
// dependencies must be trusted server-side implementations, never request fields.
export async function runPilot(domain, dependencies) {
    const {authorize, reserve, lookupApproved, createSandbox, workerFiles} = dependencies;
    if(!canonicalDomain(domain)) throw new GatewayError(400, "Enter a valid hostname");
    if(typeof authorize !== "function" || await authorize(domain) !== true) throw new GatewayError(403, "Pilot access denied");
    if(typeof reserve !== "function" || await reserve() !== true) throw new GatewayError(429, "Scan quota unavailable");
    // A reservation is consumed even if DNS, provisioning or the worker fails.
    const address = await lookupApproved(domain);
    if(!publicIPv4(address)) throw new GatewayError(422, "No approved public IPv4 destination");
    if(!workerFiles || workerPaths.some(path => !Buffer.isBuffer(workerFiles[path]) || workerFiles[path].length > 32768)) throw new GatewayError(503, "Worker unavailable");
    const sandbox = await createSandbox({persistent: false, timeout: 30000, resources: {vcpus: 1}, ports: [], networkPolicy: {allow: [], subnets: {allow: [address + "/32"], deny: denied}}});
    let result;
    try {
        await sandbox.writeFiles(workerPaths.map(path => ({path, content: workerFiles[path]})));
        const command = await sandbox.runCommand("python3", ["-m", "domain_guard.hosted_probe", domain, address]);
        if(command.exitCode !== 0) throw new GatewayError(502, "Probe failed");
        const output = await command.stdout();
        if(typeof output !== "string" || Buffer.byteLength(output) > 16384) throw new GatewayError(502, "Invalid probe response");
        const data = JSON.parse(output);
        if(data.domain !== domain || data.scope !== "hosted-web-probe" || data.schema_version !== 1 || !["complete","incomplete"].includes(data.status) || !Array.isArray(data.addresses) || data.addresses.length !== 1 || data.addresses[0] !== address || !data.checks || Object.keys(data.checks).sort().join(",") !== "headers,https,redirects,tls") throw new GatewayError(502, "Invalid probe response");
        for(const item of Object.values(data.checks)) if(!item || !["pass","fail","info","warning","unavailable","incomplete"].includes(item.status)) throw new GatewayError(502, "Invalid check status");
        result = data;
    } finally {
        // A failed cleanup is not reported as a successful scan.
        await sandbox.stop();
    }
    return result;
}
