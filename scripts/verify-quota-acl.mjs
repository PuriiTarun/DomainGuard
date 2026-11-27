import { pathToFileURL } from "node:url";

const KEY = "domainguard:scan-quota:v1";
const OTHER = "domainguard:acl-probe:unrelated";
const READ = "return redis.call('GET', KEYS[1])";
const STATE = /^v1:\d+:\d+:\d+:\d+:\d+$/;

async function command(url, token, args, request) {
    const response = await request(url, {
        method: "POST", headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
        body: JSON.stringify(args), redirect: "error", cache: "no-store", signal: AbortSignal.timeout(3000)
    });
    const body = await response.text();
    if(body.length > 2048) throw new Error("Oversized provider reply");
    let data;
    try { data = JSON.parse(body); } catch { throw new Error("Invalid provider reply"); }
    return {status: response.status, data};
}

function permitted(reply) {
    return reply.status === 200 && reply.data && Object.keys(reply.data).length === 1 && STATE.test(reply.data.result);
}

function denied(reply) {
    return reply.data && typeof reply.data.error === "string" && /NOPERM|permission/i.test(reply.data.error);
}

export async function verifyQuotaAcl({url, token, standardToken, request = fetch}) {
    const endpoint = new URL(url);
    if(endpoint.protocol !== "https:" || !/^[a-z0-9-]+\.upstash\.io$/.test(endpoint.hostname) ||
       endpoint.pathname !== "/" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password || endpoint.port) throw new Error("Invalid provider endpoint");
    if(typeof token !== "string" || token.length < 16 || token === standardToken) throw new Error("Restricted token required");
    const allowedGet = await command(endpoint.origin, token, ["GET", KEY], request);
    const allowedLua = await command(endpoint.origin, token, ["EVAL", READ, "1", KEY], request);
    const deniedGet = await command(endpoint.origin, token, ["GET", OTHER], request);
    const deniedLua = await command(endpoint.origin, token, ["EVAL", READ, "1", OTHER], request);
    if(!permitted(allowedGet) || !permitted(allowedLua) || allowedGet.data.result !== allowedLua.data.result ||
       !denied(deniedGet) || !denied(deniedLua)) throw new Error("Restricted ACL verification failed");
    return {allowedKey: KEY, deniedKey: OTHER, directReadDenied: true, luaReadDenied: true};
}

if(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    try {
        const result = await verifyQuotaAcl({url: process.env.UPSTASH_REDIS_REST_URL,
            token: process.env.DOMAIN_GUARD_QUOTA_TOKEN, standardToken: process.env.UPSTASH_REDIS_REST_TOKEN});
        process.stdout.write(JSON.stringify(result) + "\n");
    } catch {
        process.stderr.write("Restricted ACL verification failed; admission must remain disabled.\n");
        process.exitCode = 1;
    }
}
