const KEY = "domainguard:scan-quota:v1";
export const LIMITS = Object.freeze({daily:10, monthly:100, cooldown:35});
export const INITIAL_STATE = "v1:0:0:0:0:0";

export const RESERVE = `
local raw = redis.call("GET", KEYS[1])
if not raw then return 0 end
local d, dc, m, mc, next = string.match(raw, "^v1:(%d+):(%d+):(%d+):(%d+):(%d+)$")
if not d then return 0 end
d, dc, m, mc, next = tonumber(d), tonumber(dc), tonumber(m), tonumber(mc), tonumber(next)
local now = tonumber(redis.call("TIME")[1])
local day, dayEnd, month, monthEnd = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
if not now or not day or not dayEnd or not month or not monthEnd then return 0 end
if now < day or now >= dayEnd or now < month or now >= monthEnd or d > day or m > month or dc > 10 or mc > 100 then return 0 end
if d < day then d, dc = day, 0 end
if m < month then m, mc = month, 0 end
if dc >= 10 or mc >= 100 or now < next then return 0 end
redis.call("SET", KEYS[1], string.format("v1:%d:%d:%d:%d:%d", d, dc+1, m, mc+1, now+35), "XX")
return 1
`;

export function utcWindows(now) {
    if(!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid clock");
    const t = new Date(now);
    const y = t.getUTCFullYear(), m = t.getUTCMonth(), d = t.getUTCDate();
    return [Date.UTC(y,m,d),Date.UTC(y,m,d+1),Date.UTC(y,m,1),Date.UTC(y,m+1,1)].map(x=>String(x/1000));
}

export function createQuota({url,token,fetcher=fetch,clock=Date.now}={}) {
    let endpoint;
    try {
        const u = new URL(url);
        if(u.protocol !== "https:" || !/^[a-z0-9-]+\.upstash\.io$/.test(u.hostname) || u.username || u.password || u.port || u.pathname !== "/" || u.search || u.hash) return async()=>false;
        endpoint=u.origin;
    } catch { return async()=>false; }
    if(typeof token !== "string" || token.length < 16 || token.length > 2048 || !/^[\x21-\x7e]+$/.test(token)) return async()=>false;
    return async function reserve() {
        try {
            const response = await fetcher(endpoint,{method:"POST",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify(["EVAL",RESERVE,"1",KEY,...utcWindows(clock())]),redirect:"error",cache:"no-store",signal:AbortSignal.timeout(3000)});
            if(!response.ok || !response.body) return false;
            const reader=response.body.getReader();
            const chunks=[]; let size=0;
            try {
                while(true) {
                    const {done,value}=await reader.read();
                    if(done) break;
                    size+=value.byteLength;
                    if(size>1024) {await reader.cancel();return false;}
                    chunks.push(Buffer.from(value));
                }
            } finally {reader.releaseLock();}
            const data=JSON.parse(Buffer.concat(chunks).toString("utf8"));
            return Object.keys(data).length===1 && data.result===1;
        } catch { return false; }
    };
}
