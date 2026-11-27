import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runPilot, GatewayError } from "../domain_guard/hosted-sdk/gateway.mjs";
import { createQuota } from "../domain_guard/hosted-sdk/quota.mjs";
import { lookupApproved } from "../domain_guard/hosted-sdk/resolve.mjs";

const DOMAIN = "domainguard-check.vercel.app";
const PATHS = ["domain_guard/hosted_probe.py","domain_guard/checks/headers.py","domain_guard/checks/redirects.py","domain_guard/validation.py"];

export default async function handler(req,res) {
    res.setHeader("Cache-Control","no-store");
    res.setHeader("X-Content-Type-Options","nosniff");
    res.setHeader("Content-Type","application/json; charset=utf-8");
    if(process.env.VERCEL_ENV !== "preview" || process.env.DOMAIN_GUARD_PILOT !== "1") {
        return res.status(404).json({error:"Pilot disabled"});
    }
    if(req.method !== "POST") {
        res.setHeader("Allow","POST");
        return res.status(405).json({error:"Use POST"});
    }
    // Only the owner-controlled fixed domain is permitted in this preview.
    if(req.headers.origin !== "https://" + process.env.VERCEL_URL ||
       req.headers["sec-fetch-site"] !== "same-origin" ||
       req.headers["content-type"] !== "application/json") {
        return res.status(403).json({error:"Preview origin required"});
    }
    if(req.headers["transfer-encoding"] || !/^[0-9]{1,3}$/.test(req.headers["content-length"] ?? "") || Number(req.headers["content-length"]) > 128) {
        return res.status(413).json({error:"Invalid request size"});
    }
    if(!req.body || Object.keys(req.body).length !== 1 || req.body.domain !== DOMAIN) {
        return res.status(400).json({error:"Pilot domain only"});
    }
    // Never use the integration's unrestricted shared Redis credential.
    if(process.env.DOMAIN_GUARD_QUOTA_ACL_VERIFIED !== "1" || !process.env.DOMAIN_GUARD_QUOTA_TOKEN || process.env.DOMAIN_GUARD_QUOTA_TOKEN === process.env.UPSTASH_REDIS_REST_TOKEN) {
        return res.status(503).json({error:"Restricted quota credential required"});
    }
    try {
        const workerFiles = Object.fromEntries(await Promise.all(PATHS.map(async path=>[path,await readFile(join(process.cwd(),path))])));
        const result = await runPilot(DOMAIN,{
            authorize:async domain=>domain===DOMAIN,
            reserve:createQuota({url:process.env.UPSTASH_REDIS_REST_URL,token:process.env.DOMAIN_GUARD_QUOTA_TOKEN}),
            lookupApproved,
            workerFiles,
            createSandbox:async options=>{
                const {Sandbox}=await import("@vercel/sandbox");
                return Sandbox.create(options);
            }
        });
        return res.status(200).json(result);
    } catch(error) {
        const status=error instanceof GatewayError?error.status:503;
        return res.status(status).json({error:"Pilot scan unavailable or declined"});
    }
}
