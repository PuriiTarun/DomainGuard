import { runPilot, GatewayError, canonicalDomain } from "../hosted-backend/gateway.mjs";
import { createQuota } from "../hosted-backend/quota.mjs";
import { lookupApproved } from "../hosted-backend/resolve.mjs";
import { EMBEDDED_WORKERS } from "../hosted-backend/embedded-workers.mjs";

const PILOT_DOMAIN = "domainguard-check.vercel.app";
const PUBLIC_HOST = "domainguard-check.vercel.app";
const PREVIEW_HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/;

export function createHandler({loadFiles,quota=createQuota,lookup=lookupApproved,createSandbox}={}) {
    const files = loadFiles ?? (async()=>EMBEDDED_WORKERS);
    const sandbox = createSandbox ?? (async options=>{
        const {Sandbox}=await import("@vercel/sandbox");
        return Sandbox.create(options);
    });
    return async function handler(req,res) {
        res.setHeader("Cache-Control","no-store");
        res.setHeader("X-Content-Type-Options","nosniff");
        res.setHeader("Content-Type","application/json; charset=utf-8");
        const publicMode = process.env.VERCEL_ENV === "production" && process.env.DOMAIN_GUARD_PUBLIC === "1";
        const previewMode = process.env.VERCEL_ENV === "preview" && process.env.DOMAIN_GUARD_PILOT === "1";
        if(!publicMode && !previewMode) return res.status(404).json({error:"Pilot disabled"});
        if(req.method !== "POST") {
            res.setHeader("Allow","POST");
            return res.status(405).json({error:"Use POST"});
        }
        // Preview Authentication applies only to preview; headers are not authentication.
        // Public mode is untrusted and relies on restricted quotas and sandbox isolation.
        const host = previewMode ? process.env.VERCEL_URL : PUBLIC_HOST;
        const headers = req.headers ?? {};
        if(typeof host !== "string" || (previewMode && (!PREVIEW_HOST.test(host) || host === PILOT_DOMAIN)) ||
           headers.host !== host || headers.origin !== "https://" + host ||
           headers["sec-fetch-site"] !== "same-origin" ||
           headers["content-type"] !== "application/json") {
            return res.status(403).json({error:"Preview origin required"});
        }
        if(headers["transfer-encoding"] || !/^[0-9]{1,3}$/.test(headers["content-length"] ?? "") || Number(headers["content-length"]) > 128) {
            return res.status(413).json({error:"Invalid request size"});
        }
        const domain = req.body?.domain;
        if(!req.body || typeof req.body !== "object" || Array.isArray(req.body) || Object.keys(req.body).length !== 1 || !canonicalDomain(domain)) {
            return res.status(400).json({error:"Enter a valid public hostname"});
        }
        const allowed = process.env.DOMAIN_GUARD_PILOT_ALLOWLIST;
        if(previewMode && allowed !== PILOT_DOMAIN) return res.status(503).json({error:"Pilot authorization unavailable"});
        if(previewMode && domain !== PILOT_DOMAIN) return res.status(403).json({error:"Pilot domain not authorized"});
        // Never use the integration's unrestricted shared Redis credential.
        if(process.env.DOMAIN_GUARD_QUOTA_ACL_VERIFIED !== "1" || !process.env.DOMAIN_GUARD_QUOTA_TOKEN || process.env.DOMAIN_GUARD_QUOTA_TOKEN === process.env.UPSTASH_REDIS_REST_TOKEN) {
            return res.status(503).json({error:"Restricted quota credential required"});
        }
        let phase = "worker-files";
        try {
            const workerFiles = await files();
            phase = "quota-setup";
            const reserve = quota({url:process.env.UPSTASH_REDIS_REST_URL,token:process.env.DOMAIN_GUARD_QUOTA_TOKEN});
            phase = "admission";
            const result = await runPilot(domain,{
                authorize:async candidate=>publicMode || (allowed === PILOT_DOMAIN && candidate === PILOT_DOMAIN),
                reserve:async()=>{
                    phase = "quota-reservation";
                    return reserve();
                },
                lookupApproved:async candidate=>{
                    phase = "dns-resolution";
                    return lookup(candidate);
                },
                workerFiles,
                createSandbox:async options=>{
                    phase = "sandbox-create";
                    const instance = await sandbox(options);
                    return {
                        writeFiles:async(...args)=>{
                            phase = "sandbox-write";
                            return instance.writeFiles(...args);
                        },
                        runCommand:async(...args)=>{
                            phase = "worker-command";
                            return instance.runCommand(...args);
                        },
                        stop:async(...args)=>{
                            phase = "sandbox-cleanup";
                            return instance.stop(...args);
                        }
                    };
                }
            });
            return res.status(200).json(result);
        } catch(error) {
            const status=error instanceof GatewayError?error.status:503;
            // Log only fixed stage labels and sanitized error types; never credentials or request data.
            const errorName = error instanceof Error && /^[a-zA-Z]{1,40}$/.test(error.name) ? error.name : "Unknown";
            const errorCode = typeof error?.code === "string" && /^[A-Z0-9_]{1,40}$/.test(error.code) ? error.code : "none";
            console.error("DOMAIN_GUARD_PILOT_FAILURE", JSON.stringify({status,phase,errorName,errorCode}));
            return res.status(status).json({error:"Pilot scan unavailable or declined"});
        }
    };
}

export default createHandler();
