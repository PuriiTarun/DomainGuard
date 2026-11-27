import {createQuota, LIMITS} from "../domain_guard/hosted-sdk/quota.mjs";
import {verifyQuotaAcl} from "./verify-quota-acl.mjs";

if(process.env.DOMAIN_GUARD_LIVE_QUOTA_TEST !== "1") {
    process.stderr.write("Set DOMAIN_GUARD_LIVE_QUOTA_TEST=1 to consume one live quota reservation.\n");
    process.exitCode=2;
} else {
    try {
        await verifyQuotaAcl({url:process.env.UPSTASH_REDIS_REST_URL,
            token:process.env.DOMAIN_GUARD_QUOTA_TOKEN,standardToken:process.env.UPSTASH_REDIS_REST_TOKEN});
        const reserve=createQuota({url:process.env.UPSTASH_REDIS_REST_URL,token:process.env.DOMAIN_GUARD_QUOTA_TOKEN});
        const results=await Promise.all(Array.from({length:5},()=>reserve()));
        const accepted=results.filter(Boolean).length;
        if(accepted !== 1) throw new Error("Live quota concurrency result inconclusive or unsafe");
        const cooldown=await reserve();
        if(cooldown) throw new Error("Cooldown failed");
        process.stdout.write(JSON.stringify({concurrentRequests:5,accepted,cooldownDenied:true,limits:LIMITS})+"\n");
    } catch {
        process.stderr.write("Live quota verification failed; admission must remain disabled.\n");
        process.exitCode=1;
    }
}
