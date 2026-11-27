export default async function handler(req,res) {
    res.setHeader("Cache-Control","no-store");
    if(process.env.VERCEL_ENV !== "preview" || req.method !== "GET") return res.status(404).json({error:"Not available"});
    // No Redis access, sandbox creation, environment values or credentials.
    try {
        const {Sandbox}=await import("@vercel/sandbox");
        const methods=["writeFiles","runCommand","stop"];
        const ready=typeof Sandbox.create==="function" && methods.every(name=>typeof Sandbox.prototype[name]==="function");
        return res.status(ready?200:503).json({sdkReady:ready});
    } catch(error) {
        const code=error?.code;
        return res.status(503).json({sdkReady:false,reason:code==="ERR_REQUIRE_ESM"?"module-compatibility":"import-failed"});
    }
}
