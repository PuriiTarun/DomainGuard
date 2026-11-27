import {readFile} from "node:fs/promises";

const mirrors=["domain_guard/hosted_probe.py","domain_guard/checks/headers.py","domain_guard/checks/redirects.py","domain_guard/validation.py"];
for(const path of mirrors) {
    const source=await readFile(path);
    const deployed=await readFile("domain_guard/static/"+path);
    if(!source.equals(deployed)) throw new Error(`Deployment mirror differs: ${path}`);
}
for(const path of ["scripts/build-hosted-preview.mjs","domain_guard/static/hosted-backend/build.mjs"]) {
    if(!(await readFile(path,"utf8")).includes('"hosted-report.mjs"')) throw new Error(`Hosted browser asset missing: ${path}`);
}
process.stdout.write("Hosted deployment mirrors and assets verified\n");
