import { mkdir, copyFile } from "node:fs/promises";
const assets=["Geist-LICENSE.txt","Geist-Variable.woff2","action-plan.mjs","advice.mjs","app.mjs","demo.mjs","index.html","input.mjs","privacy.html","public-dns.mjs","render.mjs","report.mjs","styles.css","terms.html"];
await mkdir("public",{recursive:true});
for(const file of assets) await copyFile(file,"public/"+file);
for(const file of ["pilot.html","pilot.mjs"]) await copyFile("hosted-backend/"+file,"public/"+file);
