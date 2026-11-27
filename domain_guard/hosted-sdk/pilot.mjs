const button=document.getElementById("run");
const output=document.getElementById("result");
button.addEventListener("click",async()=>{
    button.disabled=true;
    output.textContent="Checking pilot availability...";
    try {
        const response=await fetch("/api/hosted-pilot",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:"domainguard-check.vercel.app"}),cache:"no-store",redirect:"error",signal:AbortSignal.timeout(45000)});
        const data=await response.json();
        output.textContent=JSON.stringify({status:response.status,result:data},null,2);
    } catch {output.textContent="The pilot could not be reached.";}
    finally {button.disabled=false;}
});
