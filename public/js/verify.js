/** CONFIG **/
const GROUPS = [4,4];                   // 8 chars as 4-4 (or use [5,5] for 10)
const REDEEM_URL = "/device/redeem";    // POST { bc } -> { dpop_nonce, exp }
const FINALIZE_URL = "/link/finalize";  // POST (DPoP) -> 200 session issued
const EXPECTED_QR_PREFIX = "/verify/device?bc="; // phone encodes this

/** DOM refs **/
const $ = s => document.querySelector(s);
const codeBoxesEl = $('#codeBoxes');
const codeStatus = $('#codeStatus');
const camCard = $('#camCard');
const codeCard = $('#codeCard');
const camStatus = $('#camStatus');
const useCamBtn = $('#useCamBtn'), stopCamBtn = $('#stopCamBtn');
const videoEl = $('#video');
const canvasEl = $('#qrCanvas'); const ctx = canvasEl.getContext('2d');
const toggleInputBtn = $('#toggleInputBtn');
const singleInputContainer = $('#singleInputContainer');
const singleInput = $('#singleInput');

/** Build code inputs **/
(function buildInputs(){
  GROUPS.forEach((len, gi)=>{
    for(let i=0;i<len;i++){
      const inp=document.createElement('input');
      inp.inputMode='latin'; inp.maxLength=1; inp.autocomplete='one-time-code';
      
      // Handle individual character input
      inp.addEventListener('input',(e)=>{ 
        e.target.value = normalizeCode(e.target.value).slice(0,1); 
        if(e.target.value) {
          // Find next input element, skipping spacer divs
          let nextEl = e.target.nextElementSibling;
          while(nextEl && nextEl.tagName !== 'INPUT') {
            nextEl = nextEl.nextElementSibling;
          }
          if(nextEl) nextEl.focus();
        }
      });
      
      // Handle paste of full code
      inp.addEventListener('paste',(e)=>{
        e.preventDefault();
        const pastedText = normalizeCode(e.clipboardData.getData('text'));
        if(pastedText.length >= 8) {
          // Fill all inputs with pasted code
          const inputs = codeBoxesEl.querySelectorAll('input');
          for(let j = 0; j < Math.min(pastedText.length, inputs.length); j++) {
            inputs[j].value = pastedText[j];
          }
          // Focus the last input
          inputs[inputs.length - 1].focus();
        }
      });
      
      inp.addEventListener('keydown',(e)=>{ 
        if(e.key==='Backspace'&&!e.target.value) {
          // Find previous input element, skipping spacer divs
          let prevEl = e.target.previousElementSibling;
          while(prevEl && prevEl.tagName !== 'INPUT') {
            prevEl = prevEl.previousElementSibling;
          }
          if(prevEl) prevEl.focus();
        }
      });
      codeBoxesEl.appendChild(inp);
    }
    if(gi < GROUPS.length-1){ const spacer=document.createElement('div'); spacer.style.width='0.75rem'; codeBoxesEl.appendChild(spacer); }
  });
  codeBoxesEl.querySelector('input')?.focus();
})();

function normalizeCode(raw){
  return raw.toUpperCase().replace(/[^A-Z2-9]/g,'').replace(/[ILOU]/g,(c)=>({I:'1',L:'1',O:'0',U:'V'}[c]||c));
}
function joinGroups(inputs){ return [...inputs].map(i=>i.value).join(''); }

/** Toggle between individual boxes and single input **/
let useSingleInput = false;
toggleInputBtn.addEventListener('click', () => {
  useSingleInput = !useSingleInput;
  if (useSingleInput) {
    codeBoxesEl.classList.add('hidden');
    singleInputContainer.classList.remove('hidden');
    toggleInputBtn.textContent = 'Individual boxes';
    singleInput.focus();
  } else {
    codeBoxesEl.classList.remove('hidden');
    singleInputContainer.classList.add('hidden');
    toggleInputBtn.textContent = 'Single field';
    codeBoxesEl.querySelector('input')?.focus();
  }
});

/** Handle single input **/
singleInput.addEventListener('input', (e) => {
  e.target.value = normalizeCode(e.target.value);
});

/** Get current code from either input method **/
function getCurrentCode() {
  if (useSingleInput) {
    const code = normalizeCode(singleInput.value);
    console.log('Single input code:', code); // Debug log
    return code;
  } else {
    const code = joinGroups(codeBoxesEl.querySelectorAll('input'));
    console.log('Individual boxes code:', code); // Debug log
    return code;
  }
}

/** DPoP key - generate new key for verify page **/
let dpopKeyPair;
async function ensureDpopKey(){
  if(dpopKeyPair) return dpopKeyPair;
  
  // Generate new DPoP key for verify page
  // The server will allow this key to be bound to the session
  dpopKeyPair = await crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, false, ["sign","verify"]);
  console.log('Generated new DPoP key for verify page');
  return dpopKeyPair;
}

async function exportJwk(pub){ return crypto.subtle.exportKey("jwk", pub); }
function b64u(buf){ const b = typeof buf==='string'? new TextEncoder().encode(buf): new Uint8Array(buf); return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function signES256(priv, bytes){ const sig = await crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, priv, bytes); return b64u(sig); }
async function makeDpopProof(url, method, nonce){
  const now = Math.floor(Date.now()/1000);
  const {privateKey, publicKey} = await ensureDpopKey();
  const jwk = await exportJwk(publicKey);
  const hdr = b64u(JSON.stringify({alg:"ES256", typ:"dpop+jwt", jwk}));
  const pld = b64u(JSON.stringify({htu:url, htm:method, iat:now, jti:crypto.randomUUID(), nonce}));
  const toSign = new TextEncoder().encode(`${hdr}.${pld}`);
  const sig = await signES256(privateKey, toSign);
  return `${hdr}.${pld}.${sig}`;
}

/** Debug: Add click handler to button **/
document.querySelector('button[type="submit"]')?.addEventListener('click', (e) => {
  console.log('Verify button clicked!'); // Debug log
});

/** Submit code path **/
$('#codeForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  console.log('Form submitted!'); // Debug log
  const bc = getCurrentCode();
  console.log('Current code:', bc, 'Length:', bc.length, 'Expected:', GROUPS.reduce((a,b)=>a+b,0)); // Debug log
  if (bc.length !== GROUPS.reduce((a,b)=>a+b,0)) {
    codeStatus.textContent = "Please enter the full code."; codeStatus.className = "status err"; return;
  }
  try{
    codeStatus.textContent = "Verifying code…"; codeStatus.className = "status";
    const redeem = await fetch(REDEEM_URL, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({ bc }) });
    if(!redeem.ok){ throw new Error(await redeem.text() || "Code rejected"); }
    const { dpop_nonce, link_id } = await redeem.json();

    const finalizeUrl = new URL(FINALIZE_URL, location.origin).toString();
    const proof = await makeDpopProof(finalizeUrl, "POST", dpop_nonce);
    const fin = await fetch(FINALIZE_URL, { method:"POST", headers:{ "Authorization":"DPoP placeholder", "DPoP": proof }});
    if(!fin.ok){ throw new Error(await fin.text() || "Finalize failed"); }

    codeStatus.textContent = "Success. Securing your session…"; codeStatus.className = "status ok";
    setTimeout(()=>location.assign(`/app?lid=${link_id}`), 300);
  }catch(err){
    codeStatus.textContent = `Error: ${String(err.message||err)}`; codeStatus.className = "status err";
  }
});

/** Camera scan using jsQR **/
let stream, stopLoop;
async function startCam(){
  try{
    stream = await navigator.mediaDevices.getUserMedia({ 
      video: { 
        facingMode:'environment', 
        width:{ideal:1280}, 
        height:{ideal:720} 
      } 
    });
  }catch(e){
    camStatus.textContent = "Camera permission denied or unavailable."; camStatus.className = "verify-status status err"; return;
  }
  videoEl.srcObject = stream; 
  await videoEl.play();
  camStatus.textContent = "Scanning…"; camStatus.className = "verify-status status";

  const loop = async () => {
    if (stopLoop) return;
    // Downscale for speed; keep aspect
    const vw = videoEl.videoWidth || 640, vh = videoEl.videoHeight || 480;
    const scale = Math.min(640 / vw, 480 / vh, 1);
    const w = Math.max(320, Math.floor(vw * scale));
    const h = Math.max(240, Math.floor(vh * scale));
    canvasEl.width = w; canvasEl.height = h;
    
    // Flip the image horizontally for easier phone positioning
    ctx.save();
    ctx.scale(-1, 1);
    ctx.drawImage(videoEl, -w, 0, w, h);
    ctx.restore();
    
    const img = ctx.getImageData(0, 0, w, h);

    const result = jsQR(img.data, w, h, { 
      // Try multiple inversion attempts for better detection
      inversionAttempts: "attemptBoth"
    });
    
    if (result && result.data) {
      const text = (result.data + '').trim();
      console.log('QR detected:', text); // Debug log
      
      // Check for the expected prefix (more flexible matching)
      if (text.includes('/verify/device?bc=') || text.startsWith(EXPECTED_QR_PREFIX)) {
        let bcRaw;
        if (text.includes('/verify/device?bc=')) {
          bcRaw = text.split('/verify/device?bc=')[1];
        } else {
          bcRaw = text.slice(EXPECTED_QR_PREFIX.length);
        }
        
        console.log('BC code extracted:', bcRaw); // Debug log
        autofillAndSubmit(bcRaw);
        stopCam(); 
        return;
      } else {
        console.log('QR code not matching expected format:', text); // Debug log
        // ignore foreign QR codes; keep scanning
      }
    }
    
    if ('requestVideoFrameCallback' in HTMLVideoElement.prototype){
      videoEl.requestVideoFrameCallback(loop);
    } else {
      requestAnimationFrame(loop);
    }
  };
  
  stopLoop = false;
  if ('requestVideoFrameCallback' in HTMLVideoElement.prototype){
    videoEl.requestVideoFrameCallback(loop);
  } else {
    requestAnimationFrame(loop);
  }
}
function autofillAndSubmit(code){
  const norm = normalizeCode(code);
  const inputs = codeBoxesEl.querySelectorAll('input');
  let i=0; for (const ch of norm) { if (i<inputs.length) { inputs[i++].value = ch; } }
  $('#codeForm').requestSubmit();
}
function stopCam(){
  stopLoop = true;
  if (stream) { stream.getTracks().forEach(t=>t.stop()); stream = null; }
}

useCamBtn.addEventListener('click', async ()=>{
  codeCard.classList.add('hidden'); camCard.classList.remove('hidden');
  await startCam();
});
stopCamBtn.addEventListener('click', ()=>{
  stopCam(); camCard.classList.add('hidden'); codeCard.classList.remove('hidden');
});
