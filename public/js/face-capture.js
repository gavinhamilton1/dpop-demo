import {
    FilesetResolver,
    FaceLandmarker,
    DrawingUtils
  } from "/vendor/tasks-vision/vision_bundle.mjs";
  
  const CONFIG = {
    wasmRoot: "/vendor/tasks-vision/wasm",         // local WASM path
    modelUrl: "/models/face_landmarker.task",      // local model
    minFaceScore: 0.6,
    yawLeftThresh: 0.22,
    yawRightThresh: -0.22,
    maxDurationMs: 12000,
    mimeType: "video/webm;codecs=vp9,opus"
  };
  
  const el = (id)=>document.getElementById(id);
  const video = el("video");
  const canvas = el("canvas");
  const banner = el("banner");
  const statusEl = el("status");
  const promptEl = el("prompt");
  const chipFace = el("chipFace");
  const chipLeft = el("chipLeft");
  const chipRight = el("chipRight");
  const chipRec = el("chipRecording");
  const resultBox = el("resultBox");
  const pillDuration = el("pillDuration");
  const pillSize = el("pillSize");
  const btnStart = el("btnStart");
  const btnRedo = el("btnRedo");
  const btnSend = el("btnSend");
  const btnRedo2 = el("btnRedo2");
  const btnSend2 = el("btnSend2");
  
  let mediaStream = null;
  let recorder = null;
  let chunks = [];
  let recordingStartedAt = 0;
  let rafId = null;
  let faceLM = null;
  let running = false;
  let faced = false, leftOK = false, rightOK = false, recording = false;
  
  const setStatus = (t)=> statusEl.textContent = t;
  const setBanner = (t)=> banner.textContent = t;
  const setPrompt = (t, cls) => { promptEl.textContent = t; promptEl.className = "prompt " + (cls||""); };
  const mark = (chip, ok=false, fail=false) => {
    chip.classList.remove("done","fail");
    if (ok) chip.classList.add("done");
    if (fail) chip.classList.add("fail");
  };
  
  function resetState() {
    faced = leftOK = rightOK = recording = false;
    mark(chipFace); mark(chipLeft); mark(chipRight); mark(chipRec);
    resultBox.classList.remove("show");
    btnSend.disabled = true; btnRedo.disabled = true; btnSend2.disabled = true;
    setPrompt("Ready."); setBanner("Press \"Start onboarding\"");
  }
  
  function yawRatio(landmarks) {
    const nose = landmarks[1], L = landmarks[234], R = landmarks[454];
    if (!nose || !L || !R) return 0;
    const dL = Math.hypot(nose.x - L.x, nose.y - L.y);
    const dR = Math.hypot(nose.x - R.x, nose.y - R.y);
    // Since video is mirrored, swap L and R to match user's perspective
    return Math.log((dL + 1e-6) / (dR + 1e-6));
  }
  

  async function initFaceLandmarker() {
    if (faceLM) return;
    const fileset = await FilesetResolver.forVisionTasks(CONFIG.wasmRoot);
    faceLM = await FaceLandmarker.createFromOptions(fileset, {
      baseOptions: { modelAssetPath: CONFIG.modelUrl },
      runningMode: "VIDEO",
      numFaces: 1,
      outputFaceBlendshapes: false,
      outputFacialTransformationMatrixes: false,
    });
  }
  
  async function startCamera() {
    mediaStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "user", width: {ideal: 720}, height: {ideal: 960} },
      audio: true
    });
    video.srcObject = mediaStream;
    await video.play();
    canvas.width = video.videoWidth || 720;
    canvas.height = video.videoHeight || 960;
  }
  
  function startRecording() {
    if (recording) return;
    chunks = [];
    try {
      recorder = new MediaRecorder(mediaStream, { mimeType: CONFIG.mimeType });
    } catch {
      recorder = new MediaRecorder(mediaStream);
    }
    recorder.ondataavailable = (e)=> { if (e.data && e.data.size) chunks.push(e.data); };
    recorder.onstop = onRecorded;
    recorder.start();
    recording = true; recordingStartedAt = performance.now();
    setStatus("Recording…"); setBanner("Recording… follow the instructions");
    setPrompt("Turn your head LEFT", "warn");
    mark(chipRec, true);
  }
  
  function stopRecording() {
    if (!recording) return;
    recording = false;
    try { recorder.stop(); } catch {}
  }
  
  function onRecorded() {
    const blob = new Blob(chunks, { type: recorder?.mimeType || "video/webm" });
    const durSec = ((performance.now() - recordingStartedAt) / 1000).toFixed(1);
    pillDuration.textContent = `${durSec}s`;
    pillSize.textContent = `${(blob.size/1024).toFixed(0)} KB`;
    resultBox.classList.add("show");
    btnSend.disabled = false; btnRedo.disabled = false; btnSend2.disabled = false;
    resultBox.dataset.blobUrl = URL.createObjectURL(blob);
    resultBox._blob = blob;
    setPrompt("Capture complete.", "ok");
    setBanner("Capture complete");
  }
  
  async function sendForVerification() {
    const blob = resultBox._blob;
    if (!blob) return;
    btnSend.disabled = btnSend2.disabled = true;
    
    // Determine endpoint based on URL or context
    const isVerifyMode = window.location.pathname.includes('/face-verify') || 
                        new URLSearchParams(window.location.search).get('mode') === 'verify';
    const endpoint = isVerifyMode ? '/face/verify' : '/face/register';
    const actionText = isVerifyMode ? 'verification' : 'registration';
    
    setStatus(`Uploading for ${actionText}…`);
    try {
      const fd = new FormData();
      fd.append("video", blob, "face-capture.webm");
      const res = await fetch(endpoint, { method: "POST", body: fd, credentials: "include" });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      
      if (isVerifyMode) {
        if (data.verified) {
          setStatus("Face verified ✓"); 
          setBanner("Face verification successful ✓"); 
          setPrompt(`Face verification successful! (Similarity: ${(data.similarity * 100).toFixed(1)}%)`, "ok");
        } else {
          setStatus("Verification failed"); 
          setPrompt(`Face verification failed (Similarity: ${(data.similarity * 100).toFixed(1)}%)`, "danger-txt");
          btnSend.disabled = btnSend2.disabled = false;
        }
      } else {
        setStatus("Face registered ✓"); 
        setBanner("Face registered successfully ✓"); 
        setPrompt(`Face registered with ${data.embeddings_count} embedding(s).`, "ok");
      }
    } catch (e) {
      setStatus(`${actionText} failed`); 
      setPrompt(`${actionText} failed: ${e.message}`, "danger-txt");
      btnSend.disabled = btnSend2.disabled = false;
    }
  }
  
  function stopLoop() { if (rafId) cancelAnimationFrame(rafId); rafId = null; running = false; }
  
  async function loop() {
    running = true;
    const ctx = canvas.getContext("2d");
    const drawer = new DrawingUtils(ctx);
  
    const step = async () => {
      if (!running) return;
      const now = performance.now();
      const res = faceLM.detectForVideo(video, now);
      
    //   // Debug: log detection result structure
    //   if (res && Object.keys(res).length > 0) {
    //     console.log('Detection result keys:', Object.keys(res));
    //     if (res.faceLandmarks) console.log('Face landmarks:', res.faceLandmarks.length);
    //     if (res.faceBlendshapes) console.log('Face blendshapes:', res.faceBlendshapes.length);
    //   }
  
      ctx.clearRect(0,0,canvas.width,canvas.height);
      
      // FaceLandmarker returns faceLandmarks directly - no separate faceDetections array
      if (res.faceLandmarks && res.faceLandmarks.length > 0) {
        const originalLm = res.faceLandmarks[0];
        
        // Transform landmarks to adjust mesh position
        const lm = originalLm.map(landmark => ({
          x: landmark.x - 0.08, // Move mesh left (subtract from x)
          y: landmark.y - 0.07, // Move mesh up (subtract from y)
          z: landmark.z
        }));
                
        drawer.drawConnectors(lm, FaceLandmarker.FACE_LANDMARKS_TESSELATION, { color:"#3b4b82", lineWidth:0.5 });
        drawer.drawLandmarks(lm, { color:"#78f7d7", lineWidth:0.5, radius:0.5 });
  
        if (!faced) {
          faced = true; mark(chipFace, true);
          setPrompt("Face detected. Recording will start.", "ok");
          setBanner("Face detected — starting…");
          startRecording();
        }
  
        if (recording) {
          const r = yawRatio(lm); // Use transformed landmarks for turn detection
          if (!leftOK) {
            setBanner("Turn your head RIGHT");
            if (r > CONFIG.yawLeftThresh) {
              leftOK = true; mark(chipLeft, true);
              setPrompt("Good. Now turn LEFT", "ok");
            }
          } else if (!rightOK) {
            setBanner("Turn your head LEFT");
            if (r < CONFIG.yawRightThresh) {
              rightOK = true; mark(chipRight, true);
              stopRecording();
              setBanner("Done. Review & send.");
            }
          }
          if (performance.now() - recordingStartedAt > CONFIG.maxDurationMs) {
            stopRecording();
            setBanner("Time limit reached. Review & send or redo.");
          }
        }
      } else {
        if (recording) setBanner("Keep face in view…"); else setBanner("Align your face in the frame");
      }
      rafId = requestAnimationFrame(step);
    };
    rafId = requestAnimationFrame(step);
  }
  
  // Make page context-aware
  function updatePageContext() {
    const isVerifyMode = window.location.pathname.includes('/face-verify') || 
                        new URLSearchParams(window.location.search).get('mode') === 'verify';
    
    if (isVerifyMode) {
      const pageTitle = document.getElementById('pageTitle');
      const h1 = document.querySelector('h1');
      const banner = document.getElementById('banner');
      const btnStart = document.getElementById('btnStart');
      const btnSend = document.getElementById('btnSend');
      const btnSend2 = document.getElementById('btnSend2');
      const resultBox = document.querySelector('#resultBox div');
      
      if (pageTitle) pageTitle.textContent = 'Face Verification';
      if (h1) h1.textContent = '🔐 Face Verification';
      if (banner) banner.textContent = 'Press "Start Verification" to verify your face';
      if (btnStart) btnStart.textContent = 'Start Verification';
      if (btnSend) btnSend.textContent = 'Verify Face';
      if (btnSend2) btnSend2.textContent = 'Verify Face';
      if (resultBox) resultBox.innerHTML = '<strong>Capture complete.</strong> Review and verify?';
    }
  }

  // Initialize page context when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updatePageContext);
  } else {
    updatePageContext();
  }

  // Wire up buttons
  document.getElementById("btnStart").addEventListener("click", async () => {
    btnStart.disabled = true;
    resetState(); setStatus("Initialixzing…");
    try {
      await initFaceLandmarker();
      await startCamera();
      setStatus("Preview running"); setBanner("Looking for your face…");
      loop();
    } catch (e) {
      setStatus("Camera/model init failed"); setPrompt("Camera or model failed to load.", "danger-txt");
      btnStart.disabled = false;
    }
  });
  
  function redo() {
    stopRecording(); chunks = [];
    resultBox.classList.remove("show");
    btnSend.disabled = true; btnRedo.disabled = true; btnSend2.disabled = true;
    faced = leftOK = rightOK = recording = false;
        
    mark(chipFace, false, true); mark(chipLeft, false, true); mark(chipRight, false, true); mark(chipRec, false, true);
    
    setPrompt("Ready. Face the camera to start.", ""); setBanner("Looking for your face…");
  }
  btnRedo.addEventListener("click", redo);
  btnRedo2.addEventListener("click", redo);
  btnSend.addEventListener("click", sendForVerification);
  btnSend2.addEventListener("click", sendForVerification);
  
  window.addEventListener("beforeunload", () => {
    stopLoop();
    if (mediaStream) mediaStream.getTracks().forEach(t => t.stop());
  });