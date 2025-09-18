import {
    FilesetResolver,
    FaceLandmarker,
    DrawingUtils
  } from "/vendor/tasks-vision/vision_bundle.mjs";
  
  const CONFIG = {
    wasmRoot: "/vendor/tasks-vision/wasm",         // local WASM path
    modelUrl: "/models/face_landmarker.task",      // local model
    minFaceScore: 0.6,
    yawLeftThresh: 0.5,    // Increased: requires more right turn to register left
    yawRightThresh: -0.5,  // Increased: requires more left turn to register right
    maxDurationMs: 12000,
    mimeType: "video/webm;codecs=vp9,opus"
  };
  
  const el = (id)=>document.getElementById(id);
  const video = el("video");
  const canvas = el("canvas");
  const banner = el("banner"); // May be null if banner was removed
  const statusEl = el("status");
  const promptEl = el("prompt");
  const chipFace = el("chipFace");
  const chipCenter = el("chipCenter");
  const chipLeft = el("chipLeft");
  const chipRight = el("chipRight");
  const resultBox = el("resultBox");
  const pillDuration = el("pillDuration");
  const pillSize = el("pillSize");
  const btnStartEl = el("btnStart");
  // Removed button references since we're auto-registering
  
  // Check if elements exist, if not, create fallback functions
  const safeSetStatus = (text) => {
    if (statusEl) statusEl.textContent = text;
    else console.log('Status:', text);
  };
  
  const safeSetPrompt = (text, cls) => {
    if (promptEl) {
      promptEl.textContent = text;
      promptEl.className = "face-prompt " + (cls || "");
    } else {
      console.log('Prompt:', text);
    }
  };
  
  const safeSetBanner = (text) => {
    if (banner) banner.textContent = text;
  };
  
  const safeMark = (chip, ok = false, fail = false) => {
    if (chip) {
      chip.classList.remove("done", "fail");
      if (ok) chip.classList.add("done");
      if (fail) chip.classList.add("fail");
    }
  };
  
  let mediaStream = null;
  let recorder = null;
  let chunks = [];
  let recordingStartedAt = 0;
  let rafId = null;
  let faceLM = null;
  let running = false;
  let faced = false, centered = false, leftOK = false, rightOK = false, recording = false;
  let recordingTimedOut = false;
  
  const setStatus = safeSetStatus;
  const setBanner = safeSetBanner;
  const setPrompt = safeSetPrompt;
  const mark = safeMark;
  
  function resetState() {
    faced = centered = leftOK = rightOK = recording = false;
    recordingTimedOut = false;
    mark(chipFace); mark(chipCenter); mark(chipLeft); mark(chipRight);
    updateOverlayCentered(false);
    if (resultBox) resultBox.classList.remove("show");
    setPrompt("Ready."); setBanner("Press \"Start onboarding\"");
  }

  function resetFaceCapture() {
    // Stop any running processes
    stopLoop();
    stopRecording();
    
    // Clear media stream
    if (mediaStream) {
      mediaStream.getTracks().forEach(track => track.stop());
      mediaStream = null;
    }
    
    // Clear video source
    if (video) {
      video.srcObject = null;
    }
    
    // Clear canvas
    if (canvas) {
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
      }
    }
    
    // Reset all state
    resetState();
    
    // Reset status
    setStatus("Initializing camera...");
  }
  
  function yawRatio(landmarks) {
    const nose = landmarks[1], L = landmarks[234], R = landmarks[454];
    if (!nose || !L || !R) return 0;
    const dL = Math.hypot(nose.x - L.x, nose.y - L.y);
    const dR = Math.hypot(nose.x - R.x, nose.y - R.y);
    // Since video is mirrored, swap L and R to match user's perspective
    return Math.log((dL + 1e-6) / (dR + 1e-6));
  }

  function getFaceCenter(lm) {
    // Use nose tip as face center
    const nose = lm[1];
    console.log('Nose landmark:', nose);
    return { x: nose.x, y: nose.y };
  }

  function getFaceSize(lm) {
    // Calculate face width using eye distance
    const leftEye = lm[234]; // Left eye outer corner
    const rightEye = lm[454]; // Right eye outer corner
    const eyeDistance = Math.abs(rightEye.x - leftEye.x);
    
    // Calculate face height using face contour points (more reliable than specific chin point)
    const topFace = lm[10]; // Top of face
    const bottomFace = lm[152]; // Bottom of face (try this first)
    const faceHeight = Math.abs(bottomFace.y - topFace.y);
    
    // Also try calculating face bounding box from all landmarks
    const xCoords = lm.map(p => p.x);
    const yCoords = lm.map(p => p.y);
    const faceWidth = Math.max(...xCoords) - Math.min(...xCoords);
    const faceHeight2 = Math.max(...yCoords) - Math.min(...yCoords);
    
    console.log('Eye landmarks:', { leftEye, rightEye, eyeDistance });
    console.log('Face height landmarks:', { topFace, bottomFace, faceHeight });
    console.log('Face bounding box:', { faceWidth, faceHeight2 });
    
    // Use the larger of the two measurements for more reliable detection
    return { 
      width: Math.max(eyeDistance, faceWidth), 
      height: Math.max(faceHeight, faceHeight2) 
    };
  }

  function isFaceCentered(faceCenter) {
    const centerX = 0.5; // Center of frame
    const centerY = 0.5; // Center of frame
    const tolerance = 0.15; // Allow 15% deviation from center (more precise)
    
    const xDiff = Math.abs(faceCenter.x - centerX);
    const yDiff = Math.abs(faceCenter.y - centerY);
    
    console.log(`Centering check: x=${faceCenter.x.toFixed(2)} (diff: ${xDiff.toFixed(2)}), y=${faceCenter.y.toFixed(2)} (diff: ${yDiff.toFixed(2)}), tolerance: ${tolerance}`);
    
    return xDiff < tolerance && yDiff < tolerance;
  }

  function isFaceGoodSize(faceSize) {
    // Good face size: face width should be between 0.45 and 0.75 of frame width
    // This ensures the face is very close for maximum detection quality and signal-to-noise ratio
    const minFaceWidth = 0.50;  // Increased from 0.35 to require much closer face
    const maxFaceWidth = 0.80;  // Increased from 0.65 to allow closer maximum
    
    console.log(`Size check: faceWidth=${faceSize.width.toFixed(3)}, min=${minFaceWidth}, max=${maxFaceWidth}`);
    
    return faceSize.width >= minFaceWidth && faceSize.width <= maxFaceWidth;
  }

  function updateOverlayCentered(isCentered) {
    const overlay = document.querySelector('.face-overlay');
    if (overlay) {
      if (isCentered) {
        overlay.classList.add('centered');
      } else {
        overlay.classList.remove('centered');
      }
    }
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
    
    // Wait for video metadata to load with timeout
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve(); // Continue with fallback
      }, 5000); // 5 second timeout
      
      video.addEventListener('loadedmetadata', () => {
        clearTimeout(timeout);
        resolve();
      }, { once: true });
      
      // Also try to resolve if video dimensions are already available
      if (video.videoWidth > 0 && video.videoHeight > 0) {
        clearTimeout(timeout);
        resolve();
      }
    });
    
    // Size canvas to match the video's actual dimensions for proper face detection
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
    
    if (recordingTimedOut) {
      // Recording timed out - show failure state
      setStatus("Capture failed - Time limit exceeded");
      setPrompt("Time limit exceeded. Please try again.", "danger-txt");
      setBanner("Time limit exceeded - Please redo");
    } else {
      // Recording completed successfully - check if all checks passed
      if (centered && leftOK && rightOK) {
        setStatus("All checks passed - Registering face...");
        setPrompt("Processing face registration...", "ok");
        setBanner("Registering face...");
        // Automatically register the face
        setTimeout(() => {
          sendForVerification();
        }, 500);
      } else {
        setStatus("Checks incomplete");
        if (!centered) {
          setPrompt("Please center your face in the frame.", "danger-txt");
          setBanner("Center your face");
        } else if (!leftOK || !rightOK) {
          setPrompt("Please complete left and right turns.", "danger-txt");
          setBanner("Complete liveliness checks");
        }
      }
    }
    
    resultBox.dataset.blobUrl = URL.createObjectURL(blob);
    resultBox._blob = blob;
  }
  
  async function sendForVerification() {
    const blob = resultBox._blob;
    if (!blob) return;
    
    // Determine endpoint based on URL, context, or inline mode
    const isVerifyMode = window.location.pathname.includes('/face-verify') || 
                        new URLSearchParams(window.location.search).get('mode') === 'verify' ||
                        (window.faceCapture && window.faceCapture.mode === 'verify');
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
          // Check if this is a PAD attack detection
          if (data.pad_results && !data.pad_results.live_final) {
            setPrompt(data.message || "Presentation attack detected", "danger-txt");
            setBanner("Security check failed - potential spoof detected");
          } else if (data.similarity !== undefined) {
            setPrompt(`Face verification failed (Similarity: ${(data.similarity * 100).toFixed(1)}%)`, "danger-txt");
          } else {
            setPrompt(data.message || "Face verification failed", "danger-txt");
          }
        }
      } else {
        setStatus("Face registered ✓"); 
        setBanner("Face registered successfully ✓"); 
        setPrompt(`Face registered with ${data.embeddings_count} embedding(s).`, "ok");
      }
    } catch (e) {
      setStatus(`${actionText} failed`); 
      setPrompt(`${actionText} failed: ${e.message}`, "danger-txt");
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
  
      ctx.clearRect(0,0,canvas.width,canvas.height);
      
      // FaceLandmarker returns faceLandmarks directly - no separate faceDetections array
      if (res.faceLandmarks && res.faceLandmarks.length > 0) {
        const originalLm = res.faceLandmarks[0];
        
        // Transform landmarks to adjust mesh position (keep normalized coordinates for DrawingUtils)
        const lm = originalLm.map(landmark => ({
          x: landmark.x - 0.08, // Move mesh left
          y: landmark.y - 0.07, // Move mesh up
          z: landmark.z
        }));
                
        // Mesh overlay disabled for now
        // drawer.drawConnectors(lm, FaceLandmarker.FACE_LANDMARKS_TESSELATION, { color:"#3b4b82", lineWidth:0.5 });
        // drawer.drawLandmarks(lm, { color:"#78f7d7", lineWidth:0.5, radius:0.5 });
  
        if (!faced) {
          faced = true; mark(chipFace, true);
          setPrompt("Face detected. Center your face.", "ok");
          setBanner("Center your face in the frame");
        }

        // Check if face is centered and at good distance
        if (faced && !centered) {
          const faceCenter = getFaceCenter(originalLm);
          const faceSize = getFaceSize(originalLm);
          
          // Debug logging
          console.log('Face center:', faceCenter, 'Face size:', faceSize);
          console.log('Is centered:', isFaceCentered(faceCenter), 'Is good size:', isFaceGoodSize(faceSize));
          
          // For now, let's be more lenient with centering to test
          const isCentered = isFaceCentered(faceCenter);
          const isGoodSize = isFaceGoodSize(faceSize);
          
          if (isCentered && isGoodSize) {
            centered = true; mark(chipCenter, true);
            setPrompt("Face centered. Recording will start.", "ok");
            setBanner("Face centered — starting…");
            updateOverlayCentered(true);
            startRecording();
          } else {
            updateOverlayCentered(false);
            if (!isCentered) {
              setBanner(`Move face to center (x:${faceCenter.x.toFixed(2)}, y:${faceCenter.y.toFixed(2)}, target: 0.5±0.15)`);
            } else if (!isGoodSize) {
              setBanner(`Move closer (size:${faceSize.width.toFixed(3)}, target: 0.55-0.85)`);
            }
          }
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
            recordingTimedOut = true;
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

  // Function to start face capture (reusable)
  async function startFaceCapture() {
    resetState(); setStatus("Initializing…");
    try {
      await initFaceLandmarker();
      await startCamera();
      setStatus("Preview running"); setBanner("Looking for your face…");
      loop();
    } catch (e) {
      setStatus("Camera/model init failed"); setPrompt("Camera or model failed to load.", "danger-txt");
      throw e;
    }
  }

  // Wire up buttons (only if btnStart exists - for backward compatibility)
  if (btnStartEl) {
    btnStartEl.addEventListener("click", async () => {
      btnStartEl.disabled = true;
      try {
        await startFaceCapture();
      } catch (e) {
        btnStartEl.disabled = false;
      }
    });
  }
  
  function redo() {
    stopRecording(); chunks = [];
    resultBox.classList.remove("show");
    
    faced = centered = leftOK = rightOK = recording = false;
    updateOverlayCentered(false);
        
    mark(chipFace, false, true); mark(chipCenter, false, true); mark(chipLeft, false, true); mark(chipRight, false, true);
    
    setPrompt("Ready. Face the camera to start.", ""); setBanner("Looking for your face…");
  }
  // Button event listeners removed - using automatic registration
  
  window.addEventListener("beforeunload", () => {
    stopLoop();
    if (mediaStream) mediaStream.getTracks().forEach(t => t.stop());
  });

  // Export class for inline usage
  export class FaceCaptureInline {
    constructor(mode = 'register') {
      this.mode = mode;
      this.initialized = false;
    }

    async init() {
      if (this.initialized) return;
      
      // Update button text based on mode
      this.updatePageContext();
      
      this.initialized = true;
    }

    async startCapture() {
      // Auto-start the face capture process
      await startFaceCapture();
    }

    resetFaceCapture() {
      resetFaceCapture();
    }

    setMode(mode) {
      this.mode = mode;
      if (this.initialized) {
        this.updatePageContext();
      }
    }

    updatePageContext() {
      const resultBox = document.getElementById('resultBox');
      
      if (this.mode === 'verify') {
        if (resultBox) {
          const resultText = resultBox.querySelector('div');
          if (resultText) resultText.innerHTML = '<strong>Processing face verification...</strong>';
        }
      } else {
        if (resultBox) {
          const resultText = resultBox.querySelector('div');
          if (resultText) resultText.innerHTML = '<strong>Processing face registration...</strong>';
        }
      }
    }
  }