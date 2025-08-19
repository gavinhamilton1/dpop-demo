// Simple QR scanner that redirects to the URL embedded in the code
(function () {
    const v = document.getElementById('v');
    const c = document.getElementById('c');
    const msg = document.getElementById('msg');
    const ctx = c.getContext('2d');
  
    function setMsg(text) { if (msg) msg.textContent = text; }
  
    function stopStream() {
      try {
        const s = v.srcObject;
        if (s && s.getTracks) s.getTracks().forEach(t => t.stop());
      } catch {}
    }
  
    async function start() {
      if (typeof jsQR !== 'function') {
        setMsg('QR library failed to load.');
        return;
      }
  
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } },
          audio: false
        });
        v.srcObject = stream;
        await v.play();
        setMsg('Scanning…');
        requestAnimationFrame(tick);
      } catch (e) {
        setMsg(
          (location.protocol !== 'https:' && location.hostname !== 'localhost')
            ? 'Camera requires HTTPS (or localhost).'
            : `Camera error: ${e && e.name ? e.name : 'Unknown'}`
        );
      }
    }
  
    function tick() {
      if (v.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
        c.width = v.videoWidth || 640;
        c.height = v.videoHeight || 480;
        ctx.drawImage(v, 0, 0, c.width, c.height);
        const img = ctx.getImageData(0, 0, c.width, c.height);
        // jsQR is provided by jsQR.js
        const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
        if (code && code.data) {
          stopStream();
          // Expect the QR to contain a full URL to link.html with token (& optional id)
          location.href = code.data;
          return;
        }
      }
      requestAnimationFrame(tick);
    }
  
    // Clean up if user navigates away
    window.addEventListener('beforeunload', stopStream);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') stopStream();
    });
  
    start();
  })();
  