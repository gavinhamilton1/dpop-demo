/**
 * Shared QR Code Generation Utility
 * Provides QR code generation functionality for both AppController and JourneysController
 */

/**
 * Generate QR code with AprilTag overlay
 * @param {string} containerId - ID of the container element to render QR code in
 * @param {string} qrData - Data to encode in the QR code
 * @param {string} linkId - Link ID for display purposes
 * @param {Function} statusCallback - Optional callback to update status text
 */
export function generateQRCode(containerId, qrData, linkId, statusCallback = null) {
    console.log('generateQRCode called with:', { containerId, qrData, linkId });
    const qrCodeDiv = document.getElementById(containerId);
    if (!qrCodeDiv) {
        console.error(`QR code container with ID '${containerId}' not found`);
        return;
    }
    
    console.log('QR code container found:', qrCodeDiv);
    
    // Clear any existing QR code
    qrCodeDiv.innerHTML = '';
    
    // Generate QR code using the QRCode library
    console.log('window.QRCode available:', !!window.QRCode);
    if (window.QRCode) {
        // Generate QR code with specific options to match the original implementation
        new QRCode(qrCodeDiv, {
            text: qrData,
            width: 200,
            height: 200,
            colorDark: '#000000',
            colorLight: '#FFFFFF',
            correctLevel: QRCode.CorrectLevel.M
        });
        
        // Update status if callback provided
        if (statusCallback) {
            statusCallback('Waiting for mobile scan...');
        }
        
        // Add AprilTag overlay after QR code is generated
        setTimeout(async () => {
            console.log('Attempting to add AprilTag overlay...');
            console.log('window.QRGenerator available:', !!window.QRGenerator);
            if (window.QRGenerator) {
                console.log('Creating QRGenerator instance...');
                const qrGenerator = new QRGenerator();
                console.log('Calling generateQRWithAprilTag...');
                const result = await qrGenerator.generateQRWithAprilTag(containerId, qrData);
                console.log('AprilTag overlay result:', result);
            } else {
                console.error('QRGenerator not available on window object');
            }
        }, 100); // Small delay to ensure QR code is rendered
    } else {
        console.error('QR code library not loaded');
        if (statusCallback) {
            statusCallback('QR code library not loaded');
        }
    }
}


/**
 * Create complete QR code container with styling (for AppController)
 * @param {string} qrData - Data to encode in the QR code
 * @param {string} linkId - Link ID for display purposes
 * @returns {HTMLElement} The created container element
 */
export function createQRContainer(qrData, linkId) {
    const container = document.createElement('div');
    container.className = 'qr-container';
    container.innerHTML = `
      <h3>Scan QR Code with Mobile Device</h3>
      <div class="qr-code" id="qrcode"></div>
      <p>Link ID: ${linkId}</p>
      <p><strong>URL:</strong> <code>${qrData}</code></p>
      <div class="qr-status" id="qrStatus">Waiting for scan...</div>
    `;

    // Generate QR code in the container
    generateQRCode('qrcode', qrData, linkId, (status) => {
        const statusEl = container.querySelector('#qrStatus');
        if (statusEl) {
            statusEl.textContent = status;
        }
    });

    return container;
}
