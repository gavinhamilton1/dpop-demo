/**
 * Pure JavaScript AprilTag Overlay for QR Codes
 * Provides rotating AprilTag overlay functionality for existing QR codes
 */

if (typeof QRGenerator === 'undefined') {
class QRGenerator {
    constructor() {
        this.canvasSize = 200;
        this.apriltagAnimationInterval = 100; // ms
        this.currentApriltagIndex = 0;
        this.animationInterval = null;
        this.sessionData = null;
        this.apriltagFamily = null;
        this.apriltagNumbers = [];
        
        // Initialize AprilTag family (36h11 is a good default)
        this.initializeAprilTagFamily();
    }

    /**
     * Initialize AprilTag family
     */
    async initializeAprilTagFamily() {
        try {
            // Load the 36h11 family configuration from local file
            const response = await fetch('/public/apriltag-families/36h11.json');
            const tagConfig = await response.json();
            
            // Create AprilTag family instance
            this.apriltagFamily = new AprilTagFamily(tagConfig);
            console.log('AprilTag family initialized:', this.apriltagFamily.size, 'x', this.apriltagFamily.size);
            console.log('Available tag IDs:', this.apriltagFamily.codes.length);
        } catch (error) {
            console.error('Failed to initialize AprilTag family:', error);
            // Fallback to a simple pattern
            this.apriltagFamily = null;
        }
    }

    /**
     * Verify domain is allowed
     */
    verifyDomain() {
        const allowedDomains = ['localhost', 'dpop.fun', 'stronghold.onrender.com'];
        const currentDomain = window.location.hostname;
        return allowedDomains.includes(currentDomain);
    }

    /**
     * Generate QR code with AprilTag overlay for existing QRCode element
     */
    async generateQRWithAprilTag(qrElementId, qrData) {
        console.log('Starting QR generation with AprilTag for element:', qrElementId);
        console.log('QR Code data to encode:', qrData);
        
        try {
            // Verify domain first
            if (!this.verifyDomain()) {
                console.error('Domain verification failed');
                throw new Error('Domain not allowed');
            }
            console.log('Domain verification passed');

            // Get the QR code element
            const qrElement = document.getElementById(qrElementId);
            if (!qrElement) {
                console.error('QR element not found:', qrElementId);
                throw new Error(`QR element '${qrElementId}' not found`);
            }
            console.log('QR element found:', qrElement);

            // Ensure AprilTag family is initialized
            if (!this.apriltagFamily) {
                console.log('Initializing AprilTag family...');
                await this.initializeAprilTagFamily();
            }

            // Get AprilTag numbers from server
            await this.getAprilTagNumbers();

            // Create canvas overlay
            this.createCanvasOverlay(qrElement);

            // Start AprilTag animation
            console.log('Starting AprilTag animation...');
            this.startAprilTagAnimation();

            console.log('QR code with AprilTag overlay created successfully!');
            console.log('Final summary:');
            console.log('  - QR Code data:', qrData);
            console.log('  - AprilTag numbers:', this.apriltagNumbers.length);
            return true;

        } catch (error) {
            console.error('QR generation failed:', error);
            return false;
        }
    }

    /**
     * Create canvas overlay on top of QR code element
     */
    createCanvasOverlay(qrElement) {
        // Find the actual QR code canvas/image within the element
        const qrCanvas = qrElement.querySelector('canvas');
        const qrImg = qrElement.querySelector('img');
        
        let qrSize;
        if (qrCanvas) {
            // Use the actual QR canvas dimensions
            qrSize = Math.min(qrCanvas.width, qrCanvas.height);
            console.log('Using QR canvas dimensions:', qrCanvas.width, 'x', qrCanvas.height);
        } else if (qrImg) {
            // Use the QR image dimensions
            qrSize = Math.min(qrImg.naturalWidth, qrImg.naturalHeight);
            console.log('Using QR image dimensions:', qrImg.naturalWidth, 'x', qrImg.naturalHeight);
        } else {
            // Fallback to element bounding box
            const qrRect = qrElement.getBoundingClientRect();
            qrSize = Math.min(qrRect.width, qrRect.height);
            console.log('Using element bounding box:', qrRect.width, 'x', qrRect.height);
        }
        
        // Create canvas overlay
        const canvas = document.createElement('canvas');
        canvas.id = 'apriltag-overlay';
        canvas.width = qrSize;
        canvas.height = qrSize;
        canvas.style.position = 'absolute';
        canvas.style.top = '16px'; // Account for QR code div padding
        canvas.style.left = '16px'; // Account for QR code div padding
        canvas.style.pointerEvents = 'none'; // Allow clicks to pass through
        canvas.style.zIndex = '10';
        
        // Make QR element container relative positioned
        qrElement.style.position = 'relative';
        
        // Add canvas to QR element
        qrElement.appendChild(canvas);
        
        // Store canvas reference
        this.overlayCanvas = canvas;
        this.canvasSize = qrSize;
        
        console.log('Canvas overlay created:', qrSize, 'x', qrSize);
    }

    /**
     * Configure canvas for pixel-perfect rendering
     */
    configureCanvas(ctx) {
        ctx.imageSmoothingEnabled = false;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.lineWidth = 1;
        ctx.lineCap = 'butt';
        ctx.lineJoin = 'miter';
    }

    /**
     * Generate QR code using existing QRCode library
     */
    async generateQRCode(ctx, data) {
        console.log('Starting QR code generation with data:', data);
        
        // Use the existing QRCode library that's already loaded
        if (typeof QRCode === 'undefined') {
            console.error('QRCode library not loaded');
            throw new Error('QRCode library not loaded');
        }

        try {
            // Create a temporary div for QR generation (QRCode library expects a DOM element)
            const tempDiv = document.createElement('div');
            tempDiv.style.width = (this.canvasSize - 40) + 'px';
            tempDiv.style.height = (this.canvasSize - 40) + 'px';
            tempDiv.style.position = 'absolute';
            tempDiv.style.left = '-9999px'; // Hide off-screen
            
            // Add to DOM temporarily
            document.body.appendChild(tempDiv);
            
            console.log('Created temp div for QR generation');
            
            // Generate QR code using the existing QRCode library pattern
            new QRCode(tempDiv, data);
            
            console.log('QRCode instance created');
            
            // Wait a moment for the QR code to be drawn
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Get the canvas from the QRCode library
            const qrCanvas = tempDiv.querySelector('canvas');
            if (qrCanvas) {
                console.log('Found QR canvas, drawing to main canvas');
                // Draw the QR code on our main canvas
                ctx.drawImage(qrCanvas, 20, 20); // Offset for AprilTag space
                console.log('QR code drawn successfully');
            } else {
                console.error('QR canvas not found, falling back to placeholder');
                this.drawPlaceholderQR(ctx, data);
            }
            
            // Clean up temporary div
            document.body.removeChild(tempDiv);
            
        } catch (error) {
            console.error('QRCode generation failed:', error);
            console.log('Falling back to placeholder QR code');
            // Fallback: Draw a simple placeholder
            this.drawPlaceholderQR(ctx, data);
        }
    }

    /**
     * Draw a simple placeholder QR code when the library fails
     */
    drawPlaceholderQR(ctx, data) {
        const qrSize = this.canvasSize - 60; // Leave space for AprilTag
        const startX = 30;
        const startY = 30;
        
        // Draw white background
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(startX, startY, qrSize, qrSize);
        
        // Draw black border
        ctx.strokeStyle = '#000000';
        ctx.lineWidth = 2;
        ctx.strokeRect(startX, startY, qrSize, qrSize);
        
        // Draw some placeholder squares to look like a QR code
        ctx.fillStyle = '#000000';
        const cellSize = qrSize / 25; // 25x25 grid
        
        // Draw corner squares (like QR code finder patterns)
        this.drawQRCorner(ctx, startX + cellSize, startY + cellSize, cellSize);
        this.drawQRCorner(ctx, startX + qrSize - 4*cellSize, startY + cellSize, cellSize);
        this.drawQRCorner(ctx, startX + cellSize, startY + qrSize - 4*cellSize, cellSize);
        
        // Draw some random data squares
        for (let i = 0; i < 50; i++) {
            const x = startX + (Math.random() * 20 + 2) * cellSize;
            const y = startY + (Math.random() * 20 + 2) * cellSize;
            ctx.fillRect(x, y, cellSize, cellSize);
        }
        
        // Add text
        ctx.fillStyle = '#000000';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('QR Code Placeholder', startX + qrSize/2, startY + qrSize/2);
        ctx.fillText(data.substring(0, 20) + '...', startX + qrSize/2, startY + qrSize/2 + 15);
    }

    /**
     * Draw QR code corner pattern
     */
    drawQRCorner(ctx, x, y, cellSize) {
        // Outer square
        ctx.fillRect(x, y, 7*cellSize, 7*cellSize);
        // Inner white square
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(x + cellSize, y + cellSize, 5*cellSize, 5*cellSize);
        // Center black square
        ctx.fillStyle = '#000000';
        ctx.fillRect(x + 2*cellSize, y + 2*cellSize, 3*cellSize, 3*cellSize);
    }

    /**
     * Start AprilTag animation
     */
    startAprilTagAnimation() {
        // Clear any existing animation
        if (this.animationInterval) {
            clearInterval(this.animationInterval);
        }

        if (!this.overlayCanvas) {
            console.error('No overlay canvas available for animation');
            return;
        }

        const ctx = this.overlayCanvas.getContext('2d');
        this.configureCanvas(ctx);

        // Start new animation
        this.animationInterval = setInterval(() => {
            this.drawAprilTag(ctx);
            this.currentApriltagIndex = (this.currentApriltagIndex + 1) % this.apriltagNumbers.length;
        }, this.apriltagAnimationInterval);
    }

    /**
     * Draw AprilTag in bottom right corner
     */
    drawAprilTag(ctx) {
        if (this.apriltagNumbers.length === 0) {
            console.warn('No AprilTag numbers available for rendering');
            return;
        }

        // Clear the overlay canvas
        ctx.clearRect(0, 0, this.canvasSize, this.canvasSize);

        const apriltagNumber = this.apriltagNumbers[this.currentApriltagIndex];
        const pattern = this.generateAprilTagPattern(apriltagNumber);
        
        const apriltagSize = Math.min(50, this.canvasSize * 0.20); // Responsive size - increased from 40 to 60 and 0.2 to 0.25
        const gridSize = pattern.length;
        const cellSize = apriltagSize / gridSize;
        const whiteBorderWidth = 2;
        const startX = this.canvasSize - apriltagSize + (whiteBorderWidth*2); // Account for white border
        const startY = this.canvasSize - apriltagSize + (whiteBorderWidth*2); // Account for white border
        // Draw white background
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(startX, startY, apriltagSize, apriltagSize);

        // Draw AprilTag pattern using apriltag-js format
        ctx.fillStyle = '#000000';
        for (let y = 0; y < gridSize; y++) {
            for (let x = 0; x < gridSize; x++) {
                const pixel = pattern[y][x];
                // apriltag-js uses 'b' for black, 'w' for white, 'x' for transparent
                if (pixel === 'b') { // Black cell
                    ctx.fillRect(
                        startX + x * cellSize,
                        startY + y * cellSize,
                        cellSize,
                        cellSize
                    );
                }
            }
        }

        // Draw white border on left and top sides only
        ctx.fillStyle = '#FFFFFF';
        
        // Left border
        ctx.fillRect(startX - whiteBorderWidth, startY - whiteBorderWidth, whiteBorderWidth, apriltagSize + whiteBorderWidth);
        
        // Top border
        ctx.fillRect(startX - whiteBorderWidth, startY - whiteBorderWidth, apriltagSize + whiteBorderWidth, whiteBorderWidth);
    }

    /**
     * Render debug information
     */
    renderDebugInfo(ctx, data) {
        ctx.fillStyle = '#000000';
        ctx.font = '8px monospace';
        ctx.textAlign = 'center';

        const centerX = this.canvasSize / 2;
        const currentApriltagNumber = this.apriltagNumbers.length > 0 ? this.apriltagNumbers[this.currentApriltagIndex] : 'N/A';
        const apriltagInfo = `AT: ${currentApriltagNumber} (${this.currentApriltagIndex + 1}/${this.apriltagNumbers.length})`;
        const url = data.length > 20 ? data.substring(0, 20) + '...' : data;
        const buildInfo = `Built: ${new Date().toLocaleDateString()}`;

        ctx.fillText(apriltagInfo, centerX, this.canvasSize - 30);
        ctx.fillText(url, centerX, this.canvasSize - 20);
        ctx.fillText(buildInfo, centerX, this.canvasSize - 10);
    }

    /**
     * Stop animation
     */
    stopAnimation() {
        if (this.animationInterval) {
            clearInterval(this.animationInterval);
            this.animationInterval = null;
        }
    }

    /**
     * Clean up overlay canvas
     */
    cleanup() {
        this.stopAnimation();
        if (this.overlayCanvas && this.overlayCanvas.parentNode) {
            this.overlayCanvas.parentNode.removeChild(this.overlayCanvas);
            this.overlayCanvas = null;
        }
    }

    /**
     * Get AprilTag numbers from server
     */
    async getAprilTagNumbers() {
        try {
            const response = await fetch('/get-apriltags', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({})
            });

            if (!response.ok) {
                throw new Error(`AprilTag generation failed: ${response.status}`);
            }

            const result = await response.json();
            console.log('AprilTag numbers received:', result);
            
            // Check if the response indicates an error
            if (result.result === false) {
                throw new Error(result.error || 'AprilTag generation failed');
            }
            
            // Use the AprilTag numbers from the server
            if (result.apriltag_numbers) {
                console.log('Server-provided AprilTag numbers:', result.apriltag_numbers);
                console.log('AprilTag numbers breakdown:', result.apriltag_numbers.map((num, i) => `Pattern ${i + 1}: ${num}`).join(', '));
                
                // Store the AprilTag numbers for rendering
                this.apriltagNumbers = result.apriltag_numbers;
                console.log('Stored AprilTag numbers:', this.apriltagNumbers.length, 'numbers');
            }
            
            return result;

        } catch (error) {
            console.error('AprilTag generation failed:', error);
            throw error;
        }
    }

    /**
     * Generate AprilTag pattern from number using apriltag-js library
     */
    generateAprilTagPattern(number) {
        if (!this.apriltagFamily) {
            console.warn('AprilTag family not initialized, using fallback pattern');
            return this.generateFallbackPattern(number);
        }

        try {
            // Use the apriltag-js library to generate the actual pattern
            const pattern = this.apriltagFamily.render(number);
            return pattern;
        } catch (error) {
            return this.generateFallbackPattern(number);
        }
    }

    /**
     * Generate fallback pattern when apriltag-js is not available
     */
    generateFallbackPattern(number) {
        const pattern = [];
        for (let i = 0; i < 6; i++) {
            const row = [];
            for (let j = 0; j < 6; j++) {
                // Use number to determine pattern
                const bit = (number + i * 6 + j) % 2;
                row.push(bit);
            }
            pattern.push(row);
        }
        return pattern;
    }
}

// Export for use
window.QRGenerator = QRGenerator;
}
