/**
 * Pure JavaScript AprilTag Overlay for QR Codes
 * Provides rotating AprilTag overlay functionality for existing QR codes
 */

/**
 * AprilTag Family class
 * Handles AprilTag family configuration and tag generation
 */
class AprilTagFamily {
    constructor(config) {
        this.size = config.nbits || 6;  // Grid size (e.g., 6x6 for 36h11)
        this.minHammingDistance = config.h || 11;
        this.codes = config.codes || [];
        this.name = config.name || 'unknown';
    }
    
    /**
     * Get tag pattern for a specific tag ID
     * @param {number} tagId - Tag ID to get pattern for
     * @returns {Array<Array<number>>} 2D array of 0s and 1s representing the tag pattern
     */
    getTagPattern(tagId) {
        if (tagId >= this.codes.length) {
            console.warn(`Tag ID ${tagId} out of range for family ${this.name}`);
            return null;
        }
        
        const code = this.codes[tagId];
        const gridSize = this.size;
        const pattern = [];
        
        // Convert code to binary pattern
        for (let y = 0; y < gridSize; y++) {
            const row = [];
            for (let x = 0; x < gridSize; x++) {
                const bitIndex = y * gridSize + x;
                const bit = (code >> bitIndex) & 1;
                row.push(bit);
            }
            pattern.push(row);
        }
        
        return pattern;
    }
}

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
    async generateQRWithAprilTag(qrElementId, qrData, linkId = null) {
        console.log('Starting QR generation with AprilTag for element:', qrElementId);
        console.log('QR Code data to encode:', qrData);
        console.log('Link ID:', linkId);
        
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
            await this.getAprilTagNumbers(linkId);

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
        // Remove any existing overlay first
        const existingOverlay = qrElement.querySelector('#apriltag-overlay');
        if (existingOverlay) {
            existingOverlay.remove();
            console.log('Removed existing AprilTag overlay');
        }
        
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
        
        // Get padding from element (to account for QR code padding)
        const computedStyle = window.getComputedStyle(qrElement);
        const paddingTop = parseInt(computedStyle.paddingTop) || 0;
        const paddingLeft = parseInt(computedStyle.paddingLeft) || 0;
        
        // Create canvas overlay
        const canvas = document.createElement('canvas');
        canvas.id = 'apriltag-overlay';
        canvas.width = qrSize;
        canvas.height = qrSize;
        canvas.style.position = 'absolute';
        canvas.style.top = `${paddingTop}px`;  // Account for padding
        canvas.style.left = `${paddingLeft}px`;  // Account for padding
        canvas.style.pointerEvents = 'none'; // Allow clicks to pass through
        canvas.style.zIndex = '10';
        
        // Make QR element container relative positioned
        qrElement.style.position = 'relative';
        qrElement.style.display = 'inline-block'; // Ensure proper sizing
        
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

        // Draw the first AprilTag immediately
        this.drawAprilTag(ctx);

        // Start new animation
        this.animationInterval = setInterval(() => {
            this.currentApriltagIndex = (this.currentApriltagIndex + 1) % this.apriltagNumbers.length;
            this.drawAprilTag(ctx);
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
        
        const totalSize = Math.min(50, this.canvasSize * 0.18); // Slightly bigger size
        const gridSize = pattern.length;
        
        // Calculate sizes
        // Structure: white border (top/left, = cellSize) + black border (all sides, = cellSize) + AprilTag pattern
        // totalSize = whiteBorder + blackBorder + (gridSize * cellSize) + blackBorder
        // Since both whiteBorder and blackBorder = cellSize:
        // totalSize = cellSize + cellSize + (gridSize * cellSize) + cellSize
        // totalSize = (gridSize + 3) * cellSize
        const cellSize = totalSize / (gridSize + 3); // +3 for white border and both black borders
        const whiteBorderWidth = cellSize;  // White border = one AprilTag pixel
        const blackBorderWidth = cellSize;  // Black border = one AprilTag pixel
        
        const apriltagSize = gridSize * cellSize;
        
        // Position in bottom-right corner
        const startX = this.canvasSize - totalSize;
        const startY = this.canvasSize - totalSize;
        
        // Draw top white border
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(startX, startY, totalSize, whiteBorderWidth);
        
        // Draw left white border
        ctx.fillRect(startX, startY + whiteBorderWidth, whiteBorderWidth, totalSize - whiteBorderWidth);
        
        // Draw black border all around (inside the white border area)
        ctx.fillStyle = '#000000';
        const blackBorderStart = startX + whiteBorderWidth;
        const blackBorderTop = startY + whiteBorderWidth;
        const blackBorderSize = totalSize - whiteBorderWidth;
        
        // Top black border
        ctx.fillRect(blackBorderStart, blackBorderTop, blackBorderSize, blackBorderWidth);
        // Right black border
        ctx.fillRect(blackBorderStart + blackBorderSize - blackBorderWidth, blackBorderTop, blackBorderWidth, blackBorderSize);
        // Bottom black border
        ctx.fillRect(blackBorderStart, blackBorderTop + blackBorderSize - blackBorderWidth, blackBorderSize, blackBorderWidth);
        // Left black border
        ctx.fillRect(blackBorderStart, blackBorderTop, blackBorderWidth, blackBorderSize);
        
        // Draw white background for AprilTag area
        ctx.fillStyle = '#FFFFFF';
        const patternStartX = startX + whiteBorderWidth + blackBorderWidth;
        const patternStartY = startY + whiteBorderWidth + blackBorderWidth;
        ctx.fillRect(patternStartX, patternStartY, apriltagSize, apriltagSize);

        // Draw AprilTag pattern (supports both 0/1 and 'b'/'w' formats)
        ctx.fillStyle = '#000000';
        for (let y = 0; y < gridSize; y++) {
            for (let x = 0; x < gridSize; x++) {
                const pixel = pattern[y][x];
                // Support both numeric (1 = black, 0 = white) and string ('b' = black, 'w' = white) formats
                const isBlack = pixel === 1 || pixel === 'b';
                if (isBlack) {
                    ctx.fillRect(
                        patternStartX + x * cellSize,
                        patternStartY + y * cellSize,
                        cellSize,
                        cellSize
                    );
                }
            }
        }
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
    async getAprilTagNumbers(linkId = null) {
        try {
            const response = await fetch('/get-apriltags', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ linkId: linkId || '' })
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
            
            // Use the AprilTag numbers from the server (check both 'tags' and 'apriltag_numbers')
            const tagNumbers = result.tags || result.apriltag_numbers;
            if (tagNumbers && tagNumbers.length > 0) {
                console.log('Server-provided AprilTag numbers:', tagNumbers);
                console.log('AprilTag numbers breakdown:', tagNumbers.map((num, i) => `Pattern ${i + 1}: ${num}`).join(', '));
                
                // Store the AprilTag numbers for rendering
                this.apriltagNumbers = tagNumbers;
                console.log('Stored AprilTag numbers:', this.apriltagNumbers.length, 'numbers');
            } else {
                console.warn('No AprilTag numbers in server response');
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
            // Use the AprilTagFamily to generate the actual pattern
            const pattern = this.apriltagFamily.getTagPattern(number);
            if (!pattern) {
                console.warn(`Failed to get pattern for tag ${number}, using fallback`);
                return this.generateFallbackPattern(number);
            }
            return pattern;
        } catch (error) {
            console.error('Error generating AprilTag pattern:', error);
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
