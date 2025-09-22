// src/signature-share.js
// Real-time signature sharing between linked devices
import { logger } from './utils/logging.js';

class SignatureShare {
    constructor() {
        this.websocket = null;
        this.canvas = null;
        this.ctx = null;
        this.isDrawing = false;
        this.lastPoint = null;
        this.points = [];
        this.linkId = null;
        this.isMobile = false;
    }

    // Initialize signature sharing for mobile device (drawing)
    initMobile(linkId) {
        this.linkId = linkId;
        this.isMobile = true;
        
        // Create canvas for mobile drawing
        this.createCanvas('signature-canvas-mobile', 'Mobile - Scribble');
        
        // Set up drawing events
        this.setupDrawingEvents();
        
        // Connect to WebSocket for sending signature data
        this.connectWebSocket();
        
        logger.info('Scribble sharing initialized for mobile device');
    }

    // Initialize signature sharing for desktop device (viewing)
    initDesktop(linkId) {
        this.linkId = linkId;
        this.isMobile = false;
        
        // Use existing container instead of creating new one
        const container = document.getElementById('scribbleCanvasContainer');
        if (container) {
            // Create canvas inside the existing container
            container.innerHTML = `
                <canvas id="signature-canvas-desktop" width="300" height="300" style="border: 2px solid #333; border-radius: 8px; background: white;"></canvas>
            `;
            
            // Get the canvas and context
            this.canvas = document.getElementById('signature-canvas-desktop');
            this.ctx = this.canvas.getContext('2d');
            
            // Set canvas properties
            this.ctx.lineWidth = 3;
            this.ctx.strokeStyle = '#000';
            this.ctx.lineCap = 'round';
            this.ctx.lineJoin = 'round';
        } else {
            // Fallback to creating new container
            this.createCanvas('signature-canvas-desktop', 'Desktop - View Scribble');
        }
        
        // Connect to WebSocket for receiving signature data
        this.connectWebSocket();
        
        logger.info('Scribble sharing initialized for desktop device');
    }

    // Create and setup canvas
    createCanvas(containerId, title) {
        // Create container if it doesn't exist
        let container = document.getElementById(containerId);
        if (!container) {
            container = document.createElement('div');
            container.id = containerId;
            container.className = 'signature-container';
            container.innerHTML = `
                <h3>${title}</h3>
                <canvas id="${containerId}-canvas" width="300" height="300" style="border: 2px solid #333; border-radius: 8px; background: white;"></canvas><br>
                ${this.isMobile ? '<button id="reset-signature" style="margin-top: 10px; padding: 8px 16px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer;">Clear Scribble</button>' : ''}
            `;
            
            // For desktop, insert in the linking section
            if (!this.isMobile) {
                const linkBtn = document.getElementById('linkBtn');
                if (linkBtn && linkBtn.parentNode) {
                    // Insert after the link button's parent container
                    const linkSection = linkBtn.closest('.demo-sequence') || linkBtn.parentNode;
                    linkSection.appendChild(container);
                } else {
                    // Fallback to body if link button not found
                    document.body.appendChild(container);
                }
            } else {
                // For mobile, insert before the log container
                const logContainer = document.getElementById('out');
                if (logContainer && logContainer.parentNode) {
                    logContainer.parentNode.insertBefore(container, logContainer);
                } else {
                    // Fallback to appending to main container
                    const mainContainer = document.querySelector('.container');
                    if (mainContainer) {
                        mainContainer.appendChild(container);
                    } else {
                        // Fallback to body if container not found
                        document.body.appendChild(container);
                    }
                }
            }
        }

        // Get canvas and context
        this.canvas = document.getElementById(`${containerId}-canvas`);
        this.ctx = this.canvas.getContext('2d');
        
        // Set canvas properties
        this.ctx.lineWidth = 3;
        this.ctx.strokeStyle = '#000';
        this.ctx.lineCap = 'round';
        this.ctx.lineJoin = 'round';

        // Add reset button event listener for mobile
        if (this.isMobile) {
            const resetBtn = document.getElementById('reset-signature');
            if (resetBtn) {
                resetBtn.addEventListener('click', () => this.resetCanvas());
            }
        }
    }

    // Setup drawing events for mobile device
    setupDrawingEvents() {
        if (!this.canvas || !this.isMobile) return;

        // Mouse events
        this.canvas.addEventListener('mousedown', (e) => this.startDrawing(e));
        this.canvas.addEventListener('mousemove', (e) => this.draw(e));
        this.canvas.addEventListener('mouseup', () => this.stopDrawing());
        this.canvas.addEventListener('mouseleave', () => this.stopDrawing());

        // Touch events for mobile
        this.canvas.addEventListener('touchstart', (e) => {
            e.preventDefault();
            this.startDrawing(e);
        });
        this.canvas.addEventListener('touchmove', (e) => {
            e.preventDefault();
            this.draw(e);
        });
        this.canvas.addEventListener('touchend', (e) => {
            e.preventDefault();
            this.stopDrawing();
        });
    }

    // Get canvas coordinates from event
    getCanvasCoordinates(event) {
        const rect = this.canvas.getBoundingClientRect();
        let x, y;

        if (event.touches && event.touches[0]) {
            x = event.touches[0].clientX - rect.left;
            y = event.touches[0].clientY - rect.top;
        } else {
            x = event.clientX - rect.left;
            y = event.clientY - rect.top;
        }

        return { x, y };
    }

    // Start drawing
    startDrawing(event) {
        this.isDrawing = true;
        const { x, y } = this.getCanvasCoordinates(event);
        
        this.ctx.beginPath();
        this.ctx.moveTo(x, y);
        this.lastPoint = { x, y };
        
        // Send pen down event
        this.sendSignatureData({ type: 'pen_down', x, y });
    }

    // Draw on canvas
    draw(event) {
        if (!this.isDrawing) return;
        
        const { x, y } = this.getCanvasCoordinates(event);
        
        this.ctx.lineTo(x, y);
        this.ctx.stroke();
        
        this.lastPoint = { x, y };
        
        // Send drawing data
        this.sendSignatureData({ type: 'draw', x, y });
    }

    // Stop drawing
    stopDrawing() {
        if (this.isDrawing) {
            this.isDrawing = false;
            this.lastPoint = null;
            
            // Send pen up event
            this.sendSignatureData({ type: 'pen_up' });
        }
    }

    // Reset canvas
    resetCanvas() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        this.points = [];
        
        // Send reset event
        this.sendSignatureData({ type: 'reset' });
    }

    // Connect to WebSocket for signature sharing
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/link/ws/${this.linkId}`;
        
        logger.info(`Connecting signature WebSocket: ${wsUrl}`);
        logger.info('LinkId:', this.linkId);
        
        this.websocket = new WebSocket(wsUrl);
        
        this.websocket.onopen = () => {
            logger.info('Signature WebSocket connected successfully');
        };
        
        this.websocket.onmessage = (event) => {
            logger.info('Signature WebSocket received message:', event.data);
            this.handleWebSocketMessage(event.data);
        };
        
        this.websocket.onerror = (error) => {
            console.error('Signature WebSocket error:', error);
        };
        
        this.websocket.onclose = (event) => {
            logger.info('Signature WebSocket closed:', event.code, event.reason);
        };
    }

    // Send signature data via WebSocket
    sendSignatureData(data) {
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            const message = {
                type: 'signature',
                linkId: this.linkId,
                data: data
            };
            this.websocket.send(JSON.stringify(message));
        }
    }

    // Handle incoming WebSocket messages
    handleWebSocketMessage(data) {
        try {
            const message = JSON.parse(data);
            
            if (message.type === 'signature' && !this.isMobile) {
                // Handle signature data on desktop (viewing device)
                this.handleSignatureData(message.data);
            }
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    }

    // Handle signature data on desktop device
    handleSignatureData(data) {
        logger.info('handleSignatureData called with:', data);
        
        if (!this.ctx) {
            logger.error('No canvas context available for drawing');
            return;
        }
        
        // Debug canvas properties
        logger.info('Canvas dimensions:', this.canvas.width, 'x', this.canvas.height);
        logger.info('Canvas style:', this.canvas.style.width, 'x', this.canvas.style.height);
        logger.info('Canvas visible:', this.canvas.offsetWidth, 'x', this.canvas.offsetHeight);

        switch (data.type) {
            case 'pen_down':
                logger.info('Drawing pen_down at:', data.x, data.y);
                this.ctx.beginPath();
                this.ctx.moveTo(data.x, data.y);
                // Ensure stroke style is set
                this.ctx.strokeStyle = '#000000';
                this.ctx.lineWidth = 3;
                break;
                
            case 'draw':
                logger.info('Drawing line to:', data.x, data.y);
                this.ctx.lineTo(data.x, data.y);
                this.ctx.stroke();
                break;
                
            case 'pen_up':
                logger.info('Pen up - ending path');
                // End current path
                break;
                
            case 'reset':
                logger.info('Resetting canvas');
                this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
                break;
        }
    }

    // Cleanup
    destroy() {
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
        
        // Remove canvas containers
        const mobileContainer = document.getElementById('signature-canvas-mobile');
        const desktopContainer = document.getElementById('signature-canvas-desktop');
        
        if (mobileContainer) mobileContainer.remove();
        if (desktopContainer) desktopContainer.remove();
    }
}

// Export for use in other modules
export { SignatureShare };
