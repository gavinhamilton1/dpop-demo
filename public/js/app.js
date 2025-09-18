// public/app.js
// Main application entry point - Refactored to use modular architecture

import { AppController } from './controllers/AppController.js';

// Global application instance
let appController = null;

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Initialize the application controller
    appController = new AppController();
    await appController.initialize();
    
    console.log('DPoP Demo Application initialized successfully');
    
  } catch (error) {
    console.error('Failed to initialize application:', error);
    
    // Show fallback error message
    const logContainer = document.getElementById('logContainer');
    if (logContainer) {
      logContainer.innerHTML = `
        <div class="log-entry error">
          ❌ Application initialization failed: ${error.message}
        </div>
      `;
    }
  }
});

// Handle page unload
window.addEventListener('beforeunload', () => {
  if (appController) {
    appController.cleanup();
  }
});

// Export for debugging
window.appController = appController;
