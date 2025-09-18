// PAD Test JavaScript functionality
async function debugPAD() {
    const fileInput = document.getElementById('debugFile');
    const button = document.getElementById('debugBtn');
    const results = document.getElementById('debugResults');
    
    if (!fileInput.files[0]) {
        alert('Please select a video file');
        return;
    }
    
    button.disabled = true;
    button.textContent = 'Analyzing...';
    results.style.display = 'block';
    results.textContent = 'Processing video...';
    
    try {
        const formData = new FormData();
        formData.append('video', fileInput.files[0]);
        
        const response = await fetch('/face/debug-pad', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            results.className = 'results success';
            results.textContent = JSON.stringify(data, null, 2);
        } else {
            results.className = 'results error';
            results.textContent = `Error: ${data.detail || 'Unknown error'}`;
        }
    } catch (error) {
        results.className = 'results error';
        results.textContent = `Network error: ${error.message}`;
    } finally {
        button.disabled = false;
        button.textContent = 'Debug PAD';
    }
}

async function testPAD() {
    const fileInput = document.getElementById('testFile');
    const button = document.getElementById('testBtn');
    const results = document.getElementById('testResults');
    
    if (!fileInput.files[0]) {
        alert('Please select a video file');
        return;
    }
    
    button.disabled = true;
    button.textContent = 'Testing...';
    results.style.display = 'block';
    results.textContent = 'Processing video and creating synthetic attacks...';
    
    try {
        const formData = new FormData();
        formData.append('video', fileInput.files[0]);
        
        const response = await fetch('/face/test-pad', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            results.className = 'results success';
            results.textContent = JSON.stringify(data, null, 2);
            
            // Highlight key differences
            const summary = data.test_summary;
            if (summary.difference > 0.1) {
                results.textContent += '\n\n✅ PAD is working! Real frames scored higher than synthetic attacks.';
            } else if (summary.difference < -0.1) {
                results.textContent += '\n\n⚠️ PAD may not be working correctly. Attack frames scored higher than real frames.';
            } else {
                results.textContent += '\n\n❓ PAD results are inconclusive. Scores are too similar.';
            }
        } else {
            results.className = 'results error';
            results.textContent = `Error: ${data.detail || 'Unknown error'}`;
        }
    } catch (error) {
        results.className = 'results error';
        results.textContent = `Network error: ${error.message}`;
    } finally {
        button.disabled = false;
        button.textContent = 'Test PAD';
    }
}

// Add event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const debugBtn = document.getElementById('debugBtn');
    const testBtn = document.getElementById('testBtn');
    
    if (debugBtn) {
        debugBtn.addEventListener('click', debugPAD);
    }
    
    if (testBtn) {
        testBtn.addEventListener('click', testPAD);
    }
});
