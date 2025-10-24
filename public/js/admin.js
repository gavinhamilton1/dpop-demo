// admin.js - Database Admin Panel JavaScript

let dbData = {};

async function loadAllTables() {
    const content = document.getElementById('content');
    content.innerHTML = '<div class="loading">Loading database tables...</div>';
    
    try {
        const response = await fetch('/admin/db/all', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        dbData = await response.json();
        renderTables(dbData);
    } catch (error) {
        content.innerHTML = `
            <div class="error">
                <strong>Error loading database:</strong> ${error.message}
            </div>
        `;
    }
}

function renderTables(data) {
    const content = document.getElementById('content');
    
    if (!data.tables || data.tables.length === 0) {
        content.innerHTML = '<div class="error">No tables found in database.</div>';
        return;
    }
    
    let html = '';
    
    for (const table of data.tables) {
        html += `
            <div class="table-container">
                <div class="table-header">
                    <h2>${table.name}</h2>
                    <div class="table-meta">
                        ${table.count} row${table.count !== 1 ? 's' : ''}
                    </div>
                </div>
                ${renderTable(table)}
            </div>
        `;
    }
    
    content.innerHTML = html;
}

function renderTable(table) {
    if (table.count === 0) {
        return '<p style="color: #999; font-style: italic;">No data in this table</p>';
    }
    
    const columns = table.columns;
    const rows = table.data;
    
    let html = '<table><thead><tr>';
    for (const col of columns) {
        html += `<th>${col}</th>`;
    }
    html += '</tr></thead><tbody>';
    
    for (const row of rows) {
        html += '<tr>';
        for (const col of columns) {
            const value = row[col];
            html += `<td>${formatCell(col, value)}</td>`;
        }
        html += '</tr>';
    }
    
    html += '</tbody></table>';
    return html;
}

let jsonDataStore = {}; // Store JSON data with unique IDs

function formatCell(column, value) {
    if (value === null || value === undefined) {
        return '<span style="color: #999; font-style: italic;">null</span>';
    }
    
    // Detect JSON strings
    if (typeof value === 'string' && (value.startsWith('{') || value.startsWith('['))) {
        try {
            JSON.parse(value);
            // Store JSON with unique ID to avoid escaping issues
            const jsonId = 'json_' + Math.random().toString(36).substr(2, 9);
            jsonDataStore[jsonId] = value;
            return `<span class="json-cell" data-json-id="${jsonId}">${escapeHtml(truncate(value, 50))}</span>`;
        } catch (e) {
            // Not valid JSON
        }
    }
    
    // Format timestamps
    if (column.includes('_at') || column === 'created_at' || column === 'updated_at' || column === 'expires_at') {
        if (typeof value === 'number') {
            const date = new Date(value * 1000);
            return `<span class="timestamp" title="${date.toISOString()}">${date.toLocaleString()}</span>`;
        }
    }
    
    // Truncate long strings
    if (typeof value === 'string' && value.length > 100) {
        return `<span title="${escapeHtml(value)}">${escapeHtml(truncate(value, 100))}</span>`;
    }
    
    return escapeHtml(String(value));
}

function showJSONById(jsonId) {
    try {
        const jsonStr = jsonDataStore[jsonId];
        if (!jsonStr) {
            alert('JSON data not found');
            return;
        }
        
        const parsed = JSON.parse(jsonStr);
        const formatted = JSON.stringify(parsed, null, 2);
        document.getElementById('jsonContent').textContent = formatted;
        document.getElementById('jsonModal').classList.add('active');
    } catch (e) {
        alert('Failed to parse JSON: ' + e.message);
    }
}

function closeModal() {
    document.getElementById('jsonModal').classList.remove('active');
}

function truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function exportAsJSON() {
    const dataStr = JSON.stringify(dbData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `database-export-${new Date().toISOString()}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

async function clearGeolocationCache() {
    if (!confirm('Are you sure you want to clear the geolocation cache?')) {
        return;
    }
    
    try {
        const response = await fetch('/admin/geo/clear', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            alert('Geolocation cache cleared successfully');
        } else {
            alert('Failed to clear cache');
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

function openBroadcastModal() {
    document.getElementById('broadcastModal').classList.add('active');
    document.getElementById('messageText').focus();
}

function closeBroadcastModal() {
    document.getElementById('broadcastModal').classList.remove('active');
    document.getElementById('broadcastForm').reset();
}

async function sendBroadcastMessage(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const messageData = {
        message: formData.get('message'),
        type: formData.get('type')
    };
    
    if (!messageData.message.trim()) {
        alert('Please enter a message');
        return;
    }
    
    const sendBtn = document.getElementById('sendBroadcastBtn');
    const originalText = sendBtn.textContent;
    
    try {
        sendBtn.textContent = 'Sending...';
        sendBtn.disabled = true;
        
        const response = await fetch('/sse/broadcast', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(messageData),
            credentials: 'include'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            alert(`✅ Message sent successfully!\n\nRecipients: ${result.recipients}\nMessage: "${messageData.message}"`);
            closeBroadcastModal();
        } else {
            alert('❌ Failed to send message: ' + (result.detail || 'Unknown error'));
        }
    } catch (error) {
        alert('❌ Error: ' + error.message);
    } finally {
        sendBtn.textContent = originalText;
        sendBtn.disabled = false;
    }
}

// Load data on page load
document.addEventListener('DOMContentLoaded', () => {
    loadAllTables();
    
    // Attach button event listeners
    document.getElementById('refreshBtn').addEventListener('click', loadAllTables);
    document.getElementById('exportBtn').addEventListener('click', exportAsJSON);
    document.getElementById('clearGeoBtn').addEventListener('click', clearGeolocationCache);
    document.getElementById('closeModalBtn').addEventListener('click', closeModal);
    document.getElementById('broadcastBtn').addEventListener('click', openBroadcastModal);
    
    // Close modal on outside click
    document.getElementById('jsonModal').addEventListener('click', (e) => {
        if (e.target.id === 'jsonModal') {
            closeModal();
        }
    });
    
    // Broadcast modal event listeners
    document.getElementById('closeBroadcastBtn').addEventListener('click', closeBroadcastModal);
    document.getElementById('cancelBroadcastBtn').addEventListener('click', closeBroadcastModal);
    document.getElementById('broadcastForm').addEventListener('submit', sendBroadcastMessage);
    
    // Close broadcast modal on outside click
    document.getElementById('broadcastModal').addEventListener('click', (e) => {
        if (e.target.id === 'broadcastModal') {
            closeBroadcastModal();
        }
    });
    
    // Test AMBER flag button
    const testAmberBtn = document.getElementById('testAmberBtn');
    if (testAmberBtn) {
        testAmberBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/admin/test/set-amber-flag', {
                    method: 'POST',
                    credentials: 'include'
                });
                const result = await response.json();
                
                if (response.ok) {
                    alert('✅ AMBER flag set for current session!\n\nGo back to the main page and refresh to see the risk flag.');
                } else {
                    alert('❌ Failed to set flag: ' + (result.detail || 'Unknown error'));
                }
            } catch (error) {
                alert('❌ Error: ' + error.message);
            }
        });
    }
    
    // Delegate click events for JSON cells (since they're dynamically created)
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('json-cell')) {
            const jsonId = e.target.getAttribute('data-json-id');
            if (jsonId) {
                showJSONById(jsonId);
            }
        }
    });
});

