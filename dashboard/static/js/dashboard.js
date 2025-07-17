// Table Initialization
const simulationTable = document.getElementById('simulationTable');
let threatCount = 0;
let normalCount = 0;

// Attack Types and Severity Levels
const attackTypes = ['DoS', 'DDoS', 'Brute Force', 'SQL Injection', 'Port Scanning'];
const severityLevels = ['Low', 'Medium', 'High', 'Critical'];

// Live Stream Handler
const eventSource = new EventSource('/live_stream');
const liveStream = document.getElementById('liveStream');

eventSource.onmessage = function(event) {
    if (event.data === 'keepalive') {
        return;
    }
    
    const [type, ip, category, id] = event.data.split(',');
    const timestamp = moment().format('HH:mm:ss');
    
    // Update counters
    if (type === 'attack') {
        threatCount++;
        document.getElementById('totalThreats').textContent = threatCount;
    } else {
        normalCount++;
        document.getElementById('normalTraffic').textContent = normalCount;
    }
    
    // Add new row to table
    addTableRow({
        id: id,
        timestamp: timestamp,
        type: type,
        category: category,
        severity: type === 'attack' ? getSeverity() : 'None',
        status: type === 'attack' ? 'Blocked' : 'Allowed'
    });
};

function getSeverity() {
    return severityLevels[Math.floor(Math.random() * severityLevels.length)];
}

function addTableRow(data) {
    const row = document.createElement('tr');
    row.className = data.type === 'attack' ? 'threat-row' : 'normal-row';
    
    row.innerHTML = `
        <td>${data.id}</td>
        <td>${data.timestamp}</td>
        <td>${data.type}</td>
        <td>${data.category}</td>
        <td><span class="severity-badge ${data.severity.toLowerCase()}">${data.severity}</span></td>
        <td><span class="status-badge ${data.status.toLowerCase()}">${data.status}</span></td>
        <td>
            <button onclick="showDetails('${data.id}')" class="btn-details">
                <i class="mdi mdi-information"></i>
            </button>
        </td>
    `;
    
    const tbody = simulationTable.getElementsByTagName('tbody')[0];
    tbody.insertBefore(row, tbody.firstChild);
    
    if (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

async function startSimulation() {
    try {
        const response = await fetch('/api/simulation/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            // Reset counters on simulation start
            threatCount = 0;
            normalCount = 0;
            document.getElementById('totalThreats').textContent = '0';
            document.getElementById('normalTraffic').textContent = '0';
            updateSimulationStatus('running');
        } else {
            console.error('Failed to start simulation:', data.message);
        }
    } catch (error) {
        console.error('Error starting simulation:', error);
    }
}

async function stopSimulation() {
    try {
        const response = await fetch('/api/simulation/stop', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            updateSimulationStatus('stopped');
        } else {
            console.error('Failed to stop simulation:', data.message);
        }
    } catch (error) {
        console.error('Error stopping simulation:', error);
    }
}

function updateSimulationStatus(status) {
    const statusElement = document.getElementById('simulationStatus');
    const startButton = document.getElementById('startSimulation');
    const stopButton = document.getElementById('stopSimulation');
    
    if (statusElement) {
        statusElement.className = `status-badge ${status}`;
    }
    
    if (startButton) {
        startButton.disabled = status === 'running';
    }
    if (stopButton) {
        stopButton.disabled = status === 'stopped';
    }
}

async function showDetails(packetId) {
    try {
        const modal = document.getElementById('explanationModal');
        const modalContent = document.getElementById('explanationContent');
        const sqlExplanation = document.getElementById('sqlExplanation');
        modalContent.innerHTML = '<div class="loading">Generating explanation...</div>';
        sqlExplanation.style.display = 'none';
        modal.style.display = 'block';

        const response = await fetch(`/api/explanation/${packetId}`);
        const data = await response.json();

        if (data.status === 'success') {
            modalContent.innerHTML = `
                <img src="${data.image_url}" alt="SHAP Explanation" class="explanation-image">
            `;
            
            // Show SQL injection specific explanation if applicable
            if (data.attack_type === 'SQL Injection') {
                const indicators = document.getElementById('sqlIndicators');
                indicators.innerHTML = `
                    <li>High HTTP Method Count: ${data.features.ct_flw_http_mthd} <span class="highlight-value">Suspicious</span></li>
                    <li>Large Request Size: ${data.features.sbytes} bytes <span class="highlight-value">Abnormal</span></li>
                    <li>Multiple Source Ports: ${data.features.ct_src_dport_ltm} <span class="highlight-value">Suspicious</span></li>
                    <li>High Connection Rate: ${data.features.rate}/s <span class="highlight-value">Unusual</span></li>
                `;
                sqlExplanation.style.display = 'block';
            }
        } else {
            modalContent.innerHTML = `<div class="error">Failed to generate explanation: ${data.error}</div>`;
        }
    } catch (error) {
        console.error('Error getting explanation:', error);
        modalContent.innerHTML = '<div class="error">Failed to generate explanation</div>';
    }
}

// Poll simulation status every 5 seconds
setInterval(async () => {
    try {
        const response = await fetch('/api/simulation/status');
        const data = await response.json();
        updateSimulationStatus(data.status);
    } catch (error) {
        console.error('Error updating status:', error);
    }
}, 5000);