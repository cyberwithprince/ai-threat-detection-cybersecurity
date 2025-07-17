const eventSource = new EventSource("/live_stream");

// Sound effects for threats (uncomment if you add sound files)
// const threatSound = new Audio('/static/sounds/alert.mp3');
// const successSound = new Audio('/static/sounds/success.mp3');

// Listen to live stream
eventSource.onmessage = function(event) {
    const [idx, pred, attackCategory, trueLabel, action, reward, cumReward] = event.data.split(",");
    
    // Play sound effects based on prediction (uncomment if you add sound files)
    // if (pred == "1") {
    //     threatSound.play();
    // } else {
    //     successSound.play();
    // }

    // Update metrics with cyber animation
    updateMetrics(pred, cumReward);
    
    // Add new row with cyberpunk effects
    addTableRow({
        id: idx,
        prediction: pred,
        category: attackCategory,
        trueLabel: trueLabel,
        action: action,
        reward: reward,
        cumulative: cumReward
    });
};

function updateMetrics(prediction, cumReward) {
    // Update threat/benign counters with animation
    if (prediction == "1") {
        let attackCount = document.getElementById("attackCount");
        let currentCount = parseInt(attackCount.textContent);
        animateNumber(attackCount, currentCount, currentCount + 1);
        
        // Update last detection time with cyber effect
        const now = new Date().toLocaleTimeString();
        const timeElement = document.getElementById("lastAttackTime");
        timeElement.textContent = now;
        timeElement.style.animation = "glitch 0.3s ease";
        setTimeout(() => timeElement.style.animation = "", 300);
    } else {
        let benignCount = document.getElementById("benignCount");
        let currentCount = parseInt(benignCount.textContent);
        animateNumber(benignCount, currentCount, currentCount + 1);
    }

    // Update cumulative reward with smooth animation
    const cumulativeElement = document.getElementById("cumulative");
    const currentReward = parseFloat(cumulativeElement.textContent);
    animateNumber(cumulativeElement, currentReward, parseFloat(cumReward), true);
}

function animateNumber(element, start, end, isFloat = false) {
    const duration = 1000; // 1 second animation
    const steps = 60;
    const increment = (end - start) / steps;
    let current = start;
    
    const updateDisplay = () => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            element.textContent = isFloat ? end.toFixed(2) : Math.round(end);
            return;
        }
        element.textContent = isFloat ? current.toFixed(2) : Math.round(current);
        requestAnimationFrame(updateDisplay);
    };
    
    requestAnimationFrame(updateDisplay);
}

function addTableRow(data) {
    const tableBody = document.querySelector("#stream-table tbody");
    const row = document.createElement("tr");
    row.className = data.prediction == "1" ? "high-threat" : "";
    
    row.innerHTML = `
        <td>${data.id}</td>
        <td>
            <span class="status-indicator ${data.prediction == "1" ? "threat" : "safe"}">
                ${data.prediction == "1" ? "⚠ THREAT" : "✓ SAFE"}
            </span>
        </td>
        <td class="attack-type">${data.category || 'N/A'}</td>
        <td>${data.trueLabel}</td>
        <td>
            <span class="action-tag ${data.action == "1" ? "blocked" : "allowed"}">
                ${data.action == "1" ? "BLOCKED" : "ALLOWED"}
            </span>
        </td>
        <td class="reward ${parseInt(data.reward) > 0 ? 'positive' : 'negative'}">
            ${data.reward}
        </td>
        <td class="cumulative">${data.cumulative}</td>
    `;

    // Add row with fade-in effect
    row.style.opacity = "0";
    tableBody.appendChild(row);
    setTimeout(() => row.style.opacity = "1", 50);

    // Auto-scroll to latest entry
    const container = document.querySelector(".table-container");
    container.scrollTop = container.scrollHeight;
}

// Error handling
eventSource.onerror = function(err) {
    console.error("EventSource failed:", err);
    eventSource.close();
    // Add visual feedback for connection loss
    document.getElementById("status").textContent = "CONNECTION LOST";
    document.getElementById("status").className = "error";
};
