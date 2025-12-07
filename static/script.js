// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const filenameSpan = document.getElementById('filename');
const analyzeBtn = document.getElementById('analyze-btn');
const mobsfKeyInput = document.getElementById('mobsf-key');
const vtKeyInput = document.getElementById('vt-key');
const geminiKeyInput = document.getElementById('gemini-key');
const emptyState = document.getElementById('empty-state');
const progressContainer = document.getElementById('progress-container');
const resultContainer = document.getElementById('result-container');
const statusText = document.getElementById('status-text');

let selectedFile = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadKeys();
});

// Drag & Drop
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

// Demo Button
document.getElementById('demo-btn').addEventListener('click', () => {
    startAnalysis(true);
});

function handleFile(file) {
    if (!file.name.endsWith('.apk')) {
        alert('Please select a valid .apk file');
        return;
    }
    selectedFile = file;
    filenameSpan.textContent = file.name;
    document.querySelector('.upload-area').classList.add('hidden');
    fileInfo.classList.remove('hidden');
    analyzeBtn.disabled = false;
}

function clearFile() {
    selectedFile = null;
    fileInput.value = '';
    document.querySelector('.upload-area').classList.remove('hidden');
    fileInfo.classList.add('hidden');
    analyzeBtn.disabled = true;
}

function toggleLLMFields() {
    const provider = document.getElementById('llm-provider').value;
    if (provider === 'gemini') {
        document.getElementById('gemini-fields').style.display = 'block';
        document.getElementById('ollama-fields').style.display = 'none';
    } else {
        document.getElementById('gemini-fields').style.display = 'none';
        document.getElementById('ollama-fields').style.display = 'block';
    }
}

// Logic
async function startAnalysis() {
    saveKeys();

    if (!selectedFile) return;

    // UI Updates
    analyzeBtn.disabled = true;
    emptyState.classList.add('hidden');
    progressContainer.classList.remove('hidden');
    resultContainer.classList.add('hidden');

    // Prepare Form Data
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('mobsf_key', mobsfKeyInput.value);
    formData.append('vt_key', vtKeyInput.value);
    formData.append('llm_provider', document.getElementById('llm-provider').value);
    formData.append('llm_key', geminiKeyInput.value);
    formData.append('llm_model', document.getElementById('llm-provider').value === 'gemini' ? 'gemini-1.5-flash-001' : document.getElementById('ollama-model').value);

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload failed');

        const data = await response.json();
        const taskId = data.task_id;

        pollStatus(taskId);

    } catch (error) {
        alert('Error starting analysis: ' + error.message);
        resetApp();
    }
}

async function pollStatus(taskId) {
    const interval = setInterval(async () => {
        try {
            const response = await fetch(`/api/status/${taskId}`);
            const data = await response.json();

            // Update UI Message
            statusText.textContent = data.step;
            updateStepper(data.step);

            if (data.status === 'completed') {
                clearInterval(interval);
                showResults(taskId);
            } else if (data.status === 'failed') {
                clearInterval(interval);
                alert('Analysis failed: ' + data.error);
                resetApp();
            }

        } catch (e) {
            console.error("Polling error", e);
        }
    }, 2000);
}

function updateStepper(stepText) {
    // Simple logic matching string to step
    // Reset all
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));

    let activeIndex = 1;
    if (stepText.includes('MobSF')) activeIndex = 2;
    if (stepText.includes('VirusTotal')) activeIndex = 3;
    if (stepText.includes('AI') || stepText.includes('Consulting')) activeIndex = 4;
    if (stepText.includes('Done')) activeIndex = 5; // All active

    for (let i = 1; i <= 4; i++) {
        const stepEl = document.getElementById(`step-${i}`);
        if (i <= activeIndex) stepEl.classList.add('active');
    }
}

async function showResults(taskId) {
    try {
        const response = await fetch(`/api/result/${taskId}`);
        const data = await response.json();

        progressContainer.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        // Render AI Markdown
        const aiText = data.ai_analysis || "No AI analysis available.";
        document.getElementById('ai-output').innerHTML = marked.parse(aiText);

        // Render Raw JSON
        document.getElementById('raw-json').textContent = JSON.stringify(data, null, 2);

        // Determine Verdict (Heuristic)
        const verdictBanner = document.getElementById('verdict-banner');
        const verdictLabel = document.getElementById('verdict-label');

        // Priority 1: Check for explicit Classification lines or direct starts
        const upperText = aiText.toUpperCase();

        // Helper regexes
        const isMalicious = /CLASSIFICATION\s*[:\-]?\s*\**\s*MALICIOUS/i.test(aiText) ||
            /VERDICT\s*[:\-]?\s*\**\s*MALICIOUS/i.test(aiText) ||
            /^\s*\**MALICIOUS\**/i.test(aiText) || // Starts with MALICIOUS
            upperText.includes('**MALICIOUS**');

        const isSuspicious = /CLASSIFICATION\s*[:\-]?\s*\**\s*SUSPICIOUS/i.test(aiText) ||
            /VERDICT\s*[:\-]?\s*\**\s*SUSPICIOUS/i.test(aiText) ||
            /^\s*\**SUSPICIOUS\**/i.test(aiText) || // Starts with SUSPICIOUS
            upperText.includes('**SUSPICIOUS**');

        const isBenign = /CLASSIFICATION\s*[:\-]?\s*\**\s*BENIGN/i.test(aiText) ||
            /VERDICT\s*[:\-]?\s*\**\s*BENIGN/i.test(aiText) ||
            /^\s*\**BENIGN\**/i.test(aiText) || // Starts with BENIGN
            upperText.includes('**BENIGN**');

        if (isMalicious) {
            verdictBanner.className = 'verdict-banner malware';
            verdictLabel.textContent = 'DETECTED: MALICIOUS';
            verdictBanner.style.background = '';
            verdictBanner.style.borderColor = '';
            verdictBanner.style.color = '';
        } else if (isSuspicious) {
            verdictBanner.className = 'verdict-banner unknown';
            verdictLabel.textContent = 'WARNING: SUSPICIOUS';
            verdictBanner.style.background = 'rgba(255, 193, 7, 0.2)';
            verdictBanner.style.borderColor = '#ffc107';
            verdictBanner.style.color = '#ffc107';
        } else if (isBenign) {
            verdictBanner.className = 'verdict-banner safe';
            verdictLabel.textContent = 'CLEAN: BENIGN';
            verdictBanner.style.background = '';
            verdictBanner.style.borderColor = '';
            verdictBanner.style.color = '';
        }
        // Priority 2: Semantic search
        else if (upperText.includes('CLASS AS MALICIOUS') || upperText.includes('VERDICT IS MALICIOUS')) {
            verdictBanner.className = 'verdict-banner malware';
            verdictLabel.textContent = 'DETECTED: MALICIOUS';
            verdictBanner.style.background = '';
            verdictBanner.style.borderColor = '';
            verdictBanner.style.color = '';
        } else if (upperText.includes('CLASS AS SUSPICIOUS') || upperText.includes('VERDICT IS SUSPICIOUS')) {
            verdictBanner.className = 'verdict-banner unknown';
            verdictLabel.textContent = 'WARNING: SUSPICIOUS';
            verdictBanner.style.background = 'rgba(255, 193, 7, 0.2)';
            verdictBanner.style.borderColor = '#ffc107';
            verdictBanner.style.color = '#ffc107';
        } else if (upperText.includes('CLASS AS BENIGN') || upperText.includes('VERDICT IS BENIGN')) {
            verdictBanner.className = 'verdict-banner safe';
            verdictLabel.textContent = 'CLEAN: BENIGN';
            verdictBanner.style.background = '';
            verdictBanner.style.borderColor = '';
            verdictBanner.style.color = '';
        } else {
            // Fallback
            verdictBanner.className = 'verdict-banner unknown';
            verdictLabel.textContent = 'VERDICT: UNKNOWN / ANALYSIS FAILED';
            verdictBanner.style.background = '';
            verdictBanner.style.borderColor = '';
            verdictBanner.style.color = '';
        }

    } catch (e) {
        alert("Error fetching results");
        console.error(e);
    }
}

function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    document.querySelector(`.tab[onclick="switchTab('${tab}')"]`).classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
}

function resetApp() {
    progressContainer.classList.add('hidden');
    resultContainer.classList.add('hidden');
    emptyState.classList.remove('hidden');
    clearFile();
}

// LocalStorage helpers
function saveKeys() {
    localStorage.setItem('mobsf_key', mobsfKeyInput.value);
    localStorage.setItem('vt_key', vtKeyInput.value);
    localStorage.setItem('gemini_key', geminiKeyInput.value);
    localStorage.setItem('llm_provider', document.getElementById('llm-provider').value);
    localStorage.setItem('ollama_model', document.getElementById('ollama-model').value);
}

function loadKeys() {
    if (localStorage.getItem('mobsf_key')) mobsfKeyInput.value = localStorage.getItem('mobsf_key');
    if (localStorage.getItem('vt_key')) vtKeyInput.value = localStorage.getItem('vt_key');
    if (localStorage.getItem('gemini_key')) geminiKeyInput.value = localStorage.getItem('gemini_key');

    if (localStorage.getItem('llm_provider')) {
        document.getElementById('llm-provider').value = localStorage.getItem('llm_provider');
        toggleLLMFields();
    }

    if (localStorage.getItem('ollama_model')) document.getElementById('ollama-model').value = localStorage.getItem('ollama_model');
}
