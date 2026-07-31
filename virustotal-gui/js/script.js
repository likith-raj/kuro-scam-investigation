const API_URL = 'http://localhost:5000/analyze'; 
const urlInput = document.getElementById('urlInput'); 
const analyzeBtn = document.getElementById('analyzeBtn'); 
const resultsDiv = document.getElementById('results'); 
const loadingDiv = document.getElementById('loading'); 
const maliciousCount = document.getElementById('maliciousCount'); 
const suspiciousCount = document.getElementById('suspiciousCount'); 
const cleanCount = document.getElementById('cleanCount'); 
const totalCount = document.getElementById('totalCount'); 
const verdictText = document.getElementById('verdictText'); 
const vendorBody = document.getElementById('vendorBody'); 
const sampleBtns = document.querySelectorAll('.sample-btn'); 
analyzeBtn.addEventListener('click', analyzeUrl); 
urlInput.addEventListener('keypress', (e) = if (e.key === 'Enter') analyzeUrl(); }); 
sampleBtns.forEach(btn = btn.addEventListener('click', () = urlInput.value = btn.dataset.url; analyzeUrl(); }); }); 
async function analyzeUrl() { 
    const url = urlInput.value.trim(); 
    if (!url) { alert('Please enter a URL or hash to analyze.'); return; } 
    resultsDiv.style.display = 'block'; 
    loadingDiv.classList.remove('hidden'); 
    vendorBody.innerHTML = ''; 
    document.getElementById('summaryCards').style.opacity = '0.3'; 
    try { 
        const response = await fetch(API_URL, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ url: url }) 
        }); 
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`); 
        const data = await response.json(); 
        displayResults(data); 
    } catch (error) { 
        console.error('Error:', error); 
        alert('Error analyzing URL. Please check the backend server.'); 
        loadingDiv.classList.add('hidden'); 
        document.getElementById('summaryCards').style.opacity = '1'; 
    } 
} 
function displayResults(data) { 
    loadingDiv.classList.add('hidden'); 
    document.getElementById('summaryCards').style.opacity = '1'; 
    const verdictColors = { 'Malicious': '#ff4757', 'Suspicious': '#ffa502', 'Clean': '#2ed573', 'Unknown': '#6c5ce7' }; 
    verdictText.textContent = verdict; 
    vendorBody.innerHTML = ''; 
    for (const [vendor, result] of Object.entries(vendors)) { 
        const row = document.createElement('tr'); 
        const vendorCell = document.createElement('td'); 
        vendorCell.textContent = vendor; 
        const resultCell = document.createElement('td'); 
        const badge = document.createElement('span'); 
        badge.className = `result-badge ${result.toLowerCase()}`; 
        badge.textContent = result; 
        resultCell.appendChild(badge); 
        row.appendChild(vendorCell); 
        row.appendChild(resultCell); 
        vendorBody.appendChild(row); 
    } 
