let scannedTarget;
let currentScore;
let currentFindings;

document.getElementById("scanBtn").addEventListener("click", async () => {
  const url = document.getElementById("urlInput").value;

  if (!url) {
    alert("Please enter a URL");
    return;
  }
  const loadingDiv = document.getElementById("loading");
  const scanBtn = document.getElementById("scanBtn");

  // Show loader
  loadingDiv.style.display = "block";
  scanBtn.disabled = true;
  scanBtn.innerText = "Scanning...";
  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    scannedTarget = url;
    currentScore = data.score;
    currentFindings = data.findings;

    const scoreDiv = document.getElementById("score");
    const resultDiv = document.getElementById("results");
    const logsDiv = document.getElementById("logs");

    /* ==========================
    SECURITY SCORE SECTION
   ========================== */

    // Determine score color
    let scoreColor = "green";
    if (data.score < 75) scoreColor = "orange";
    if (data.score < 50) scoreColor = "red";

    // Risk badge color
    let riskColor = "#27ae60";
    if (data.riskLevel === "Medium Risk") riskColor = "#f39c12";
    if (data.riskLevel === "High Risk") riskColor = "#e74c3c";

    scoreDiv.innerHTML = `
  <div class="score-header">
      <div class="score-text" style="color:${scoreColor}">
          Security Score: ${data.score}/100
      </div>

      <div class="risk-badge" style="background-color:${riskColor}">
          ${data.riskLevel}
      </div>
  </div>

  <div class="summary-container">
      <div class="summary-box critical">Critical: ${data.summary.critical}</div>
      <div class="summary-box high">High: ${data.summary.high}</div>
      <div class="summary-box medium">Medium: ${data.summary.medium}</div>
      <div class="summary-box low">Low: ${data.summary.low}</div>
      <div class="summary-box info">Info: ${data.summary.info}</div>
  </div>
`;

    /* ==========================
       2️⃣ FINDINGS GRID SECTION
       ========================== */

    let findingsHtml = "";

    data.findings.forEach((f) => {
      findingsHtml += `
        <div class="card ${f.severity.toLowerCase()}">
          <b>${f.type}:</b> ${f.name}<br>
          <b>Status:</b> ${f.status}<br>
          <b>Severity:</b> ${f.severity}<br>
          <b>Impact:</b> ${f.impact}<br>
          <b>Fix:</b> ${f.fix}
        </div>
      `;
    });

    resultDiv.innerHTML = findingsHtml;
    /* ==========================
        3️⃣ RECENT SCANS SECTION
        ========================== */

    let logsHtml = "<h3>Recent Scans</h3>";

    if (data.logs && data.logs.length > 0) {
      data.logs.forEach((log) => {
        logsHtml += `
            <div>
                ${new Date(log.date).toLocaleString()} |
                ${log.url} |
                Score: ${log.score}
            </div>
            `;
      });
    } else {
      logsHtml += `<div>No recent scans available.</div>`;
    }

    logsDiv.innerHTML = logsHtml;
    document.getElementById("downloadBtn").style.display = "inline-block";
    // Hide loader
    loadingDiv.style.display = "none";
    scanBtn.disabled = false;
    scanBtn.innerText = "Scan";
  } catch (error) {
    alert("Error scanning the URL");
    console.error(error);
    loadingDiv.style.display = "none";
    scanBtn.disabled = false;
    scanBtn.innerText = "Scan";
  }
});
document.getElementById("downloadBtn").addEventListener("click", async () => {
  if (!scannedTarget || !currentFindings) {
    alert("Please run a scan before downloading report.");
    return;
  }

  const response = await fetch("/generate-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: scannedTarget,
      score: currentScore,
      findings: currentFindings,
    }),
  });

  if (!response.ok) {
    alert("Failed to generate report.");
    return;
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "Security_Report.pdf";
  document.body.appendChild(a);
  a.click();

  a.remove();
  window.URL.revokeObjectURL(url); // Clean memory
});
