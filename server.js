const express = require("express");
const axios = require("axios");
const cors = require("cors");
const path = require("path");
const PDFDocument = require("pdfkit");
const fs = require("fs");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

async function safeRequest(targetUrl) {
  try {
    return await axios.get(targetUrl, {
      timeout: 5000,
      maxRedirects: 3,
      validateStatus: () => true,
    });
  } catch (err) {
    return null;
  }
}

let scanHistory = [];

const securityHeaders = {
  "content-security-policy": {
    severity: "High",
    impact: "Prevents XSS, data injection and malicious resource loading.",
    fix: "Implement strong CSP like: default-src 'self'; object-src 'none'; frame-ancestors 'none';",
  },

  "strict-transport-security": {
    severity: "High",
    impact: "Forces browser to use HTTPS and prevents SSL stripping attacks.",
    fix: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },

  "x-content-type-options": {
    severity: "Medium",
    impact: "Prevents MIME-type sniffing which can lead to XSS.",
    fix: "Add: X-Content-Type-Options: nosniff",
  },

  "x-frame-options": {
    severity: "Medium",
    impact: "Prevents clickjacking attacks by blocking iframe embedding.",
    fix: "Add: X-Frame-Options: DENY (or use frame-ancestors in CSP)",
  },

  "referrer-policy": {
    severity: "Low",
    impact: "Prevents leaking sensitive URL data in Referer header.",
    fix: "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },

  "permissions-policy": {
    severity: "Low",
    impact: "Restricts access to browser APIs like camera, mic, geolocation.",
    fix: "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
  },

  "cross-origin-resource-policy": {
    severity: "Medium",
    impact: "Prevents other origins from loading your resources improperly.",
    fix: "Add: Cross-Origin-Resource-Policy: same-origin",
  },

  "cross-origin-opener-policy": {
    severity: "Medium",
    impact: "Protects against cross-origin attacks such as Spectre.",
    fix: "Add: Cross-Origin-Opener-Policy: same-origin",
  },

  "cross-origin-embedder-policy": {
    severity: "Medium",
    impact: "Enforces cross-origin isolation for advanced browser protections.",
    fix: "Add: Cross-Origin-Embedder-Policy: require-corp",
  },

  "x-permitted-cross-domain-policies": {
    severity: "Low",
    impact:
      "Prevents Adobe Flash and PDF files from making cross-domain requests.",
    fix: "Add: X-Permitted-Cross-Domain-Policies: none",
  },

  "cache-control": {
    severity: "Low",
    impact: "Prevents sensitive data from being cached by browsers or proxies.",
    fix: "For sensitive pages add: Cache-Control: no-store, no-cache",
  },
};

app.post("/scan", async (req, res) => {
  const { url } = req.body;

  if (!url || !url.startsWith("http")) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const response = await axios.get(url, {
      maxRedirects: 5,
      validateStatus: () => true,
    });

    const headers = Object.fromEntries(
      Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]),
    );

    let findings = [];
    let score = 100;

    // HTTPS check
    if (!url.startsWith("https://")) {
      findings.push({
        type: "Transport",
        name: "HTTPS Not Enforced",
        severity: "High",
        status: "Missing",
        impact: "Application is accessible over insecure HTTP.",
        fix: "Redirect HTTP to HTTPS and enable HSTS.",
      });
      score -= 20;
    } else {
      findings.push({
        type: "Transport",
        name: "HTTPS Enforcement",
        severity: "Info",
        status: "Present",
        impact: "Application is served securely over HTTPS.",
        fix: "No action required.",
      });
    }

    // Header checks
    Object.keys(securityHeaders).forEach((header) => {
      if (!headers[header]) {
        findings.push({
          type: "Header",
          name: header,
          severity: securityHeaders[header].severity,
          status: "Missing",
          impact: securityHeaders[header].impact,
          fix: securityHeaders[header].fix,
        });

        if (securityHeaders[header].severity === "High") score -= 15;
        if (securityHeaders[header].severity === "Medium") score -= 8;
        // Do NOT deduct for Low (treat as hardening)
        //if (securityHeaders[header].severity === "Low") score -= 4;
      } else {
        const value = headers[header];

        let weak = false;
        let weakReason = "";
        let recommendedFix = "No action required.";

        if (header === "content-security-policy") {
          if (
            value.includes("unsafe-inline") ||
            value.includes("unsafe-eval") ||
            value.includes("*")
          ) {
            weak = true;
            weakReason =
              "CSP contains unsafe directives (unsafe-inline / wildcard).";
            recommendedFix =
              "Remove unsafe-inline, unsafe-eval and avoid wildcard sources.";
          }
        }

        if (header === "strict-transport-security") {
          const maxAgeMatch = value.match(/max-age=(\d+)/);
          if (!maxAgeMatch || parseInt(maxAgeMatch[1]) < 31536000) {
            weak = true;
            weakReason = "HSTS max-age is too low or missing.";
            recommendedFix =
              "Set max-age to at least 31536000 and includeSubDomains.";
          }
        }

        if (header === "x-frame-options") {
          if (
            !value.toUpperCase().includes("DENY") &&
            !value.toUpperCase().includes("SAMEORIGIN")
          ) {
            weak = true;
            weakReason = "X-Frame-Options is not properly configured.";
            recommendedFix = "Use DENY or SAMEORIGIN.";
          }
        }

        if (header === "referrer-policy") {
          if (value === "no-referrer-when-downgrade") {
            weak = true;
            weakReason = "Referrer-Policy is outdated and less secure.";
            recommendedFix = "Use strict-origin-when-cross-origin.";
          }
        }

        if (header === "cache-control") {
          if (!value.includes("no-store") && !value.includes("no-cache")) {
            weak = true;
            weakReason = "Cache-Control does not prevent caching.";
            recommendedFix = "Use no-store for sensitive content.";
          }
        }

        if (weak) {
          findings.push({
            type: "Header",
            name: header,
            severity: "Medium",
            status: "Weak Configuration",
            impact: weakReason,
            fix: recommendedFix,
          });
          score -= 5;
        } else {
          findings.push({
            type: "Header",
            name: header,
            severity: "Info",
            status: "Properly Configured",
            impact: "Header exists and appears securely configured.",
            fix: "No action required.",
          });
        }
      }
    });
    // =============================
    // COOKIE SECURITY VALIDATION
    // =============================

    const setCookieHeaders = response.headers["set-cookie"];

    if (setCookieHeaders && setCookieHeaders.length > 0) {
      setCookieHeaders.forEach((cookie) => {
        const cookieName = cookie.split("=")[0];

        const hasSecure = cookie.toLowerCase().includes("secure");
        const hasHttpOnly = cookie.toLowerCase().includes("httponly");
        const sameSiteMatch = cookie.match(/samesite=(\w+)/i);

        let issues = [];
        let severity = "Low";

        if (!hasSecure) {
          issues.push("Missing Secure flag");
          severity = "Medium";
          score -= 5;
        }

        if (!hasHttpOnly) {
          issues.push("Missing HttpOnly flag");
          severity = "Medium";
          score -= 5;
        }

        if (!sameSiteMatch) {
          issues.push("Missing SameSite attribute");
          severity = "Medium";
          score -= 5;
        } else {
          const sameSiteValue = sameSiteMatch[1].toLowerCase();

          if (sameSiteValue === "none" && !hasSecure) {
            issues.push("SameSite=None without Secure flag");
            severity = "High";
            score -= 10;
          }

          if (
            sameSiteValue !== "strict" &&
            sameSiteValue !== "lax" &&
            sameSiteValue !== "none"
          ) {
            issues.push("Invalid SameSite value");
            severity = "Medium";
            score -= 5;
          }
        }

        if (issues.length > 0) {
          findings.push({
            type: "Cookie",
            name: cookieName,
            severity: severity,
            status: "Weak Configuration",
            impact: issues.join(", "),
            fix: "Ensure cookies use Secure, HttpOnly and SameSite=Strict or Lax.",
          });
        } else {
          findings.push({
            type: "Cookie",
            name: cookieName,
            severity: "Info",
            status: "Properly Configured",
            impact: "Cookie uses Secure, HttpOnly and SameSite correctly.",
            fix: "No action required.",
          });
        }
      });
    } else {
      findings.push({
        type: "Cookie",
        name: "No Cookies Set",
        severity: "Info",
        status: "No Cookies",
        impact: "Application does not set cookies in response.",
        fix: "No action required unless authentication is expected.",
      });
    }
    // =============================
    // SERVER INFORMATION DISCLOSURE CHECK
    // =============================

    const sensitiveHeaders = [
      "server",
      "x-powered-by",
      "x-aspnet-version",
      "x-runtime",
    ];

    sensitiveHeaders.forEach((h) => {
      if (headers[h]) {
        findings.push({
          type: "Information Disclosure",
          name: h,
          severity: "Low",
          status: "Exposed",
          impact: `Server reveals technology details: ${headers[h]}`,
          fix: "Remove or mask this header at web server or reverse proxy level.",
        });

        score -= 5;
      }
    });

    // =============================
    // OWASP MISCONFIGURATION CHECKS
    // =============================

    const baseUrl = url.endsWith("/") ? url.slice(0, -1) : url;

    // -------- 1. .git Exposure --------
    const gitCheck = await safeRequest(`${baseUrl}/.git/config`);
    if (
      gitCheck &&
      gitCheck.status === 200 &&
      typeof gitCheck.data === "string" &&
      gitCheck.data.includes("[core]")
    ) {
      findings.push({
        type: "Security Misconfiguration",
        name: ".git Repository Exposed",
        severity: "High",
        status: "Vulnerable",
        impact: "Source code repository is publicly accessible.",
        fix: "Block access to .git directory at web server level.",
      });
      score -= 20;
    }

    // -------- 2. .env Exposure --------
    const envCheck = await safeRequest(`${baseUrl}/.env`);
    if (
      envCheck &&
      envCheck.status === 200 &&
      typeof envCheck.data === "string" &&
      envCheck.data.includes("=") &&
      (envCheck.data.includes("DB_") || envCheck.data.includes("APP_"))
    ) {
      findings.push({
        type: "Security Misconfiguration",
        name: ".env File Exposed",
        severity: "Critical",
        status: "Vulnerable",
        impact:
          "Environment configuration file is publicly accessible and may leak secrets.",
        fix: "Block access to .env file immediately.",
      });
      score -= 25;
    }

    // -------- 3. Directory Listing --------
    const dirCheck = await safeRequest(`${baseUrl}/`);
    if (
      dirCheck &&
      dirCheck.status === 200 &&
      typeof dirCheck.data === "string" &&
      (dirCheck.data.includes("Index of /") ||
        dirCheck.data.includes("Parent Directory"))
    ) {
      findings.push({
        type: "Security Misconfiguration",
        name: "Directory Listing Enabled",
        severity: "Medium",
        status: "Vulnerable",
        impact: "Directory contents are publicly accessible.",
        fix: "Disable directory listing in web server configuration.",
      });
      score -= 15;
    }
    // =============================
    // BASELINE 404 BEHAVIOR CHECK
    // =============================

    const randomPath = `/nonexistent-${Date.now()}-test`;
    const baselineResponse = await safeRequest(`${baseUrl}${randomPath}`);

    let baselineStatus = null;
    let baselineLength = null;

    if (baselineResponse) {
      baselineStatus = baselineResponse.status;
      baselineLength = baselineResponse.data ? baselineResponse.data.length : 0;
    }
    // =============================
    // BACKUP FILE EXPOSURE CHECK (Improved)
    // =============================

    const backupFiles = [
      "/backup.zip",
      "/website.zip",
      "/db.sql",
      "/config.php.bak",
      "/index.php.old",
      "/app.bak",
    ];

    for (let file of backupFiles) {
      const response = await safeRequest(`${baseUrl}${file}`);

      if (response && response.status === 200) {
        const contentType = response.headers["content-type"] || "";
        const contentLength = response.data ? response.data.length : 0;

        const isDifferentFromBaseline =
          response.status !== baselineStatus ||
          Math.abs(contentLength - baselineLength) > 200;

        const looksLikeFile =
          contentType.includes("application") ||
          contentType.includes("octet-stream") ||
          contentType.includes("zip") ||
          contentType.includes("sql");

        if (isDifferentFromBaseline && looksLikeFile) {
          findings.push({
            type: "Security Misconfiguration",
            name: `Backup File Exposed (${file})`,
            severity: "High",
            status: "Vulnerable",
            impact:
              "Backup or sensitive file appears to be publicly accessible.",
            fix: "Remove backup files from production server immediately.",
          });

          score -= 15;
        }
      }
    }

    // =============================
    // PUBLIC INFORMATION FILES CHECK
    // =============================

    const infoFiles = [
      "/.well-known/security.txt",
      "/robots.txt",
      "/sitemap.xml",
      "/humans.txt",
    ];

    for (let file of infoFiles) {
      const fileCheck = await safeRequest(`${baseUrl}${file}`);
      if (fileCheck && fileCheck.status === 200) {
        findings.push({
          type: "Information Disclosure",
          name: `Public File Found (${file})`,
          severity: "Info",
          status: "Accessible",
          impact:
            "This public file is accessible. Review content to ensure no sensitive data is exposed.",
          fix: "Ensure file does not contain confidential information.",
        });
      } else {
        findings.push({
          type: "Best Practice",
          name: `Public File Missing (${file})`,
          severity: "Info",
          status: "Not Found",
          impact: "Recommended public file not found.",
          fix: "Consider adding this file if applicable.",
        });
      }
    }

    if (score < 0) score = 0;

    // =============================
    // RISK CLASSIFICATION
    // =============================

    let riskLevel = "Low Risk";

    if (score < 50) {
      riskLevel = "High Risk";
    } else if (score < 75) {
      riskLevel = "Medium Risk";
    }

    // Optional: severity summary
    const summary = {
      critical: findings.filter((f) => f.severity === "Critical").length,
      high: findings.filter((f) => f.severity === "High").length,
      medium: findings.filter((f) => f.severity === "Medium").length,
      low: findings.filter((f) => f.severity === "Low").length,
      info: findings.filter((f) => f.severity === "Info").length,
    };

    const scanResult = {
      url,
      score,
      findings,
      timestamp: new Date().toLocaleString(),
    };

    scanHistory.unshift({
      date: new Date(),
      url,
      score,
    });

    // keep only last 20 scans
    if (scanHistory.length > 20) {
      scanHistory.pop();
    }

    res.json({
      score,
      riskLevel,
      summary,
      findings,
      logs: scanHistory,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to scan target." });
  }
});
// =============================
// PDF REPORT GENERATION (STREAM VERSION)
// =============================
app.post("/generate-report", (req, res) => {
  const { target, score, findings } = req.body;

  const doc = new PDFDocument({ margin: 50 });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    "attachment; filename=Web_Baseline_Security_Report.pdf",
  );

  doc.pipe(res);

  // =============================
  // COLORS
  // =============================
  const severityColors = {
    Critical: "#B71C1C",
    High: "#D32F2F",
    Medium: "#F57C00",
    Low: "#FBC02D",
    Info: "#1976D2",
  };

  // =============================
  // HEADER SECTION
  // =============================
  doc
    .fontSize(22)
    .fillColor("#111111")
    .text("Web Baseline Security Assessment Report", {
      align: "center",
    });

  doc.moveDown(1);

  doc
    .fontSize(12)
    .fillColor("#444444")
    .text(`Target Application: ${target}`)
    .text(`Scan Date: ${new Date().toLocaleString()}`)
    .text(`Security Score: ${score}/100`)
    .moveDown();

  // Risk classification
  let riskLevel = "Low Risk";
  let riskColor = "#2E7D32";

  if (score < 50) {
    riskLevel = "High Risk";
    riskColor = "#C62828";
  } else if (score < 75) {
    riskLevel = "Medium Risk";
    riskColor = "#EF6C00";
  }

  doc
    .fontSize(14)
    .fillColor(riskColor)
    .text(`Overall Risk Level: ${riskLevel}`)
    .moveDown(2);

  // Divider
  doc
    .moveTo(50, doc.y)
    .lineTo(550, doc.y)
    .strokeColor("#cccccc")
    .stroke()
    .moveDown();

  // =============================
  // SUMMARY SECTION
  // =============================
  const summary = {
    Critical: findings.filter((f) => f.severity === "Critical").length,
    High: findings.filter((f) => f.severity === "High").length,
    Medium: findings.filter((f) => f.severity === "Medium").length,
    Low: findings.filter((f) => f.severity === "Low").length,
    Info: findings.filter((f) => f.severity === "Info").length,
  };

  doc
    .fontSize(16)
    .fillColor("#000000")
    .text("Findings Summary", { underline: true })
    .moveDown();

  Object.keys(summary).forEach((level) => {
    doc
      .fontSize(12)
      .fillColor(severityColors[level])
      .text(`${level}: ${summary[level]}`);
  });

  doc.moveDown(2);

  // =============================
  // DETAILED FINDINGS
  // =============================
  doc
    .fontSize(16)
    .fillColor("#000000")
    .text("Detailed Findings", { underline: true })
    .moveDown();

  findings.forEach((finding, index) => {
    // Add page break automatically
    if (doc.y > 700) {
      doc.addPage();
    }

    doc
      .fontSize(13)
      .fillColor("#000000")
      .text(`${index + 1}. ${finding.name}`, {
        continued: false,
      });

    doc
      .fontSize(11)
      .fillColor(severityColors[finding.severity] || "#000000")
      .text(`Severity: ${finding.severity}`);

    doc.fontSize(11).fillColor("#333333").text(`Impact: ${finding.impact}`);

    doc.fontSize(11).fillColor("#2E7D32").text(`Remediation: ${finding.fix}`);

    doc.moveDown();
  });

  // =============================
  // FOOTER
  // =============================
  doc.moveDown(2);

  doc
    .fontSize(9)
    .fillColor("#777777")
    .text(
      "Generated by Web Baseline Security Scanner | Developed by Akshay Salunke",
      { align: "center" },
    );

  doc.end();
});

app.get("/dashboard", (req, res) => {
  res.json(scanHistory);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
