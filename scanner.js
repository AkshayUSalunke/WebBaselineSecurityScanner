const axios = require("axios");

async function scanWebsite(url) {
    console.log("Starting Security Scan...");
    console.log("Target:", url);
    console.log("--------------------------------");

    try {
        const response = await axios.get(url);

        const headers = response.headers;

        const checks = [
            "x-frame-options",
            "x-xss-protection",
            "x-content-type-options",
            "strict-transport-security",
            "content-security-policy"
        ];

        checks.forEach(header => {
            if (headers[header]) {
                console.log(`✔ ${header} is present`);
            } else {
                console.log(`✘ ${header} is missing`);
            }
        });

    } catch (error) {
        console.log("Error scanning site:", error.message);
    }
}

const target = process.argv[2];

if (!target) {
    console.log("Usage: node scanner.js <website_url>");
    process.exit();
}

scanWebsite(target);