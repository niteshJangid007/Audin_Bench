// Vulnerable SSRF outbound fetch
const axios = require("axios");

async function fetchWebhook(req, res) {
    // Flaw: RULE_A10_UNVALIDATED_FETCH
    const response = await axios.get(req.query.targetUrl);
    res.json(response.data);
}
