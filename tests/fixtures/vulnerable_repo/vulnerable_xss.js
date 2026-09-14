// Vulnerable XSS innerHTML injection
function renderUserProfile(userData) {
    const container = document.getElementById("profile-display");
    // Flaw: RULE_A03_XSS_INNERHTML
    container.innerHTML = "<h3>User: " + userData.name + "</h3>";
}
