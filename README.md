# MD5 Header Updater Burp Extension.

This Burp Extension hashes the request body and places the hash into a header.  Currently it is using MD5, but this can be changed to SHA-1 or SHA-256.  The modified responses aren't displayed in the Proxy History but will show up in Flow or Logger++.

## Sample request

```POST / HTTP/1.1
Host: localhost
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Hash: 05a671c66aefea124cc08b76ea6d30bb

testtest
```

## License
[MIT](https://choosealicense.com/licenses/mit/)