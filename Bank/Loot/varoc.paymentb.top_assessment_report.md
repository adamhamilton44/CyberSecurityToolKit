Security Assessment Report
**Target:** varoc.paymentb.top
**Date:** Sun Jan 19 17:26:29 CST 2025

------------------------

## Information Gathering
The queried object does not exist: varoc.paymentb.top
>>> Last update of WHOIS database: 2025-01-19T23:20:18Z <<<

Status Codes: For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in ZDNS Global Registry
Services' ("ZDNS") Whois database is provided by ZDNS for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. ZDNS does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to ZDNS (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of ZDNS. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. ZDNS reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  ZDNS may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. ZDNS
reserves the right to modify these terms at any time.

---

Server:		192.168.40.1
Address:	192.168.40.1#53

Non-authoritative answer:
Name:	varoc.paymentb.top
Address: 172.67.163.156
Name:	varoc.paymentb.top
Address: 104.21.10.150
Name:	varoc.paymentb.top
Address: 2606:4700:3033::6815:a96
Name:	varoc.paymentb.top
Address: 2606:4700:3037::ac43:a39c


---


; <<>> DiG 9.20.4-3-Debian <<>> varoc.paymentb.top ANY
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 21379
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;varoc.paymentb.top.		IN	ANY

;; Query time: 11 msec
;; SERVER: 192.168.40.1#53(192.168.40.1) (TCP)
;; WHEN: Sun Jan 19 17:26:29 CST 2025
;; MSG SIZE  rcvd: 47


---

## Vulnerability Testing
# Nmap 7.95 scan initiated Sun Jan 19 17:26:47 2025 as: /usr/lib/nmap/nmap -sV --script=vuln -oN nmap_vuln_scan.txt varoc.paymentb.top
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for varoc.paymentb.top (104.21.10.150)
Host is up (0.016s latency).
Other addresses for varoc.paymentb.top (not scanned): 172.67.163.156 2606:4700:3037::ac43:a39c 2606:4700:3033::6815:a96
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Cloudflare http proxy
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: cloudflare
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
443/tcp  open  ssl/http Cloudflare http proxy
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: cloudflare
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-enum: 
|   /robots.txt: Robots file
|   /manifest.json: Manifest JSON File
|   /0/: Potentially interesting folder
|_  /index/: Potentially interesting folder
8080/tcp open  http     Cloudflare http proxy
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: cloudflare
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
8443/tcp open  ssl/http Cloudflare http proxy
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: cloudflare

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 19 17:33:30 2025 -- 1 IP address (1 host up) scanned in 403.54 seconds
## Web Application Analysis
- Nikto v2.5.0/
+ Target Host: varoc.paymentb.top
+ Target Port: 80
+ GET /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options: 
+ GET /: Uncommon header 'server-timing' found, with contents: cfL4;desc="?proto=TCP&rtt=11729&min_rtt=10955&rtt_var=3679&sent=3&recv=6&lost=0&retrans=0&sent_bytes=2074&recv_bytes=591&delivery_rate=132177&cwnd=247&unsent_bytes=0&cid=0000000000000000&ts=0&x=0".
+ GET /: An alt-svc header was found which is advertising HTTP/3. The endpoint is: ':443'. Nikto cannot test HTTP/3 over QUIC. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/alt-svc: 
+ GET /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/: 
+ GET /cdn-cgi/trace: Retrieved access-control-allow-origin header: *.
+ GET /cdn-cgi/trace: Cloudflare trace CGI found, which may leak some system information.
[1m[34mhttp://varoc.paymentb.top[0m [301 Moved Permanently] [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mHTTPServer[0m[[1m[36mcloudflare[0m], [1mIP[0m[[0m[22m172.67.163.156[0m], [1mRedirectLocation[0m[[0m[22mhttps://varoc.paymentb.top/[0m], [1mTitle[0m[[1m[33m301 Moved Permanently[0m], [1mUncommonHeaders[0m[[0m[22mreport-to,nel,cf-ray,alt-svc,server-timing[0m]
[1m[34mhttps://varoc.paymentb.top/[0m [200 OK] [1mAccess-Control-Allow-Methods[0m[[0m[22mGET, POST, OPTIONS, DELETE[0m], [1mCookies[0m[[0m[22mPHPSESSID[0m], [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mHTML5[0m, [1mHTTPServer[0m[[1m[36mcloudflare[0m], [1mIP[0m[[0m[22m172.67.163.156[0m], [1mScript[0m, [1mUncommonHeaders[0m[[0m[22maccess-control-allow-origin,access-control-allow-methods,access-control-allow-headers,cf-cache-status,report-to,nel,cf-ray,alt-svc,server-timing[0m], [1mX-UA-Compatible[0m[[0m[22mIE=edge[0m]
## Database Assessment
SQLMap results saved to /home/adam/Documents/Github/CyberSecurityToolKit/Bank/Loot/sqlmap_results directory.
