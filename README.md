# IoC analyzer

Tool to analyze IoCs with various OSINT APIs. Prints a detailed report and a summary table on the cli.
IoC type is detected automatically.
## Supported IoC types and implemented services:
### IP addresses
 - AbuseIPDB
 - IPQualityScore
 - Virustotal
 - Alienvault
 - Blocklist.de
 - THREATfox (abuse.ch)
 - Maltiverse
 - Shodan
 - Twitter
 - Reddit
### Domains
 - Virustotal
 - Alienvault
 - Google Safe Browsing
 - Shodan
 - Twitter
 - Reddit
### URLs
 - Virustotal
 - Google Safe Browsing
 - URLhaus (abuse.ch)
 - Twitter
 - Reddit
### MD5 hashes
 - Virustotal
 - Alienvault
 - THREATfox (abuse.ch)
 - MALWAREbazaar (abuse.ch)
 - Twitter
 - Reddit
### SHA1 hashes
 - Virustotal
 - Alienvault
 - THREATfox (abuse.ch)
 - MALWAREbazaar (abuse.ch)
 - Twitter
 - Reddit
### SHA256 hashes
 - Virustotal
 - Alienvault
 - THREATfox (abuse.ch)
 - MALWAREbazaar (abuse.ch)
 - Twitter
 - Reddit

### Example output for an ip address:
![ioca_ip](https://user-images.githubusercontent.com/44299200/168872804-4e485af3-171f-4e58-8c3c-fecbec3208d8.png)



### Example output for hashes:
![ioca_sha1](https://user-images.githubusercontent.com/44299200/172066106-01a0a97d-f411-46e4-bdf1-f94a2b61e82a.png)
![ioca_twitter](https://user-images.githubusercontent.com/44299200/168872786-ef3c2a87-282b-4145-8350-b1831673b21b.png)



For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com
- https://console.cloud.google.com/apis/credentials
- https://developer.twitter.com
- https://www.reddit.com/prefs/apps
