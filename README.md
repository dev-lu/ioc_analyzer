# IoC analyzer

Tool to check IoCs against various APIs. Prints a detailed report and a summary table on the cli.
IoC type is detected automatically.
Supported IoC types and their implemented services:
### IP addresses
 - AbuseIPDB
 - IPQualityScore
 - Virustotal
 - Alienvault
 - Blocklist.de
 - THREATfox (abuse.ch)
 - Maltiverse
### Domains
 - Virustotal
 - Alienvault
### URLs
 - Virustotal
### MD5 hashes
 - Virustotal
 - Alienvault
 - THREATfox
### SHA1 hashes
 - Virustotal
 - Alienvault
 - THREATfox
### SHA256 hashes
 - Virustotal
 - Alienvault
 - THREATfox

### Example output for an ip address:
![ioc_analyzer_ip](https://user-images.githubusercontent.com/44299200/164914835-2a94df99-9754-4866-b1d1-59915b953665.png)

### Example output for a hash:
![ioc_analyzer](https://user-images.githubusercontent.com/44299200/164914795-9a7a879e-c38c-4526-9d69-3cae6106ec73.png)



For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com


