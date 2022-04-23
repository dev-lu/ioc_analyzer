# IoC analyzer

Tool to check IoCs against various APIs. Prints a detailed report and a summary table on the cli.
IoC type is detected automatically.
Supported IoC types and their implemented services:
- IP addresses
 - AbuseIPDB
 - IPQualityScore
 - Virustotal
 - Alienvault
 - Blocklist.de
 - THREATfox (abuse.ch)
 - Maltiverse
- Domains
 - Virustotal
 - Alienvault
- URLs
 - Virustotal
- MD5 hashes
 - Virustotal
 - Alienvault
 - THREATfox
- SHA1 hashes
 - Virustotal
 - Alienvault
 - THREATfox
- SHA256 hashes
 - Virustotal
 - Alienvault
 - THREATfox

<img width="722" alt="ioc_analyser" src="https://user-images.githubusercontent.com/44299200/164659861-2c5ea5dd-0b45-4283-adfa-f8a8fdce699a.png">

![ioc_analyzer](https://user-images.githubusercontent.com/44299200/164914795-9a7a879e-c38c-4526-9d69-3cae6106ec73.png)



For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com


