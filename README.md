# IoC analyzer

Tool to analyze IoCs with various APIs. Prints a detailed report and a summary table on the cli.
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
 - Twitter
### Domains
 - Virustotal
 - Alienvault
 - Twitter
### URLs
 - Virustotal
 - Twitter
### MD5 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter
### SHA1 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter
### SHA256 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter

### Example output for an ip address:
![ioc_analyzer_ip](https://user-images.githubusercontent.com/44299200/164914835-2a94df99-9754-4866-b1d1-59915b953665.png)

### Example output for a hash:
<img width="813" alt="Bildschirmfoto 2022-05-13 um 13 48 55" src="https://user-images.githubusercontent.com/44299200/168277208-960c7d5e-fcde-459e-b279-4fcdad2e5001.png">


For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com
- https://developer.twitter.com
