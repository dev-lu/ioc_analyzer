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
<img width="555" alt="Bildschirmfoto 2022-05-13 um 14 45 16" src="https://user-images.githubusercontent.com/44299200/168286279-5069258a-3063-44d7-9d91-50e88eb7a10d.png">


### Example output for a hash:
<img width="779" alt="Bildschirmfoto 2022-05-13 um 13 50 29" src="https://user-images.githubusercontent.com/44299200/168277450-d882b06d-9514-49b8-9d11-1dff2043d903.png">


For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com
- https://developer.twitter.com
