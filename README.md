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
 - Reddit
### Domains
 - Virustotal
 - Alienvault
 - Twitter
 - Reddit
### URLs
 - Virustotal
 - Twitter
 - Reddit
### MD5 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter
 - Reddit
### SHA1 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter
 - Reddit
### SHA256 hashes
 - Virustotal
 - Alienvault
 - THREATfox
 - Twitter
 - Reddit

### Example output for an ip address:
<img width="555" alt="Bildschirmfoto 2022-05-13 um 14 45 16" src="https://user-images.githubusercontent.com/44299200/168286279-5069258a-3063-44d7-9d91-50e88eb7a10d.png">


### Example output for a hashes:
![iaca_reddit](https://user-images.githubusercontent.com/44299200/168870372-909c1ef3-81be-4198-9606-bd9d075a2ef3.png)
![ioca_twitter](https://user-images.githubusercontent.com/44299200/168870377-6829c754-2397-4250-9300-9b2a47b3f0b3.png)


For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com
- https://developer.twitter.com
- https://www.reddit.com/prefs/apps
