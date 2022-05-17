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
![ioca_ip](https://user-images.githubusercontent.com/44299200/168872804-4e485af3-171f-4e58-8c3c-fecbec3208d8.png)



### Example output for a hashes:
![ioca_reddit](https://user-images.githubusercontent.com/44299200/168872781-6489932d-9a46-4503-8089-c5792d209e95.png)
![ioca_twitter](https://user-images.githubusercontent.com/44299200/168872786-ef3c2a87-282b-4145-8350-b1831673b21b.png)



For this tool to work properly, you need to register on the following services and generate API keys:
- https://virustotal.com
- https://otx.alienvault.com
- https://www.abuseipdb.com
- https://threatfox.abuse.ch
- https://www.ipqualityscore.com
- https://maltiverse.com
- https://developer.twitter.com
- https://www.reddit.com/prefs/apps
