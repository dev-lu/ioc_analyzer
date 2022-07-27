#==============================================
# Tool to check IoCs againt various threat intelligences.
# IoC type will be detected automatically.
# Implmented services: AbuseIPDB, IPQualityScore, Alienvault, Virustotal, THREATfox, URLhaus, MALWAREbazaar, Blocklist.de, Maltiverse, Twitter, Reddit
# Author: https://github.com/dev-lu
#==============================================
from datetime import datetime
from decouple import config, RepositoryEnv
from colorama import Fore, Back, Style
from prettytable import PrettyTable
from pprint import pprint
import requests
import base64
import json
import re

requests.packages.urllib3.disable_warnings()  # Disable SSL warning

ioc = str(input('Enter IoC:\n')).strip()

table           = PrettyTable()
table.header    = True
table.title     = f"{Style.BRIGHT} - Result summary - {Style.RESET_ALL}"
# Colors for table
green   = Back.GREEN    + "     " + Style.RESET_ALL
red     = Back.RED      + "     " + Style.RESET_ALL
yellow  = Back.YELLOW   + "     " + Style.RESET_ALL
white   = Back.WHITE    + "     " + Style.RESET_ALL
black   = Back.BLACK    + "     " + Style.RESET_ALL


def abuseipdb_ip_check(ip, apikey):
    apikey      = apikey
    url         = "https://api.abuseipdb.com/api/v2"
    endpoint    = "/check"
    
    headers = {
        'Accept': 'application/json',
        'Key': apikey
        }
    
    querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '365'
            }
    
    response        = requests.get(url = url + endpoint, headers = headers, params = querystring)
    response_json   = json.loads(response.text)
    
    if response.status_code == 429:
        print("\n========== AbuseIPDB results ==========\n")
        print("API limit exceeded")
        table.add_row(["AbuseIPDB", "API limit exceeded", black])
        
    elif response.status_code == 200:
        print("\n========== AbuseIPDB results ==========\n")
        print("IP: " + str(response_json["data"]["ipAddress"]))
        print("Domain: " + str(response_json["data"]["domain"]))
        print("Hostnames: " + str(response_json["data"]["hostnames"]))
        print("Malicious: " + str(response_json["data"]["abuseConfidenceScore"]) + "%")
        print("Number of reports: " + str(response_json["data"]["totalReports"]))
        print("Country: " + str(response_json["data"]["countryCode"]))
        print("ISP: " + str(response_json["data"]["isp"]))
        print("Type: " + str(response_json["data"]["usageType"]))
        print("Last reported: " + str(response_json["data"]["lastReportedAt"]))
        #print("\n" + "========================" + "\n")
        
        global abuseipdb_score, abuseipdb_reports, ip_country, ip_type, ip_isp
        ip_country          = str(response_json["data"]["countryCode"])
        ip_type             = str(response_json["data"]["usageType"])
        ip_isp              = str(response_json["data"]["isp"])
        abuseipdb_score     = str(response_json["data"]["abuseConfidenceScore"])
        abuseipdb_reports   = str(response_json["data"]["totalReports"])
        message             = f"{abuseipdb_score}% malicious - {abuseipdb_reports} report(s)"
        
        if int(abuseipdb_score)<1:      table.add_row(["AbuseIPDB", message, green])
        elif int(abuseipdb_score)<80:   table.add_row(["AbuseIPDB", message, yellow])
        elif int(abuseipdb_score)>79:   table.add_row(["AbuseIPDB", message, red])
        else:                           table.add_row(["AbuseIPDB", "Error", white])
        
    else :
        print("Error while checking for AbuseIPDB results:")
        print(response.content)


def alienvaultotx(ioc, endpoint, apikey):
    url     = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{ioc}"
    apikey  = apikey
    
    headers = {
        "X-OTX-API-Key": apikey
    }
    
    response        = requests.get(url = url, headers = headers)
    response_json   = json.loads(response.text)
    
    global alienvault_score
    alienvault_score = str(response_json["pulse_info"]["count"])
    
    if response.status_code == 200:
        print("\n\n========== Alienvault results ==========\n")
        print("Alienvault Pulses: " + str(response_json["pulse_info"]["count"]))
        if response_json["pulse_info"]["count"] > 0:
            for pulses in range(len(response_json["pulse_info"]["pulses"])):
                print("Pulse " + str(pulses) + ": " + response_json["pulse_info"]["pulses"][pulses]["name"])
        
        message = f"Pulses: {alienvault_score}"
        
        if int(alienvault_score)<1:     table.add_row(["Alienvault", message, green])
        elif int(alienvault_score)>0:   table.add_row(["Alienvault", message, red])
        else:                           table.add_row(["Alienvault", "Error", white])
    
    else :
        print("Error while checking for Alienvault results:")
        print(response.content)


def virustotal(ioc, endpoint, apikey):
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {
        "x-apikey": apikey
    }
    
    response        = requests.get(url = url, headers = headers)
    response_json   = json.loads(response.text)
    
    global virustotal_score
    virustotal_score = str(response_json["data"]["attributes"]["last_analysis_stats"]["malicious"])
    
    if response.status_code == 429:
        print("\n\n========== Virustotal results ==========\n")
        print("API limit exceeded")
        table.add_row([
            "Virustotal", 
            "API limit exceeded", 
            black
        ])
    
    elif response.status_code == 200:
        print("\n\n========== Virustotal results ==========\n")
        print("Harmless: " + str(response_json["data"]["attributes"]["last_analysis_stats"]["harmless"]))
        print("Malicious: " + str(response_json["data"]["attributes"]["last_analysis_stats"]["malicious"]))
        print("Suspicious: " + str(response_json["data"]["attributes"]["last_analysis_stats"]["suspicious"]))
        print("Unknown: " + str(response_json["data"]["attributes"]["last_analysis_stats"]["undetected"]))
        print("Timeout: " + str(response_json["data"]["attributes"]["last_analysis_stats"]["timeout"]))
        #print("\n" + "========================" + "\n")
        
        message = f"Identified as malicious by {virustotal_score} Services."
        
        if int(virustotal_score)<1:     table.add_row(["Virustotal", message, green])
        elif int(virustotal_score)<2:   table.add_row(["Virustotal", message, yellow])
        elif int(virustotal_score)>1:   table.add_row(["Virustotal", message, red])
        else:                           table.add_row(["Virustotal", "Error", white])
    
    else :
        print("Error while checking for Virustotal results:")
        print(response.content)


def ipqualityscore_ip_check(ip, apikey):
    endpoint        = f"https://ipqualityscore.com/api/json/ip/{apikey}/{ip}"
    response        = requests.get(url = endpoint)
    response_json   = json.loads(response.text)
    
    global ipqualityscore_score, is_proxy, is_vpn, is_tor
    is_proxy                = str(response_json["proxy"])
    is_vpn                  = str(response_json["vpn"])
    is_tor                  = str(response_json["tor"])
    ipqualityscore_score    = str(response_json["fraud_score"])
    
    message = f"{ipqualityscore_score}% malicious"
    
    if response_json["success"] and response.status_code == 200:
        if int(ipqualityscore_score)<1:     table.add_row(["IPQualityScore", message, green])
        elif int(ipqualityscore_score)<90:  table.add_row(["IPQualityScore", message, yellow])
        elif int(ipqualityscore_score)>89:  table.add_row(["IPQualityScore", message, red])
    else:                                   table.add_row(["IPQualityScore", "Error", white])


def blocklist_de_ip_check(ip):
    url         = "http://api.blocklist.de/api.php?"
    endpoint    = "ip="
    
    response     = requests.get(url=url + endpoint + ip)
    result      = response.text.replace("<br />", " ")
    attacks     = re.search('attacks: (\d+)', result).group(1)
    reports     = re.search('reports: (\d+)', result).group(1)
    result_dict = {
        "attacks": attacks,
        "reports": reports
    }
    
    global blocklist_attacks
    global blocklist_reports
    blocklist_attacks = result_dict["attacks"]
    blocklist_reports = result_dict["reports"]
    
    message = f"Attacks: {blocklist_attacks} - Reports: {blocklist_reports}"
    
    if response.status_code == 200:
        if int(blocklist_attacks)<1 and int(blocklist_reports)<1:   table.add_row(["Blocklist.de", message, green])
        else:                                                       table.add_row(["Blocklist.de", message, red])
    
    else:
        print("Error while checking for Blocklist.de results:")
        print(response.text)


def threatfox_ip_check(ip, apikey):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "API-KEY": apikey
    }
    
    payload = {
        "query": "search_ioc",
        "search_term": ip
    }
    
    payload_json    = json.dumps(payload)
    response        = requests.post(url = url, headers = headers, data = payload_json)
    response_json   = json.loads(response.text)
    
    global threatfox_status
    global threatfox_result
    threatfox_status = response_json["query_status"]
    threatfox_result = response_json
    
    if response.status_code == 200:
        if threatfox_status == "no_result":
            table.add_row([
                "THREATfox (abuse.ch):",
                "No results",
                green
            ])
        elif threatfox_status == "ok":
            table.add_row([
                "THREATfox (abuse.ch): ", 
                str(threatfox_result["data"][0]["threat_type_desc"]) + "\nConfidence: " + str(threatfox_result["data"][0]["confidence_level"]) + "%", 
                f"{red}\n{red}"
            ])
        else:
            table.add_row([
                "THREATfox (abuse.ch): ", 
                "Error", 
                white
            ])
    else:
        print("Error while checking for THREATfox results: ")
        print(response.text)


def urlhaus_url_check(ioc):
    url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {
        'url': ioc
    }
    response = requests.post(url=url, data=data)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            table.add_row(["URLhaus (abuse.ch)", "Malicious", red])
            print("\n\n========== URLhaus results ==========\n")
            print("Result ID: " + str(json_response['id']))
            print("Status: " + str(json_response['url_status']))
            print("Host: " + str(json_response['host']))
            print("Date added: " + str(json_response['date_added']))
            print("Last online: " + str(json_response['last_online']))
            print("Threat: " + str(json_response['threat']))
            print("Blacklists: ")
            pprint(json_response['blacklists'])
            print("Tags: ")
            pprint(json_response['tags'])
            print("Payloads: ")
            pprint(json_response['payloads'])
        elif json_response['query_status'] == 'no_results':
            print("\n\n========== URLhaus results ==========\n")
            table.add_row(["URLhaus (abuse.ch)", "No results", green])
            print("No results")
        else:
            print("\n\n========== URLhaus results ==========\n")
            print("URLhaus error")
            print(response.text)
    else: 
        print("URLhaus error")
        print(response.status_code)
        print(response.text)


def malwarebazaar_hash_check(ioc):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        'query': 'get_info', 
        'hash': ioc
        }
    response = requests.post(url=url, data=data)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            table.add_row(["MALWAREbazaar (abuse.ch)", "Malicious", red])
            print("\n\n========== MALWAREbazaar results ==========\n")
            print("MD5 hash: " + str(json_response['data'][0]['md5_hash']))
            print("SHA1 hash: " + str(json_response['data'][0]['sha1_hash']))
            print("SHA256 hash: " + str(json_response['data'][0]['sha256_hash']))
            print("SHA3-384 hash: " + str(json_response['data'][0]['sha3_384_hash']))
            print("ImpHash: " + str(json_response['data'][0]['imphash']))
            print("Trend Micro Locality Sensitive Hash: " + str(json_response['data'][0]['tlsh']))
            print("Trend Micro ELF Hash: " + str(json_response['data'][0]['telfhash']))
            print("Fuzzy hash (ssdeep): " + str(json_response['data'][0]['ssdeep']))
            print("File type: " + str(json_response['data'][0]['file_type']))
            print("\nOrigin country: " + str(json_response['data'][0]['origin_country']))
            print("\nTags: ")
            pprint(json_response['data'][0]['tags'])
            print("\nIntelligence: ")
            pprint(json_response['data'][0]['intelligence'])
            print("\nFile information: ")
            pprint(json_response['data'][0]['file_information'])
            print("\nYara rules: ")
            pprint(json_response['data'][0]['yara_rules'])
            print("\nVendor intelligence: ")
            pprint(json_response['data'][0]['vendor_intel'])
        elif json_response['query_status'] == 'no_results':
            print("\n\n========== MALWAREbazaar results ==========\n")
            table.add_row(["MALWAREbazaar (abuse.ch)", "No results", green])
            print("No results")
        else:
            print("\n\n========== MALWAREbazaar results ==========\n")
            print("Something went wrong")
            print(response.text)
    else: 
        print("MALWAREbazaar error")
        print(response.status_code)
        print(response.text)


def maltiverse_ip_check(ip, apikey):
    headers = {
        'Authorization': f'Bearer {apikey}'
    }
    
    url             = "https://api.maltiverse.com/ip/"
    response        = requests.get(url=f"{url}{ip}", headers=headers)
    response_json   = json.loads(response.text)
    
    global maltiverse_classification, maltiverse_is_cdn, maltiverse_is_cnc, maltiverse_is_distributing_malware, maltiverse_is_hosting
    global maltiverse_is_known_attacker, maltiverse_is_known_scanner, maltiverse_is_mining_pool, maltiverse_is_open_proxy
    global maltiverse_is_sinkhole, maltiverse_is_tor_node, maltiverse_is_vpn_node
    
    if response.status_code == 429:
        print("\n\n========== Maltiverse results ==========\n")
        print("API limit exceeded")
        table.add_row([
            "Maltiverse", 
            "API limit exceeded", 
            black
        ])
    
    elif response.status_code == 200:
        print("\n\n========== Maltiverse results ==========\n")
        if "classification" in response_json:
            maltiverse_classification = str(response_json["classification"])
            print(f"Classification: {maltiverse_classification}")
            
            if maltiverse_classification == "malicious": table.add_row(["Maltiverse: ", maltiverse_classification, red])
            elif maltiverse_classification == "suspicious": table.add_row(["Maltiverse: ", maltiverse_classification, yellow])
            else: table.add_row(["Maltiverse: ", maltiverse_classification, green])
            
        if "is_cnc" in response_json:
            maltiverse_is_cnc = str(response_json["is_cnc"])
            print(f"Is CNC server?: {maltiverse_is_cnc}")
            if maltiverse_is_cnc == "True": 
                table.add_row(["Is CNC server?", maltiverse_is_cnc, red])
            else: table.add_row(["Is CNC server?", maltiverse_is_cnc, green])
            
        if "is_distributing_malware" in response_json:
            maltiverse_is_distributing_malware = str(response_json["is_distributing_malware"])
            print(f"Is distributing malware?: {maltiverse_is_distributing_malware}")
            if maltiverse_is_distributing_malware == "True": 
                table.add_row(["Is distributing malware?", maltiverse_is_distributing_malware, red])
            else:
                table.add_row(["Is distributing malware?", maltiverse_is_distributing_malware, green])
                
        if "is_hosting" in response_json: maltiverse_is_hosting = str(response_json["is_hosting"])
        
        if "is_known_attacker" in response_json:
            maltiverse_is_known_attacker = str(response_json["is_known_attacker"])
            print(f"Known attacker?: {maltiverse_is_known_attacker}")
            if maltiverse_is_known_attacker == "True":
                table.add_row(["Is Known attacker?", maltiverse_is_known_attacker, red])
            else:
                table.add_row(["Is Known attacker?", maltiverse_is_known_attacker, green])
                
        if "is_known_scanner" in response_json:
            maltiverse_is_known_scanner = str(response_json["is_known_scanner"])
            print(f"Is scanner?: {maltiverse_is_known_scanner}")
            if maltiverse_is_known_scanner == "True":
                table.add_row(["Is Known scanner? ", maltiverse_is_known_scanner, red])
            else:
                table.add_row(["Is Known scanner? ", maltiverse_is_known_scanner, green])
                
        if "is_mining_pool" in response_json:
            maltiverse_is_mining_pool = str(response_json["is_mining_pool"])
            print(f"Is mining pool?: {maltiverse_is_mining_pool}")
            if maltiverse_is_mining_pool == "True":
                table.add_row(["Is mining pool?", maltiverse_is_mining_pool, red])
            else:
                table.add_row(["Is mining pool?", maltiverse_is_mining_pool, green])
        if "is_open_proxy" in response_json:
            maltiverse_is_open_proxy = str(response_json["is_open_proxy"])
            if maltiverse_is_open_proxy == "True":
                table.add_row(["Is proxy?", maltiverse_is_open_proxy, yellow])
            else:
                table.add_row(["Is proxy?", maltiverse_is_open_proxy, green])
                
        if "is_tor_node" in response_json:
            maltiverse_is_tor_node = str(response_json["is_tor_node"])
            print(f"Is Tor node?: {maltiverse_is_tor_node}")
            
        if "is_vpn_node" in response_json:
            maltiverse_is_vpn_node = str(response_json["is_vpn_node"])
            if maltiverse_is_vpn_node == "True":
                table.add_row(["Is VPN?", maltiverse_is_vpn_node, yellow])
            else:
                table.add_row(["Is VPN?", maltiverse_is_vpn_node, green])
                
        if "blacklist" in response_json:
            print("Blacklists:")
            pprint(response_json["blacklist"])
            
        if "as_name" in response_json: print("ASN: " + str(response_json["as_name"]))
        if "asn_cidr" in response_json: print("ASN CIDR: " + str(response_json["asn_cidr"]))
        if "asn_country_code" in response_json: print("ASN country: " + str(response_json["asn_country_code"]))
        if "asn_date" in response_json: print("ASN Date: " + str(response_json["asn_date"]))
        if "asn_registry" in response_json: print("ASN registry: " + str(response_json["asn_registry"]))
        if "city" in response_json: print("City: " + str(response_json["city"]))
        if "creation_time" in response_json: print("Creation time: " + str(response_json["creation_time"]))
        if "modification_time" in response_json: print("Last modification: " + str(response_json["modification_time"]))
        if "number_of_domains_resolving" in response_json: print("Number of domains resolving: " + str(response_json["number_of_domains_resolving"]))
        if "number_of_blacklisted_domains_resolving" in response_json: print("Number of blacklisted domains: " + str(response_json["number_of_blacklisted_domains_resolving"]))
        if "number_of_whitelisted_domains_resolving" in response_json: print("Number of whitelisted Domains: " + str(response_json["number_of_whitelisted_domains_resolving"]))
        if "email" in response_json: print("Email: \n" + str(response_json["email"]))
        
        if is_tor == "True": table.add_row(["Is Tor address?", is_tor, yellow])
        else: table.add_row(["Is Tor address?", is_tor, green])
        
        if "is_cdn" in response_json:
            maltiverse_is_cdn = str(response_json["is_cdn"])
            print(f"Is CDN?: {maltiverse_is_cdn}")
            table.add_row(["Is CDN?", maltiverse_is_cdn, white])
        if "is_sinkhole" in response_json:
            maltiverse_is_sinkhole = str(response_json["is_sinkhole"])
            table.add_row(["Is sinkhole?", maltiverse_is_sinkhole, white])

        table.add_row(["Country", ip_country, white])
        table.add_row(["Type", ip_type, white])
        table.add_row(["ISP", ip_isp, white])

        
def safebrowsing_url_check(ioc):
    apikey = config('GOOGLE_SAFEBROWSING')
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apikey}"
    headers = {'Content-type': 'application/json'}
    
    data = {
        "client": {
        "clientId":      "IoC Analyzer",
        "clientVersion": "1.5.2"
        },
        "threatInfo": {
        "threatTypes":      ["MALWARE",
                            "SOCIAL_ENGINEERING",
                            "THREAT_TYPE_UNSPECIFIED",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
        "platformTypes":    ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [
            {"url": f"{ioc}"}
        ]
        }
    }

    response = requests.post(url=url, headers=headers, data=json.dumps(data))
    response_json = json.loads(response.text)

    if response.status_code == 429:
        table.add_row(["Google Safebrowsing", "API limit exceeded", black])
    elif response.status_code == 200:
        if response_json:
            threattype = response_json['matches'][0]['threatType']
            table.add_row(["Google Safebrowsing", threattype, red])
        else:
            table.add_row(["Google Safebrowsing", "Clean", green])
    else :
        print("Error while checking for Safebrowsing results:")
        print(response.content)

        
def search_twitter(ioc:str):
    import tweepy as tw
    import unicodedata
    twitter_bearer_token    = config('TWITTER_BEARER')
    client                  = tw.Client(bearer_token=twitter_bearer_token)

    print("\n\n========== Top 15 Twitter results ==========\n")

    # Define search query and exclude retweets
    query = f'{ioc} -is:retweet'
    
    # get tweets from API
    tweets = client.search_recent_tweets(
        query           = repr(query), 
        tweet_fields    = ['context_annotations', 'created_at', 'author_id', 'public_metrics'], 
        max_results     = 15
    )
    
    # print tweets
    if tweets.data:
        for tweet in tweets.data:
            author = client.get_user(id=tweet.author_id)  # find username by id
            author = unicodedata.normalize('NFKD', str(author.data.username)).encode('ascii', 'ignore')
            created_at = unicodedata.normalize('NFKD', str(tweet.created_at)).encode('ascii', 'ignore')
            text = unicodedata.normalize('NFKD', str(tweet.text)).encode('ascii', 'ignore')
            print(f"Author: {author}")
            print(f"Created at:  {created_at}")
            print(f"Likes: {tweet.public_metrics['like_count']}")
            print(f"Retweets: {tweet.public_metrics['retweet_count']}\n")
            print(f"Title: {text}")
            print("\n---\n")
        table.add_row(["Twitter", f"{len(tweets.data)} tweet(s)", yellow])
    else: 
        print("No tweets within the last 7 days\n\n")
        table.add_row(["Twitter", "0 tweet(s)", green])

        
def search_reddit(ioc:str):
    import praw
    ioc = str(ioc)
    reddit = praw.Reddit(
        client_id = config('REDDIT_CLIENT_ID'),
        client_secret = config('REDDIT_CLIENT_SECRET'),
        password = config('REDDIT_PASSWORD'),
        user_agent = "python",
        username = config('REDDIT_USERNAME')
    )
    
    print("\n\n========== Top 15 Reddit results ==========\n")

    reddit_sum = sum(1 for x in reddit.subreddit("all").search(ioc))
    
    if reddit_sum:
        table.add_row(["Reddit", f"{reddit_sum} post(s)", yellow])
        for submission in reddit.subreddit("all").search(ioc, sort="new", limit=15):
            print("")
            print("Autor: " + str(submission.author))
            print("Created at: " + datetime.fromtimestamp(int(submission.created_utc)).strftime('%Y-%m-%d %H:%M:%S'))
            print("Link: " + str(submission.url))
            print("Title: " + str(submission.title))
            print("\n---\n")
    else: 
        print("No results\n\n")
        table.add_row(["Reddit", "0 posts", green])
        

def check_shodan(ioc:str, method:str):
    url = "https://api.shodan.io"
    endpoint = {'ip': '/shodan/host/',  # IP information
                'domain': '/dns/domain/',  # Subdomains and DNS entrys per Domain
                'dns_resolve': '/dns/resolve'  # IP for hostname
                }
    apikey = config('SHODAN_APIKEY')
    response = requests.get(url = url + endpoint[method] + ioc + '?key=' + apikey)
    response_json   = json.loads(response.text)
    
    if response.status_code == 200:
        print("\n\n========== Shodan results ==========\n")
        print("Country code: " + str(response_json['country_code']))
        print("Hostnames: " + str(response_json['hostnames']))
        print("Organisation: " + str(response_json['org']))
        print("Last update: " + str(response_json['last_update']))
        print("ASN: " + str(response_json['asn']))
        print("Ports: " + str(response_json['ports']))
    else:
        print("Error while checking for Shodan results:")
        print(response.content)


if __name__ == "__main__":
    # Match IP address
    if re.match(r'[0-9]+(?:\.[0-9]+){3}', ioc):
        table.field_names = ["IoC type: IP", str(ioc), ""]
        try:
            abuseipdb_ip_check(ioc, config('ABUSEIPDB_APIKEY'))
        except Exception as e:
            print("\n========== AbuseIPDB error ==========\n" + str(e))
        try:
            ipqualityscore_ip_check(ioc, config('IPQUALITYSCORE_APIKEY'))
        except Exception as e:
            print("\n========== IPQualityScore error ==========\n" + str(e))
        try:
            virustotal(ioc, "ip_addresses", config('VIRUSTOTAL_APIKEY'))
        except Exception as e:
            print("\n========== Virustotal error ==========\n" + str(e))
        try:
            alienvaultotx(ioc, "IPv4", config('ALIENVAULTOTX_APIKEY'))
        except Exception as e:
            print("\n========== Alienvault OTX error ==========\n" + str(e))
        try:
            blocklist_de_ip_check(ioc)
        except Exception as e:
            print("\n========== Blocklist.de error ==========\n" + str(e))
        try:
            threatfox_ip_check(ioc, config('THREATFOX_APIKEY'))
        except Exception as e:
            print("\n========== THREATfox error ==========\n" + str(e))
        try:
            maltiverse_ip_check(ioc, config('MALTIVERSE_APIKEY'))
        except Exception as e:
            print("\n========== Maltiverse error ==========\n" + str(e))
        try: 
            check_shodan(ioc, 'ip')
        except Exception as e:  
            print("\n========== Shodan error ==========\n" + str(e))
        try: 
            search_twitter(repr(ioc))
        except Exception as e:
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(ioc)
        except Exception as e:
            print("\n========== Reddit error ==========\n" + str(e))
            
    # Match domain
    elif re.match(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', ioc):
        table.field_names = ["IoC type: Domain", str(ioc), ""]
        try:
            virustotal(ioc, "domains", config('VIRUSTOTAL_APIKEY'))
        except Exception as e:
            print("\n========== Virustotal error ==========\n" + str(e))
        try:
            alienvaultotx(ioc, "domain", config('ALIENVAULTOTX_APIKEY'))
        except Exception as e:
            print("\n========== Alienvault OTX error ==========\n" + str(e))
        try: 
            safebrowsing_url_check(ioc)
        except Exception as e:
            print("\n========== Google Safebrowsing error ==========\n" + str(e))
        try: 
            search_twitter(repr(ioc))
        except Exception as e:
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(ioc)
        except Exception as e:
            print("\n========== Reddit error ==========\n" + str(e))
        
    # Match URL
    elif re.match(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)', ioc):
        table.field_names = ["IoC type: URL", str(ioc), ""]
        try:
            ioc_encoded = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            virustotal(ioc_encoded, "urls", config('VIRUSTOTAL_APIKEY'))
        except Exception as e:
            print("\n========== Virustotal error ==========\n" + str(e))
        try: 
            safebrowsing_url_check(ioc)
        except Exception as e:
            print("\n========== Google Safebrowsing error ==========\n" + str(e))
        try:
            urlhaus_url_check(ioc)
        except Exception as e:
            print("\n========== URLhaus error ==========\n")
            print(str(e))
        try: 
            search_twitter(repr(ioc))
        except Exception as e:
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(repr(ioc))
        except Exception as e:
            print("\n========== Reddit error ==========\n" + str(e))
        
    # Match MD5
    elif re.match(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', ioc):
        table.field_names = ["IoC type: MD5", str(ioc), ""]
        try:
            virustotal(ioc, "files", config('VIRUSTOTAL_APIKEY'))
        except Exception as e:
            print("\n========== Virustotal error ==========\n" + str(e))
        try:
            alienvaultotx(ioc, "file", config('ALIENVAULTOTX_APIKEY'))
        except Exception as e:
            print("\n========== Alienvault OTX error ==========\n" + str(e))
        try:
            threatfox_ip_check(ioc, config('THREATFOX_APIKEY'))
        except Exception as e:
            print("\n========== THREATfox error ==========\n" + str(e))
        try:
            malwarebazaar_hash_check(ioc)
        except Exception as e:
            print("\n========== MALWAREbazaar error ==========\n")
            print(str(e))
        try: 
            search_twitter(ioc)
        except Exception as e:
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(ioc)
        except Exception as e:
            print("\n========== Reddit error ==========\n" + str(e))
     
    # Match SHA1       
    elif re.match(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', ioc):
        table.field_names = ["IoC type: SHA1", str(ioc), ""]
        try:
            virustotal(ioc, "files", config('VIRUSTOTAL_APIKEY'))
        except Exception as e:
            print("\n========== Virustotal error ==========\n" + str(e))
        try:
            alienvaultotx(ioc, "file", config('ALIENVAULTOTX_APIKEY'))
        except Exception as e:
            print("\n========== Alienvault OTX error ==========\n" + str(e))
        try:
            threatfox_ip_check(ioc, config('THREATFOX_APIKEY'))
        except Exception as e:
            print("\n========== THREATfox error ==========\n" + str(e))
        try:
            malwarebazaar_hash_check(ioc)
        except Exception as e:
            print("\n========== MALWAREbazaar error ==========\n")
            print(str(e))
        try: 
            search_twitter(ioc)
        except Exception as e:
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(ioc)
        except Exception as e:
            print("\n========== Reddit error ==========\n" + str(e))
         
    # Match SHA256
    elif re.match(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', ioc):
        table.field_names = ["IoC type: SHA256", str(ioc), ""]
        try: 
            virustotal(ioc, "files", config('VIRUSTOTAL_APIKEY'))
        except Exception as e: 
            print("\n========== Virustotal error ==========\n" + str(e))
        try: 
            alienvaultotx(ioc, "file", config('ALIENVAULTOTX_APIKEY'))
        except Exception as e: 
            print("\n========== Alienvault OTX error ==========\n" + str(e))
        try: 
            threatfox_ip_check(ioc, config('THREATFOX_APIKEY'))
        except Exception as e: 
            print("\n========== THREATfox error ==========\n" + str(e))
        try:
            malwarebazaar_hash_check(ioc)
        except Exception as e:
            print("\n========== MALWAREbazaar error ==========\n")
            print(str(e))
        try: 
            search_twitter(ioc)
        except Exception as e: 
            print("\n========== Twitter error ==========\n" + str(e))
        try: 
            search_reddit(ioc)
        except Exception as e: 
            print("\n========== Reddit error ==========\n" + str(e))
            
    else:
        table.field_names = ["IoC type: Unknown", str(ioc), ""]
        table.add_row(["Error", "IoC type could not be detected", white])


    table.align = "l"
    print(table)
