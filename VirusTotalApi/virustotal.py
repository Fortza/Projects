#Used for API calls towards VirusTotal
import requests
from config import virus_API_KEY



def get_ip_report(ip):

    headers = {
        "x-apikey": virus_API_KEY
    }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    response = requests.get(url, headers=headers)

    return response.json()


def get_domain_report(domain):

    headers = {
        "x-apikey": virus_API_KEY
    }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(url, headers=headers)

    return response.json()

#Human readable json resultat
def parse_report(result):

    stats = result["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"]
    }