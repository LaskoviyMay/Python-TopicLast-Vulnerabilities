import requests
import json

# Настройки API
API_KEY = "KK7EN8NOVVF27ASJQ5DL050V9DGJ17NYXFRXM3S1EPPNDFZJANUQGX7NE0CDF7IMB"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"

# Входные данные
software_list = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]

def check_vulnerabilities(software, version):
    params = {
        "software": software,
        "version": version,
        "apikey": API_KEY
    }
    response = requests.get(VULNERS_API_URL, params=params)
    
    if response.status_code != 200:
        return {"error": f"API request failed with status code {response.status_code}"}
    
    data = response.json()
    if data.get("result") != "OK":
        return {"error": "No data found or invalid response"}
    
    vulnerabilities = data.get("data", {}).get("vulnerabilities", [])
    return vulnerabilities


def generate_report(software_list):
    report = []
    for item in software_list:
        program = item["Program"]
        version = item["Version"]
        print(f"Checking {program} {version}...")
        vulns = check_vulnerabilities(program, version)
        
        entry = {
            "Program": program,
            "Version": version,
            "Vulnerable": False,
            "CVEs": []
        }
        
        if "error" in vulns:
            entry["Error"] = vulns["error"]
        elif vulns:
            entry["Vulnerable"] = True
            entry["CVEs"] = [vuln["id"] for vuln in vulns]
        
        report.append(entry)
    
    return report

if __name__ == "__main__":
    report = generate_report(software_list)
    with open("vulnerability_report.json", "w") as f:
        json.dump(report, f, indent=4)