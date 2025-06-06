import requests
import json

# 定义服务器组件及其版本信息
server_components = {
    "Apache HTTP Server": "2.2.14",
    "mod_mono": "2.4.3",
    "PHP": "5.3.2-1ubuntu4.30",
    "Suhosin-Patch": "unknown",
    "proxy_html": "3.0.1",
    "mod_python": "3.3.1",
    "Python": "2.6.5",
    "mod_ssl": "2.2.14",
    "OpenSSL": "0.9.8k",
    "Phusion Passenger": "4.0.38",
    "mod_perl": "2.0.4",
    "Perl": "v5.10.1"
}

# 定义CVE数据库的API地址
cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 遍历服务器组件，查找每个组件的漏洞信息
for component, version in server_components.items():
    print(f"Checking vulnerabilities for {component} {version}...")

    # 构造查询参数
    params = {
        "keywordSearch": f"{component} {version}",
        "cveId": "",
        "cweId": "",
        "pubStartDate": "",
        "pubEndDate": "",
        "lastModStartDate": "",
        "lastModEndDate": "",
        "sourceIdentifier": "nvd@nist.gov"
    }

    try:
        # 发送请求到CVE数据库API
        response = requests.get(cve_api_url, params=params)
        data = response.json()

        # 检查是否有漏洞信息
        if data["totalResults"] > 0:
            print(f"Found {data['totalResults']} vulnerabilities for {component} {version}:")
            for cve in data["vulnerabilities"]:
                cve_id = cve["cve"]["id"]
                cve_desc = cve["cve"]["descriptions"][0]["value"]
                cve_severity = cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                print(f"  - {cve_id} ({cve_severity}): {cve_desc}")
        else:
            print(f"No vulnerabilities found for {component} {version}.")

    except Exception as e:
        print(f"An error occurred while checking vulnerabilities for {component} {version}: {e}")

    print("\n" + "-" * 50 + "\n")