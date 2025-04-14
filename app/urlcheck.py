import requests

def check_url_virustotal(url, api_key):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        # Step 1: Encode the URL
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code != 200:
            return {"status": "error", "message": "Failed to submit URL"}

        scan_id = response.json()["data"]["id"]

        # Step 2: Get the analysis result
        analysis_url = f"{endpoint}/{scan_id}"
        result = requests.get(analysis_url, headers=headers).json()

        stats = result["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        harmless = stats["harmless"]

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total": sum(stats.values())
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
