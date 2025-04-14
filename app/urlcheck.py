import requests
import base64

def check_url_virustotal(url, api_key):
    try:
        # Step 1: Submit URL for scanning
        endpoint = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code != 200:
            return {"error": f"Submit failed: {response.text}"}

        # Step 2: Retrieve the scan ID and encode it safely
        scan_id = response.json()["data"]["id"]
        encoded_url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Step 3: Fetch the analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url_id}"
        result = requests.get(analysis_url, headers=headers).json()

        stats = result["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values())
        }

    except Exception as e:
        return {"error": str(e)}
