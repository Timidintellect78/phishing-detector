import requests
import time

def check_url_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    endpoint = "https://www.virustotal.com/api/v3/urls"

    try:
        # Submit the URL for scanning
        submission = requests.post(endpoint, headers=headers, data={"url": url})
        if submission.status_code != 200:
            return {"error": f"URL submission failed with code {submission.status_code}", "url": url}

        scan_id = submission.json().get("data", {}).get("id")
        if not scan_id:
            return {"error": "Missing scan ID from VirusTotal response", "url": url}

        # Wait briefly to let VirusTotal finish analysis
        time.sleep(5)  # adjust or loop for polling if needed

        # Fetch the scan result
        analysis_url = f"{endpoint}/{scan_id}"
        result = requests.get(analysis_url, headers=headers)
        if result.status_code != 200:
            return {"error": f"Failed to retrieve analysis, code {result.status_code}", "url": url}

        attributes = result.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            return {"error": "Analysis stats missing", "url": url}

        return {
            "harmless": stats.get("harmless", 0),
            "suspicious": stats.get("suspicious", 0),
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
        }

    except Exception as e:
        return {"error": str(e), "url": url}

