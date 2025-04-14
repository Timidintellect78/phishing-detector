import requests

def check_url_virustotal(url, api_key):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        # Step 1: Submit the URL for scanning
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code != 200:
            return {"error": f"Submission failed: {response.status_code} - {response.text}"}

        data = response.json()
        scan_id = data.get("data", {}).get("id")
        if not scan_id:
            return {"error": "Scan ID not found in VirusTotal response."}

        # Step 2: Retrieve scan results
        analysis_url = f"{endpoint}/{scan_id}"
        result = requests.get(analysis_url, headers=headers)
        if result.status_code != 200:
            return {"error": f"Failed to fetch analysis: {result.status_code} - {result.text}"}

        result_data = result.json().get("data", {})
        stats = result_data.get("attributes", {}).get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values())
        }

    except Exception as e:
        return {"error": str(e)}
