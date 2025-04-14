import requests

def check_url_virustotal(url, api_key):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        # Step 1: Submit URL for scanning
        submit_response = requests.post(endpoint, headers=headers, data={"url": url})
        if submit_response.status_code != 200:
            return {
                "status": "error",
                "error": f"Submit failed with status {submit_response.status_code}: {submit_response.text}"
            }

        scan_id = submit_response.json().get("data", {}).get("id")
        if not scan_id:
            return {"status": "error", "error": "Scan ID not found in response"}

        # Step 2: Retrieve analysis results
        analysis_url = f"{endpoint}/{scan_id}"
        analysis_response = requests.get(analysis_url, headers=headers)

        if analysis_response.status_code != 200:
            return {
                "status": "error",
                "error": f"Analysis failed with status {analysis_response.status_code}: {analysis_response.text}"
            }

        analysis_data = analysis_response.json().get("data", {})
        stats = analysis_data.get("attributes", {}).get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values())
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}


