import time
import requests

def check_url_virustotal(url, api_key):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        # Step 1: Submit the URL
        submit_resp = requests.post(endpoint, headers=headers, data={"url": url})
        if submit_resp.status_code != 200:
            return {"error": "Failed to submit URL"}

        scan_id = submit_resp.json()["data"]["id"]
        analysis_url = f"{endpoint}/{scan_id}"

        # Step 2: Poll for results (max 10 tries)
        for _ in range(10):
            result_resp = requests.get(analysis_url, headers=headers)
            result_json = result_resp.json()

            status = result_json.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = result_json["data"]["attributes"]["last_analysis_stats"]
                return {
                    "harmless": stats.get("harmless", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values())
                }
            time.sleep(2)  # Wait before retrying

        return {"error": "Scan did not complete in time"}

    except Exception as e:
        return {"error": str(e)}
