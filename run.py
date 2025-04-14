from app.parser import parse_email_from_file
from app.detector import analyze_email

if __name__ == '__main__':
    filepath = input("Enter the path to the .eml file: ").strip()
    try:
        parsed = parse_email_from_file(filepath)
        parsed['reply_to'] = "fraud@fake.com"  # Simulate reply-to mismatch
        parsed['spf_passed'] = False           # Simulate SPF fail
        parsed['dkim_passed'] = True           # Simulate DKIM pass
        print("\n--- Parsed Email ---")
        print(f"From: {parsed['from']}")
        print(f"To: {parsed['to']}")
        print(f"Subject: {parsed['subject']}")
        print(f"Body: {parsed['body'][:200]}...")
        print(f"Links: {parsed['links']}")

        print("\n--- Phishing Analysis ---")
        result = analyze_email(parsed)
        print(f"Risk Score: {result['score']} / 100")
        print(f"Label: {result['label']}")
        print("Flags:")
        for flag in result['flags']:
            print(f"  - {flag}")

    except Exception as e:
        print(f"Error parsing email: {e}")
