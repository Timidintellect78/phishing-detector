import email
from email import policy
from bs4 import BeautifulSoup
import re

def parse_email_from_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        msg = email.message_from_file(file, policy=policy.default)

    return_path = msg.get('Return-Path', '')

    return {
        "from": msg.get('From', ''),
        "to": msg.get('To', ''),
        "subject": msg.get('Subject', ''),
        "body": get_email_body(msg),
        "links": extract_links_from_body(msg),
        "return_path": return_path
    }

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                if content_type == "text/plain":
                    return part.get_payload(decode=True).decode(errors="ignore")
                elif content_type == "text/html":
                    return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""

def extract_links_from_body(msg):
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        if msg.get_content_type() == "text/html":
            html = msg.get_payload(decode=True).decode(errors="ignore")

    soup = BeautifulSoup(html, "html.parser")
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    return links
