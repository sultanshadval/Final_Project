import email
from email.policy import default
import requests
import time

def analyze_email(email_content, api_key):
    msg = email.message_from_string(email_content, policy=default)
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            body = part.get_payload(decode=True).decode('utf-8')
            suspicious_links = [word for word in body.split() if word.startswith('http://') or word.startswith('https://')]
            for link in suspicious_links:
                print(f"Suspicious link found in email body: {link}")
                result = check_link_virustotal(link, api_key)
                if result:
                    print(f"VirusTotal assessment for {link}: {result}")
                else:
                    print(f"Unable to assess link {link} with VirusTotal")
    print(f"From: {msg['From']}")
    print(f"Subject: {msg['Subject']}")

def check_link_virustotal(link, api_key):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key
    }
    data = {
        "url": link
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        # Wait and recheck for analysis result
        time.sleep(10)  # Initial wait time
        for _ in range(10):  # Retry up to 10 times
            result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            result_response = requests.get(result_url, headers=headers)
            if result_response.status_code == 200:
                result_data = result_response.json()
                status = result_data['data']['attributes']['status']
                if status == 'completed':
                    stats = result_data['data']['attributes']['stats']
                    return stats
            time.sleep(10)  # Wait before retrying
    return None

api_key = '91bf8de0b443b4126d3b6aaa69c252b962fbef97afa47afea80728778b2a607a'  # Replace with your actual VirusTotal API key

email_content = """\
From: phishing@example.com
Subject: Update Your Account Information

Please visit http://phishing-link.com to update your account.
"""
analyze_email(email_content, api_key)
