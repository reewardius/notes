import base64
import html
import urllib.parse
import sys

def obfuscate_xss_payload(payload):
    # URL encode the payload
    payload_url_encoded = urllib.parse.quote(payload)

    # Base64 encode the payload
    payload_base64_encoded = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    # HTML encode the payload
    payload_html_encoded = html.escape(payload)

    # JavaScript encode the payload
    payload_js_encoded = payload.replace('\'', '\\x27').replace('\"', '\\x22')

    # Double URL encode the payload
    payload_double_url_encoded = urllib.parse.quote(payload_url_encoded)

    # Double HTML encode the payload
    payload_double_html_encoded = html.escape(payload_html_encoded)

    # Double JavaScript encode the payload
    payload_double_js_encoded = payload_js_encoded.replace('\'', '\\x27').replace('\"', '\\x22')

    return (payload_url_encoded, payload_base64_encoded, payload_html_encoded, payload_js_encoded, 
            payload_double_url_encoded, payload_double_html_encoded, payload_double_js_encoded)

if __name__ == '__main__':
    # Get the XSS payload from the command line argument
    payload = sys.argv[1]

    # Obfuscate the payload
    obfuscated_payloads = obfuscate_xss_payload(payload)

    # Print the obfuscated payloads
    for payload in obfuscated_payloads:
        print(payload)
