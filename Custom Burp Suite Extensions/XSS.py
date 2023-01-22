from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Set up extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Tester")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests
        if messageIsRequest:
            # Get request details
            request = messageInfo.getRequest()
            url = messageInfo.getUrl()

            # Get list of XSS payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
                "<img src='x' onerror='alert(\"XSS\")'>"
            ]

            # Modify parameters to include XSS payloads
            for payload in payloads:
                modified_request = self._helpers.updateParameter(request, self._helpers.buildParameter("", payload, self._helpers.CONTENT_TYPE_HTML))
                modified_message = self._helpers.buildHttpMessage(modified_request.getHeaders(), modified_request.getBody())

                # Send modified request and get response
                response = self._callbacks.makeHttpRequest(url.getHost(), url.getPort(), url.getProtocol() == "https", modified_message)
                response_headers = self._helpers.analyzeResponse(response).getHeaders()
                response_body = response[self._helpers.analyzeResponse(response).getBodyOffset():]

                # Check if payload is reflected and not sanitized
                if payload in response_body and not any("X-XSS-Protection" in header for header in response_headers):
                    # Print payload and response
                    print("Payload: " + payload)
                    print("Response: " + response_body)

                    # Add issue to Activity Issues tab
                    issue = XSSIssue(url, payload, response_body)
                    self._callbacks.addScanIssue(issue)

# Class for custom scan issue
class XSSIssue(IScanIssue):
    def __init__(self, url, payload, detail):
        self._url = url
        self._payload = payload
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Possible XSS Vulnerability"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Certain"

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpservice
       
