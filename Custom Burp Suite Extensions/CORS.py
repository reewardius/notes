from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Set up extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CORS Tester")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses
        if not messageIsRequest:
            # Get response details
            response = messageInfo.getResponse()
            headers = self._helpers.analyzeResponse(response).getHeaders()
            body = response[self._helpers.analyzeResponse(response).getBodyOffset():]
            body_string = body.tostring()
            url = messageInfo.getUrl()

            # Initialize report
            report = ""

            # Check for CORS headers
            for header in headers:
                if "Access-Control-Allow-Origin" in header:
                    report += "CORS header found: " + header + "\n"
                    # Check for valid values for "Access-Control-Allow-Origin" header
                    if "*" in header:
                        report += "  Warning: Using '*' allows any origin to access the resource.\n"
                if "Access-Control-Allow-Methods" in header:
                    report += "CORS header found: " + header + "\n"
                    # Check for valid values for "Access-Control-Allow-Methods" header
                    if "*" in header:
                        report += "  Warning: Using '*' allows any method to be used with the resource.\n"
                if "Access-Control-Allow-Headers" in header:
                    report += "CORS header found: " + header + "\n"
                    # Check for valid values for "Access-Control-Allow-Headers" header
                    if "*" in header:
                        report += "  Warning: Using '*' allows any header to be used with the resource.\n"
                if "Access-Control-Allow-Credentials" in header:
                    report += "CORS header found: " + header + "\n"
                if "Access-Control-Max-Age" in header:
                    report += "CORS header found: " + header + "\n"

            # If report is not empty, add issue to Activity Issues tab
            if report != "":
                issue = CORSIssue(url, report)
                self._callbacks.addScanIssue(issue)

# Class for custom scan issue
class CORSIssue(IScanIssue):
    def __init__(self, url, detail):
        self._url = url
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Medium"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

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