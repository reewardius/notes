from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IScannerCheck):
  def registerExtenderCallbacks(self, callbacks):
    # Set up extension
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("Session Management Check")

    # Register extension as a scanner check
    callbacks.registerScannerCheck(self)

    # Print extension info
    stdout = PrintWriter(callbacks.getStdout(), True)
    stdout.println("Session Management Check extension loaded")
    stdout.println("Author: Your Name")

  def doPassiveScan(self, baseRequestResponse):
    # Check for insecure session management vulnerabilities in the response
    self.checkSessionManagement(baseRequestResponse)

  def doActiveScan(self, baseRequestResponse, insertionPoint):
    # Check for insecure session management vulnerabilities in the response
    self.checkSessionManagement(baseRequestResponse)

  def checkSessionManagement(self, baseRequestResponse):
    # Get the response and its headers
    response = baseRequestResponse.getResponse()
    headers = self._helpers.analyzeResponse(response).getHeaders()

    # Look for the Set-Cookie header
    for header in headers:
      if header.startswith("Set-Cookie:"):
        # Get the value of the Set-Cookie header
        cookie = header[12:]

        # Check for the presence of the Secure, SameSite, and HttpOnly flags
        if "Secure" not in cookie:
          # Report a warning if the Secure flag is not present
          issue = SessionManagementIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), [baseRequestResponse], "Insecure session management: Secure flag not set", "The Secure flag is not set on the following cookie: " + cookie, "High")
          self._callbacks.addScanIssue(issue)
        if "SameSite" not in cookie:
          # Report a warning if the SameSite flag is not present
          issue = SessionManagementIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), [baseRequestResponse], "Insecure session management: SameSite flag not set", "The SameSite flag is not set on the following cookie: " + cookie, "Medium")
          self._callbacks.addScanIssue(issue)
        if "HttpOnly" not in cookie:
          # Report a warning if the HttpOnly flag is not present
          issue = SessionManagementIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), [baseRequestResponse], "Insecure session management: HttpOnly flag not set", "The HttpOnly flag is not set on the following cookie: " + cookie, "Low")
          self._callbacks.addScanIssue(issue)

class SessionManagementIssue(IScanIssue):
    def __init__(self, httpservice, url, requestResponse, name, detail, severity):
        self._httpservice = httpservice
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

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
