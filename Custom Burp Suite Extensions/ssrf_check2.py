import re

from burp import IBurpExtender
from burp import IScanIssue

class BurpExtender(IBurpExtender):

    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("SSRF Scanner")
        
        # get the callbacks object
        self.callbacks = callbacks
        
        # get the helpers object
        self.helpers = callbacks.getHelpers()

    def doPassiveScan(self, baseRequestResponse):
        # get the request message
        request = baseRequestResponse.getRequest()
        
        # get the request body
        requestBody = request[request.offset:request.offset+request.length]
        
        # check if the request body contains a domain name with or without a protocol
        if re.search(r"(?:http[s]?://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+", requestBody):
            # create a new scan issue
            issue = SSRFIssue(baseRequestResponse.getHttpService(),
                              baseRequestResponse.getUrl(),
                              [baseRequestResponse],
                              "Potential SSRF Vulnerability",
                              "The request body contains a domain name with or without a protocol: " + requestBody,
                              "High")
            # report the issue
            return [issue]
        
        # no SSRF vulnerabilities found
        return []

class SSRFIssue(IScanIssue):
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
