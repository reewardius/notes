import re

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):

    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("Secret Key Finder")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # implement IScannerCheck
    def doPassiveScan(self, baseRequestResponse):
        # get the response message
        response = baseRequestResponse.getResponse()

        # get the response body
        responseBody = response[response.offset:response.offset+response.length]

        # create a list of patterns to search for
        patterns = [re.compile("secret"), 
                    re.compile("key"), 
                    re.compile("password"),
                    re.compile("[0-9a-f]{32}")]

        # search the response body for the patterns
        for pattern in patterns:
            if pattern.search(responseBody):
                # create a new scan issue
                issue = SecretKeyIssue(baseRequestResponse.getHttpService(),
                                      baseRequestResponse.getUrl(),
                                      [baseRequestResponse],
                                      "Secret Key Found",
                                      "The response contains a secret key matching the following pattern: " + pattern.pattern,
                                      "High")
                # report the issue
                return [issue]
        
        # no secret keys found
        return None

class SecretKeyIssue(IScanIssue):
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
