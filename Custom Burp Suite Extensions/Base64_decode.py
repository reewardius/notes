import base64

from burp import IBurpExtender
from burp import IScanIssue

class BurpExtender(IBurpExtender):
    
    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("Base64 Decoder")
        
        # get the callbacks object
        self.callbacks = callbacks
        
        # get the helpers object
        self.helpers = callbacks.getHelpers()

    def doPassiveScan(self, baseRequestResponse):
        # get the response message
        response = baseRequestResponse.getResponse()
        
        # get the response body
        responseBody = response[response.offset:response.offset+response.length]
        
        # check if the response body contains a base64 string
        if "base64" in responseBody:
            # decode the base64 string
            decoded = base64.b64decode(responseBody)
            
            # create a new scan issue
            issue = Base64Issue(baseRequestResponse.getHttpService(),
                                baseRequestResponse.getUrl(),
                                [baseRequestResponse],
                                "Base64 String Found",
                                "The response contains a base64 string: " + responseBody + "\n\nDecoded: " + decoded,
                                "Information")
            # report the issue
            return [issue]
        
        # no base64 strings found
        return None

class Base64Issue(IScanIssue):
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
