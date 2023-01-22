from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from bs4 import BeautifulSoup

class HiddenParameterExtension(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Hidden Parameter Extension")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            # parse the response HTML to extract the hidden parameters
            response = messageInfo.getResponse()
            soup = BeautifulSoup(response, "html.parser")
            hidden_inputs = soup.find_all("input", type="hidden")
            hidden_params = []
            for input in hidden_inputs:
                hidden_params.append(f"{input['name']}: {input['value']}")
            # output the result to the Issue Activity tab
            if hidden_params:
                issue = HiddenParameterIssue(
                    messageInfo.getHttpService(),
                    messageInfo.getUrl(),
                    hidden_params
                )
                self.callbacks.addScanIssue(issue)

class HiddenParameterIssue(IScanIssue):
    def __init__(self, http_service, url, hidden_params):
        self.http_service = http_service
        self.url = url
        self.hidden_params = hidden_params

    def getUrl(self):
        return self.url

    def getIssueName(self):
        return "Hidden Parameters Found"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "The following hidden parameters were found in the response:"

    def getRemediationBackground(self):
        return "It is generally a good security practice to minimize the use of hidden form fields. Hidden fields should only be used for data that is not sensitive and does not need to be protected."

    def getIssueDetail(self):
        return "\n".join(self.hidden_params)

    def getRemediationDetail(self):
        return "Consider removing unnecessary hidden fields or securing sensitive data in a different way."

    def getHttpMessages(self):
        return [self.http_service, self.url, self.hidden_params]

    def getHttpService(self):
        return self.http_service
