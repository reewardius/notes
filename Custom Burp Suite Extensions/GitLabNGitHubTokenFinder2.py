from burp import IBurpExtender
from burp import IHttpListener
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("Token Finder")
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process responses
        if not messageIsRequest:
            # get the response body
            response = currentRequest.getResponse()
            responseBody = self._helpers.bytesToString(response)
            
            # search for GitLab tokens
            gitlabTokens = []
            gitlabTokenRegex = r"(xoxp-|xoxb-).*"
            gitlabTokens = re.findall(gitlabTokenRegex, responseBody)
            if gitlabTokens:
                for gitlabToken in gitlabTokens:
                    callbacks.addIssue(callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                       callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                       "GitLab Token Found", "High", "High", "GitLab token found in response: " + gitlabToken[0])
            
            # search for GitHub tokens
            githubTokens = []
            githubTokenRegex = r"(github_pat_|ghp_).*"
            githubTokens = re.findall(githubTokenRegex, responseBody)
            if githubTokens:
                for githubToken in githubTokens:
                    callbacks.addIssue(callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                       callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                       "GitHub Token Found", "High", "High", "GitHub token found in response: " + githubToken[0])
