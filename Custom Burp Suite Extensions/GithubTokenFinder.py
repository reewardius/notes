from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

import re

class BurpExtender(IBurpExtender, IScannerCheck):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("GitHub Token Scanner")
    callbacks.registerScannerCheck(self)

  def doPassiveScan(self, baseRequestResponse):
    # Get the response from the base request
    response = baseRequestResponse.getResponse()

    # Convert the response to a string
    responseString = self._helpers.bytesToString(response)

    # Search for a GitHub personal access token using a regular expression
    tokenRegex = re.compile(r'github_pat_[a-zA-Z0-9]+')
    match = tokenRegex.search(responseString)

    # If a token is found, create a new scan issue
    if match:
      issue = GitHubTokenIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), baseRequestResponse, match.group())
      return [issue]
    else:
      return None

  def consolidateDuplicateIssues(self, existingIssue, newIssue):
    if existingIssue.getUrl() == newIssue.getUrl():
      return -1
    else:
      return 0

class GitHubTokenIssue(IScanIssue):
  def __init__(self, httpservice, url, requestResponse, token):
    self._httpservice = httpservice
    self._url = url
    self._requestResponse = requestResponse
    self._token = token

  def getUrl(self):
    return self._url

  def getIssueName(self):
    return "GitHub Personal Access Token Found"

  def getIssueType(self):
    return 0

  def getSeverity(self):
    return "High"

  def getConfidence(self):
    return "Certain"

  def getIssueBackground(self):
    return "A GitHub personal access token was found in the response. Personal access tokens provide access to the GitHub API and can be used to perform actions on behalf of the user or application. It is important to ensure that personal access tokens are kept secure and are not disclosed in public."

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpservice