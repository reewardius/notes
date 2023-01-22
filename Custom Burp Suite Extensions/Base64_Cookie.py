from burp import IBurpExtender
from burp import IHttpListener
from java.util import ArrayList
import base64

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("Base64 Cookie Decoder")
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process responses
        if not messageIsRequest:
            # get the response headers
            headers = currentRequest.getResponseHeaders()
            
            # search for the "Set-Cookie" header
            for header in headers:
                if header.startswith("Set-Cookie: "):
                    # get the value of the "Set-Cookie" header
                    cookie = header.split(": ", 1)[1]
                    
                    # try to decode the cookie with base64
                    try:
                        decodedCookie = base64.b64decode(cookie)
                        
                        # display the decoded cookie in the Issue Activity tab
                        callbacks.addIssue(callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                          callbacks.getHelpers().analyzeRequest(currentRequest).getUrl(), 
                                          "Base64 Cookie Decoded", "Information", "High", "Cookie decoded successfully: " + decodedCookie)
                    except:
                        # if the decoding fails, do nothing
                        pass