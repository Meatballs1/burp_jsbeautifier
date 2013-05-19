##
# js-beautifier burpsuite extension
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
# http://rewtdance.blogspot.co.uk
# http://github.com/Meatballs1/burp_jsbeautifier
#
# Place the jsbeautifier python folder in the burpsuite/lib/ folder.
# Load extension in the Extender tab.
#
# Tested in Burpsuite Pro v1.5.11 with js-beautify v1.3.2
# http://jsbeautifier.org/
##

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
try:
    import jsbeautifier
except ImportError:
    print "jsbeautifier missing from burpsuite lib/ folder."

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Javascript Beautifier")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        return
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return JavaScriptTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class JavaScriptTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display the javascript
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

        # Set JS Beautifier opts
        opts = jsbeautifier.default_options()
        opts.indent_size = 2

        # Store httpHeaders incase request is modified
        self._httpHeaders = None
        return
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "JavaScript"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab only for responses containing javascript Content-Types
	if isRequest:
            return False

	response_info = self._extender._helpers.analyzeResponse(content)
	
	if response_info != None:
	    headers = response_info.getHeaders()
	    # Store HTTP Headers incase we edit the response.
	    self._httpHeaders = headers
	    if (headers != None and len(headers) > 0):
		content_type_headers = self.getHeadersContaining('Content-Type', headers)
                if (content_type_headers != None):
                    for content_type_header in content_type_headers:
                        if ('javascript' in content_type_header):
                            return True
							
        return False
    
    def getHeadersContaining(self, findValue, headers):
        if (findValue != None and headers != None and len(headers)>0):
            return [s for s in headers if findValue in s]
        return None
        
    def setMessage(self, content, isRequest):
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            # retrieve the js body
            info = self._extender._helpers.analyzeResponse(content)
            javascript = ""
            js = self._extender._helpers.bytesToString(content[info.getBodyOffset():])

            if (js != None and len(js) > 0):
                try:
                    bjs = jsbeautifier.beautify(js)
                    if (bjs != None and len(bjs) > 0):
                        javascript = bjs
                    else:
                        print "ERROR: jsbeautifier returned an empty string or None."
                        javascript = js
                except:
                    print "ERROR: jsbeautifier threw an exception: %s" % sys.exc_info()[0]
                    javascript = js              
            
            self._txtInput.setText(javascript)
            self._txtInput(self._editable)

        # remember the displayed content
        self._currentMessage = content
        return
    
    def getMessage(self):
        if (self._txtInput.isTextModified()):
            # reserialize the data
            text = self._txtInput.getText()
            
            # update the request with the new edited js
            return self._extender._helpers.buildHttpMessage(self._httpHeaders,text)
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
            
