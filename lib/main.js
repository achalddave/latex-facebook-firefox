exports.main = function() {
    var pageMod = require("sdk/page-mod");
    var data = require("sdk/self").data;

    pageMod.PageMod({
      include: "*.facebook.com",
      contentScriptFile: data.url('content-script.js')
    });

    // Stolen from http://stackoverflow.com/questions/19264831/how-to-add-content-security-policy-to-firefox-extension/19917664#19917664
    const {Cc,Ci} = require("chrome");
    Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService)
    .addObserver(_httpExamineCallback, "http-on-examine-response", false);

    function _httpExamineCallback(aSubject, aTopic, aData) {
      var httpChannel = aSubject.QueryInterface(Ci.nsIHttpChannel);

      if (httpChannel.responseStatus !== 200) {
        return;
      }

      var cspRules;
      var mycsp;
      // thre is no clean way to check the presence of csp header. an exception
      // will be thrown if it is not there.
      // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIHttpChannel
      try {
        cspRules = httpChannel.getResponseHeader("Content-Security-Policy");
        mycsp = _getCspAppendingMyHostDirective(cspRules);
        httpChannel.setResponseHeader('Content-Security-Policy', mycsp, false);
      } catch (e) {
        try {
          // Fallback mechanism support             
          cspRules = httpChannel.getResponseHeader("X-Content-Security-Policy");
          mycsp = _getCspAppendingMyHostDirective(cspRules);    
          httpChannel.setResponseHeader('X-Content-Security-Policy', mycsp, false);            
        } catch (e) {
          // no csp headers defined
          return;
        }
      }

    };

    /**
     * @var cspRules : content security policy 
     * For my requirement i have to append rule just to 'script-src' directive. But you can
     * modify this function to your need.
     *
     */
    function _getCspAppendingMyHostDirective(cspRules) {
      var rules = cspRules.split(';'),
      scriptSrcDefined = false,
      defaultSrcIndex = -1;

      for (var ii = 0; ii < rules.length; ii++) {
        if ( rules[ii].toLowerCase().indexOf('script-src') != -1 ) {
          rules[ii] = rules[ii] + ' http://cdn.mathjax.org https://cdn.mathjax.org https://*.rackcdn.com';
          scriptSrcDefined = true;
        }

        if (rules[ii].toLowerCase().indexOf('default-src') != -1) {
          defaultSrcIndex = ii;
        }
      }

      // few publishers will put every thing in the default (default-src) directive,
      // without defining script-src. We need to modify those as well.
      if ((!scriptSrcDefined) && (defaultSrcIndex != -1)) {
        rules[defaultSrcIndex] = rules[defaultSrcIndex] + '  http://cdn.mathjax.org https://cdn.mathjax.org https://*.rackcdn.com';
      }

      return rules.join(';');
    };
};
