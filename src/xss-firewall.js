/* eslint accessor-pairs: "off" */

/**
 *  xss-firewall --  xss 防火墙
 */

(function () {


    if (!window.MutationObserver || !window.Object.defineProperty) {
        return;
    }

	
	var XSS_FW_CONFIG = {
		reportOnly: true,
		reportUrl : '',
		reportBefore : false,
		checkAfterDomReady : true,
		ignoreToken: 'xssfw-token-' + Math.random(),
	};


	if (window.XSS_FW_CONFIG){
		Object.keys(window.XSS_FW_CONFIG).forEach(function (key ){
			XSS_FW_CONFIG[key] = window.XSS_FW_CONFIG[key];
		});
	}

	window.XSS_FW_TOKEN = XSS_FW_CONFIG.ignoreToken;
	
	var reportSubmit = function (type, domStr , dom) {
        console.log('detect xss type :', type, ', dom :', domStr);

		if (XSS_FW_CONFIG.reportBefore){
			var reportBeforeResult = XSS_FW_CONFIG.reportBefore(type , domStr , dom);
			if (reportBeforeResult) {
				reportBeforeResult.type && (type = reportBeforeResult.type);
				reportBeforeResult.domStr && (domStr = reportBeforeResult.domStr);
			}
		}

        if(isReporting || !XSS_FW_CONFIG.reportUrl){
            return ;
        }


        reportArr.push({type: type , domStr: domStr , dom: dom});
        isReporting = true;

        setTimeout(function (){
            var submitReportArr = reportArr ;
            reportArr = [];

            var postData = [];
            for(var i= 0;i<submitReportArr.length ; i++) {
                var reportItem = submitReportArr[i];
                postData.push({type: reportItem.type || ''  , domStr : (reportItem.domStr||'').replace(/[\n\t]/gi, '').substr(0,500) , url : window.location.href });
            }

            var xmlHttp = new XMLHttpRequest() ;
            xmlHttp.open("POST", XSS_FW_CONFIG.reportUrl , true);
            xmlHttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xmlHttp.send('xss-monitor=' + JSON.stringify(postData));

            xmlHttp.onreadystatechange = function (){
                if (xmlHttp.readyState == 4) {
                    isReporting = false;
                }
            }

        },3000);
    }

	

    var reportArr = [];
    var isReporting = false;
    var isAspectJquery = false;
	var	IGNORE_FLAG_NAME = 'xssfw-ignore';


    var clearEventTagNAME = {'IMG': true, 'LINK': true, 'VIDEO': true, 'AUDIO': true, 'IFRAME': true};

    // 校验属性就是可执行的 javascript
    var checkAttrXss = function (str) {
        if (/^javascript:/gi.test(str) &&
            !/^javascript:;?$/gi.test(str) &&
            !/^javascript:void\(0\);?$/gi.test(str) &&
            !/^javascript:;?window\.location\.reload\(\);?$/gi.test(str) &&
            !/^javascript:.?history\.go\(-1\);?$/gi.test(str) &&
            !/^javascript:history\.back\(\);?$/gi.test(str) &&
            !/^javascript:false;?$/gi.test(str)
        ) {
            return true;
        }
        return false;
    };


    var checkIsXssAnchor = function (node) {
        var href = node.getAttribute('href');
        if (checkAttrXss(href)) {
            return true;
        }
        return false;
    };

    var clearEvent = function (node) {
        if (node.hasAttribute('onerror')) {
            reportSubmit('has_onerror', node.outerHTML , node);
        }
        if (node.hasAttribute('onload') ) {
            reportSubmit('has_onload', node.outerHTML , node);
        }


        if (!XSS_FW_CONFIG.reportOnly && !shouldIgnore(node)) {
            node.removeAttribute('onerror');
            node.removeAttribute('onload');
        }
    };

	var shouldIgnore = function (dom){
		if (dom){
			var ignoreValue = dom.getAttribute(IGNORE_FLAG_NAME);
			if (ignoreValue == XSS_FW_CONFIG.ignoreToken) {
				return true;
			}
		}
		return false;
	}

    // 存在内敛的 iframe src 不是http , 过滤
    var filterIframe = function (str) {
        var isMatchXssIframe = false;
		var orgStr = str;
        str = (str || '').replace(/<iframe.*?>/gi, function ($0, $1) {
            var arr = /\bsrc=['"]([^'"]+)/gi.exec($0);
			var ignoreAttr = new RegExp('\\b'+IGNORE_FLAG_NAME+'=[\'"]([^\'"]+)', 'gi').exec($0);

			var shouldIgnore = false;
			if (ignoreAttr && ignoreAttr[1] && ignoreAttr[1] == XSS_FW_CONFIG.ignoreToken){
				shouldIgnore = true;
			}


            if (arr && arr[1] && checkAttrXss(arr[1])) {
                isMatchXssIframe = true;
                if (!XSS_FW_CONFIG.reportOnly && !shouldIgnore) {
                    return '';
                }
            }
            return $0;
        });

        if (isMatchXssIframe) {
            reportSubmit('filterIframe', orgStr);
        }

        return str;
    };

    // 存在内敛的 script，过滤
    var filterScript = function (str) {

        var isMatchXssScript = false;
		var orgStr = str;
        str = (str || '').replace(/<script.*?>/gi, function ($0) {
            var arr = /\btype=['"]([^'"]+)/gi.exec($0);

            if(arr && arr[1] && arr[1] != 'text/javascript' ){
                return $0;
            }

            if (!/\bsrc=/gi.test($0) ) {
                isMatchXssScript = true;
                if (!XSS_FW_CONFIG.reportOnly) {
                    return '';
                }
            }
            return $0;
        });

        if (isMatchXssScript) {
            reportSubmit('filterScript', orgStr);
        }

        return str;
    };


    var detectNode = function (nodes) {
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i];

            // 这些tag 不能存在在内敛代码的事件，存在攻击风险
            if (clearEventTagNAME[node.tagName] ) {
                clearEvent(node);
            }

            if (node.tagName == 'A' && checkIsXssAnchor(node)) {
                reportSubmit('filterHref', node.outerHTML , node);
                if (!XSS_FW_CONFIG.reportOnly && !shouldIgnore(node)) {
                    node.setAttribute('href', 'javascript:;');
                }
                // node.setAttribute("href" , "javascript:;")
            }

            // 内敛script 监控就可以
            if (node.tagName == 'SCRIPT' && !node.src && (!node.type || node.type == 'text/javascript')) {
				//chrome 插件的 content-script 能检测到，但是不在dom中，用这种方式忽略
				if (node.ownerDocument.body.contains(node)){
					 reportSubmit('has_innerScript', node.outerHTML , node);
				}
               
            }

            if (node.childNodes && node.childNodes.length) {
                detectNode(node.childNodes);
            }
        }
    };


    var htmlElementHook = function () {
		var attrHook = function ( name , value ,orgAttrFunc , node){
			if (!checkAttrXss(value)) {
				orgAttrFunc.apply(node,  [name, value ]);
			} else {
				 if (XSS_FW_CONFIG.reportOnly || shouldIgnore(node)) {
					 orgAttrFunc.apply( node, [name, value ]);
				 } 
				 reportSubmit('filterSetAttribute _' + name, node.outerHTML , node);
			}
		}

		// a
        var anchor_raw_href = Object.getOwnPropertyDescriptor(window.HTMLAnchorElement.prototype, 'href');
        Object.defineProperty(window.HTMLAnchorElement.prototype, 'href', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    anchor_raw_href.set.apply(this, arguments);
                } else {
					 if (XSS_FW_CONFIG.reportOnly || shouldIgnore(this)) {
	                     anchor_raw_href.set.apply(this, arguments);
					 }
					 reportSubmit('filterHref', this.outerHTML , this);
                }
            }
        });

		//img
        var img_raw_src = Object.getOwnPropertyDescriptor(window.HTMLImageElement.prototype, 'src');
        Object.defineProperty(window.HTMLImageElement.prototype, 'src', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    img_raw_src.set.apply(this, arguments);
                } else {
					 if (XSS_FW_CONFIG.reportOnly || shouldIgnore(this)) {
	                     img_raw_src.set.apply(this, arguments);
					 }
                    reportSubmit('filterImgSrc', this.outerHTML , this);
                }
            }
        });

	
		// iframe
        var iframe_raw_src = Object.getOwnPropertyDescriptor(window.HTMLIFrameElement.prototype, 'src');
        Object.defineProperty(window.HTMLIFrameElement.prototype, 'src', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    iframe_raw_src.set.apply(this, arguments);
                } else {
					  if (XSS_FW_CONFIG.reportOnly || shouldIgnore(this)) {
	                     iframe_raw_src.set.apply(this, arguments);
					 }
                    reportSubmit('filterIframeSrc', this.outerHTML , this);
                }
            }
        });


		//element
        var element_raw_innerHTML = Object.getOwnPropertyDescriptor(window.Element.prototype, 'innerHTML');
        Object.defineProperty(window.Element.prototype, 'innerHTML', {
            set: function (value) {

                value = filterScript(value);
                value = filterIframe(value);

                element_raw_innerHTML.set.apply(this, arguments);
            }
        });

		var el_setAttribute = window.Element.prototype.setAttribute;
		window.Element.prototype.setAttribute = function (name , value){
			if(this.tagName == 'A' && name == 'href'){
				attrHook(name , value , el_setAttribute , this);
			}else if ( this.tagName == 'IFRAME' && name == 'src' ){
				attrHook(name , value , el_setAttribute , this);
			}else {
				el_setAttribute.apply( this , arguments);
			}
		}
	
    };

    var jqueryHook = function () {
        if (!window.jQuery || !window.$ || isAspectJquery) {
            return;
        }

          /*  
		  //jquery.html 也是调用了 append，无须替换
		  var orgFnHTML = $.fn.html ;
           $.fn.html = function (value){
               if(typeof value != 'string'){
                   return orgFnHTML.apply(this , arguments);
               }
               value = filterScript(value);
               value = filterIframe(value);
               return orgFnHTML.apply(this , arguments);;
           }*/ 


        var orgFnAppend = $.fn.append;
        $.fn.append = function (value) {
            if (typeof value != 'string') {
                return orgFnAppend.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnAppend.apply(this, arguments);
        };

        var orgFnPrepend = $.fn.prepend;
        $.fn.prepend = function (value) {
            if (typeof value != 'string') {
                return orgFnPrepend.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnPrepend.apply(this, arguments);
        };

        var orgFnAfter = $.fn.after;
        $.fn.after = function (value) {
            if (typeof value != 'string') {
                return orgFnAfter.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnAfter.apply(this, arguments);
        };

        var orgFnBefore = $.fn.before;
        $.fn.before = function (value) {
            if (typeof value != 'string') {
                return orgFnBefore.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnBefore.apply(this, arguments);
        };
        isAspectJquery = true;
    };


	//init

	 var observer = new MutationObserver(function (mutations) {
		mutations.forEach(function (mutation) {

            //var startDate = new Date();
            detectNode(mutation.addedNodes);
           // var spendTime = new Date - startDate;
            // console.log("detectNode : " + spendTime + " ms");

        });
    });

	var init = function (){
		observer.observe(document, {
            subtree: true,
            childList: true
        });
        htmlElementHook();
        jqueryHook();
	}

	if(!XSS_FW_CONFIG.checkAfterDomReady){
		init();
	} else {
		document.addEventListener('DOMContentLoaded', function () {
			init();
		}, false);
	}

  


})(window);
