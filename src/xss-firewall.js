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
        reportUrl: '',
        reportBefore: false,
        checkAfterDomReady: true,
        checkNavigatorUrl: true,

        // 默认不许使用内敛事件，很危险！！
        filterEvent: [
            'onerror', 'onload',
            //form
            'onblur', 'onchange', 'oncontextmenu', 'onfocus', 'onformchange', 'onforminput', 'oninput', 'oninvalid', 'onreset', 'onselect', 'onsubmit',
            //Mouse
            'onkeydown', 'onkeypress', 'onkeyup',
            //click
            'onclick', 'ondblclick', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',

        ],
        ignoreToken: 'xssfw-token-' + Math.random(),
    };

    var reportArr = [];
    var isReporting = false;
    var isAspectJquery = false;
    var IGNORE_FLAG_NAME = 'xssfw-ignore';
    //var clearEventTagNAME = { 'IMG': true, 'LINK': true, 'VIDEO': true, 'AUDIO': true, 'IFRAME': true };


    if (window.XSS_FW_CONFIG) {
        Object.keys(window.XSS_FW_CONFIG).forEach(function (key) {
            XSS_FW_CONFIG[key] = window.XSS_FW_CONFIG[key];
        });
    }

    window.XSS_FW_TOKEN = XSS_FW_CONFIG.ignoreToken;

    var reportSubmit = function (type, domStr, dom) {
        console.log('%cdetect xss %ctype: ' + type + ' dom: ' + domStr, 'color:red', 'color:black');

        if (XSS_FW_CONFIG.reportBefore) {
            var reportBeforeResult = XSS_FW_CONFIG.reportBefore(type, domStr, dom);
            if (reportBeforeResult) {
                reportBeforeResult.type && (type = reportBeforeResult.type);
                reportBeforeResult.domStr && (domStr = reportBeforeResult.domStr);
            }
        }

        if (isReporting || !XSS_FW_CONFIG.reportUrl) {
            return;
        }


        reportArr.push({type: type, domStr: domStr, dom: dom});
        isReporting = true;

        setTimeout(function () {
            var submitReportArr = reportArr;
            reportArr = [];

            var postData = [];
            for (var i = 0; i < submitReportArr.length; i++) {
                var reportItem = submitReportArr[i];
                postData.push({
                    type: reportItem.type || '',
                    domStr: (reportItem.domStr || '').replace(/[\n\t]/gi, '').substr(0, 500),
                    url: window.location.href
                });
            }

            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open('POST', XSS_FW_CONFIG.reportUrl, true);
            xmlHttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xmlHttp.send('xss-monitor=' + JSON.stringify(postData));

            xmlHttp.onreadystatechange = function () {
                if (xmlHttp.readyState == 4) {
                    isReporting = false;
                }
            };

        }, 3000);
    };


    // 校验属性是否可执行的 javascript
    var checkAttrXss = function (str) {
        if (/^javascript:/gi.test(str) &&
            !/^javascript:;?$/gi.test(str) &&
            !/^javascript:void\(0\);?$/gi.test(str) &&
            !/^javascript:;?window\.location\.reload\(\);?$/gi.test(str) &&
            !/^javascript:.?history\.go\(-1\);?$/gi.test(str) &&
            !/^javascript:history\.back\(\);?$/gi.test(str) &&
            !/^javascript:false;?$/gi.test(str)) {
            return true;
        } else if (/^data:text\/html/gi.test(str)) {
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
        if (!XSS_FW_CONFIG.filterEvent || !node.hasAttribute) {
            return;
        }
        for (var i = 0; i < XSS_FW_CONFIG.filterEvent.length; i++) {
            var eventName = XSS_FW_CONFIG.filterEvent[i];
            if (node.hasAttribute(eventName)) {
                reportSubmit('has_' + eventName, node.outerHTML, node);
            }

            if (!XSS_FW_CONFIG.reportOnly && !shouldIgnore(node)) {
                node.removeAttribute(eventName);
            }
        }

    };

    var shouldIgnore = function (dom) {
        if (dom) {
            var ignoreValue = dom.getAttribute(IGNORE_FLAG_NAME);
            if (ignoreValue == XSS_FW_CONFIG.ignoreToken) {
                return true;
            }
        }
        return false;
    };


    var getAttrList = function (content) {
        content = (content || '').replace(/^<[\w]+/i, '').replace(/>$/i, '').split(' ');
        var arr = [];
        content.forEach(function (attStr) {
            if (!attStr) {
                return;
            }
            attStr = attStr.replace(/ +/, '');
            var tmpAtt = attStr.split('=') || [];
            // 避免参数中有个= 的问题
            var name = tmpAtt[0] || '';
            tmpAtt[0] = '';
            arr.push({name: name, value: (tmpAtt.join('') || '').replace(/['"]/gi, '')});
        });
        return arr;
    }

    // 存在内敛的 iframe src 不是http , 过滤
    var filterIframe = function (str) {
        var isMatchXssIframe = false;
        var orgStr = str;
        str = (str || '').replace(/<iframe.*?>/gi, function ($0, $1) {
            var attrList = getAttrList($0);

            //无src ，存在 onload ，会直接触发onload
            var srcArr, onloadArr, ignoreAttr;
            attrList.forEach(function (attr) {
                if (attr.name == 'src') {
                    srcArr = [attr.name, attr.value];
                }

                if (attr.name == 'onload') {
                    onloadArr = [attr.name, attr.value];
                }

                if (attr.name == IGNORE_FLAG_NAME) {
                    ignoreAttr = [attr.name, attr.value];
                }

            });


            var isShouldIgnore = false;
            if (ignoreAttr && ignoreAttr[1] && ignoreAttr[1] == XSS_FW_CONFIG.ignoreToken) {
                isShouldIgnore = true;
            }


            if (srcArr && srcArr[1] && checkAttrXss(srcArr[1])) {
                isMatchXssIframe = true;
                if (!XSS_FW_CONFIG.reportOnly && !isShouldIgnore) {
                    return '';
                }
            }

            if (onloadArr && onloadArr[1] && XSS_FW_CONFIG.filterEvent.indexOf('onload') > -1) {
                isMatchXssIframe = true;
                if (!XSS_FW_CONFIG.reportOnly && !isShouldIgnore) {
                    return '';
                }
            }

            if (!isShouldIgnore) {
                $0 = $0.replace(/\bsrcdoc=/gi, ' unsrcdoc=');
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

            var arr ;
            var attrList = getAttrList($0);
            attrList.forEach(function (attr) {
                if (attr.name == 'type') {
                    arr = [attr.name, attr.value];
                }
            })

            if (arr && arr[1] && arr[1] != 'text/javascript') {
                return $0;
            }

            if (!/\bsrc=/gi.test($0)) {
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
            // if (clearEventTagNAME[node.tagName]) {
            clearEvent(node);
            //}

            if (node.tagName == 'A' && checkIsXssAnchor(node)) {
                reportSubmit('filterHref', node.outerHTML, node);
                if (!XSS_FW_CONFIG.reportOnly && !shouldIgnore(node)) {
                    node.setAttribute('href', 'javascript:;');
                }
                // node.setAttribute("href" , "javascript:;")
            }

            // 内敛script 监控就可以
            if (node.tagName == 'SCRIPT' && !node.src && (!node.type || node.type == 'text/javascript')) {
                // chrome 插件的 content-script 能检测到，但是不在dom中，用这种方式忽略
                if (node.ownerDocument.body.contains(node)) {
                    reportSubmit('has_innerScript', node.outerHTML, node);
                }

            }

            if (node.childNodes && node.childNodes.length) {
                detectNode(node.childNodes);
            }
        }
    };

    var htmlElementHook = function () {
        var attrHook = function (name, value, orgAttrFunc, node) {
            if (!checkAttrXss(value)) {
                orgAttrFunc.apply(node, [name, value]);
            } else {
                if (XSS_FW_CONFIG.reportOnly || shouldIgnore(node)) {
                    orgAttrFunc.apply(node, [name, value]);
                }
                reportSubmit('filterSetAttribute _' + name, node.outerHTML, node);
            }
        };

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
                    reportSubmit('filterHref', this.outerHTML, this);
                }
            }
        });

        // img
        var img_raw_src = Object.getOwnPropertyDescriptor(window.HTMLImageElement.prototype, 'src');
        Object.defineProperty(window.HTMLImageElement.prototype, 'src', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    img_raw_src.set.apply(this, arguments);
                } else {
                    if (XSS_FW_CONFIG.reportOnly || shouldIgnore(this)) {
                        img_raw_src.set.apply(this, arguments);
                    }
                    reportSubmit('filterImgSrc', this.outerHTML, this);
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
                    reportSubmit('filterIframeSrc', this.outerHTML, this);
                }
            }
        });


        // element
        var element_raw_innerHTML = Object.getOwnPropertyDescriptor(window.Element.prototype, 'innerHTML');
        Object.defineProperty(window.Element.prototype, 'innerHTML', {
            set: function (value) {

                value = filterScript(value);
                value = filterIframe(value);

                element_raw_innerHTML.set.apply(this, arguments);
            }
        });

        var el_setAttribute = window.Element.prototype.setAttribute;
        window.Element.prototype.setAttribute = function (name, value) {
            if (this.tagName == 'A' && name == 'href') {
                attrHook(name, value, el_setAttribute, this);
            } else if (this.tagName == 'IFRAME' && name == 'src') {
                attrHook(name, value, el_setAttribute, this);
            } else {
                el_setAttribute.apply(this, arguments);
            }
        };

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
         } */


        var orgFnAppend = $.fn.append;
        $.fn.append = function (value) {
            if (typeof value !== 'string') {
                return orgFnAppend.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnAppend.apply(this, arguments);
        };

        var orgFnPrepend = $.fn.prepend;
        $.fn.prepend = function (value) {
            if (typeof value !== 'string') {
                return orgFnPrepend.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnPrepend.apply(this, arguments);
        };

        var orgFnAfter = $.fn.after;
        $.fn.after = function (value) {
            if (typeof value !== 'string') {
                return orgFnAfter.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnAfter.apply(this, arguments);
        };

        var orgFnBefore = $.fn.before;
        $.fn.before = function (value) {
            if (typeof value !== 'string') {
                return orgFnBefore.apply(this, arguments);
            }

            value = filterScript(value);
            value = filterIframe(value);

            return orgFnBefore.apply(this, arguments);
        };
        isAspectJquery = true;
    };

    var sysHook = function (){
        var orgFnWrite = document.write;
        var orgFnWriteln = document.writeln;
        // var orgFnEval = window.eval;

        document.write = function (value){
            value = filterScript(value);
            value = filterIframe(value);
            return orgFnWrite.apply(this,arguments);
        }

        document.writeln = function (value){
            value = filterScript(value);
            value = filterIframe(value);
            return orgFnWriteln.apply(this,arguments);
        }

       /* 好像没有必要重写这个。这个是用户主动运行的代码
       window.eval = function (value){
            value = filterScript(value);
            value = filterIframe(value);
            return orgFnEval.apply(this,arguments);
        }*/

    }

    var unescapeUrl = function (url, codeUrl) {
        for (var arr = [], o = 0; o < url.length; o++) if ("&" == url.charAt(o)) {
            var a = [3, 4, 5, 9], r = 0;
            for (var c in a) {
                var i = a[c];
                if (o + i <= url.length) {
                    var m = url.substr(o, i).toLowerCase();
                    if (codeUrl[m]) {
                        arr.push(codeUrl[m]), o = o + i - 1, r = 1;
                        break
                    }
                }
            }
            0 == r && arr.push(url.charAt(o))
        } else arr.push(url.charAt(o));
        return arr.join("")
    }

    var checkNavigatorUrl = function () {
        var codeMap = {}, codeStr = "'\"<>`script:daex/hml;bs64,";
        for (var n = 0; n < codeStr.length; n++) {
            var charAt = codeStr.charAt(n),
                charCodeAt = charAt.charCodeAt(),
                charCodeAt2 = charCodeAt,
                chartCodeAt16 = charCodeAt.toString(16);
            for (var i = 0; i < 7 - charCodeAt.toString().length; i++) charCodeAt2 = "0" + charCodeAt2;
            codeMap["&#" + charCodeAt + ";"] = charAt, codeMap["&#" + charCodeAt2] = charAt, codeMap["&#x" + chartCodeAt16] = charAt;
        }
        codeMap["&lt"] = "<", codeMap["&gt"] = ">", codeMap["&quot"] = '"';

        var pageHref = location.href;
        pageHref = decodeURIComponent(unescapeUrl(pageHref, codeMap));

        var reg = new RegExp("['\"<>`]|script:|data:text/html;base64,");
        if (reg.test(pageHref)) {
            pageHref = pageHref.replace(/['\"<>`]|script:/gi, "M").replace(/data:text\/html;base64,/gi, "data:text/plain;base64,");
            location.href = encodeURI(pageHref);
        }
    }


    // init

    var observer = new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {

            // var startDate = new Date();
            detectNode(mutation.addedNodes);
            // var spendTime = new Date - startDate;
            // console.log("detectNode : " + spendTime + " ms");

        });
    });

    var init = function () {
        observer.observe(document, {
            subtree: true,
            childList: true
        });
        htmlElementHook();
        jqueryHook();
        sysHook();

    };

    //检测反射性xss攻击
    if (XSS_FW_CONFIG.checkNavigatorUrl) {
        checkNavigatorUrl();
    }

    if (!XSS_FW_CONFIG.checkAfterDomReady) {
        init();
    } else {
        document.addEventListener('DOMContentLoaded', function () {
            init();
        }, false);
    }


})(window);
