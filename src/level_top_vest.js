/* eslint accessor-pairs: "off" */

/**
 *  level-top-vest --  前端 xss-防火墙
 */

(function () {


    if (!window.MutationObserver || !window.Object.defineProperty) {
        return;
    }


    window.XSS_MONITOR_REPORT_ONLY =  !!window.XSS_MONITOR_REPORT_ONLY  ;
    window.XSS_MONITOR_REPORT_URL = window.XSS_MONITOR_REPORT_URL ;
    var reportArr = [];
    var isReporting = false;
    var isAspectJquery = false;


    window.XSS_MONITOR_REPORT_LOG = function (type, domStr , dom) {
        if( dom &&  dom.hasAttribute('ignore-xss-monitor')) {
            return ;
        }
        console.log('detect xss type :', type, ', dom :', domStr);

        reportArr.push({type: type , domStr: domStr , dom: dom});

        if(isReporting){
            return ;
        }

        if(!window.XSS_MONITOR_REPORT_URL){
            return ;
        }

        isReporting = true;
        setTimeout(function (){
            var submitReportArr = reportArr ;
            reportArr = [];

            var postData = [];
            for(var i= 0;i<submitReportArr.length ; i++) {
                var reportItem = submitReportArr[i];
                postData.push({type: reportItem.type || ''  , domStr : (reportItem.domStr||'').substr(0,100) , url : window.location.href });
            }

            var xmlHttp = new XMLHttpRequest() ;
            xmlHttp.open("POST", window.XSS_MONITOR_REPORT_URL , true);
            xmlHttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xmlHttp.send('xss-monitor=' + JSON.stringify(postData));

        },3000)
    };


    var clearEventTagNAME = {'IMG': true, 'LINK': true, 'VIDEO': true, 'AUDIO': true, 'IFRAME': true};

    // 校验属性就是可执行的 javascript
    var checkAttrXss = function (str) {
        if (/^javascript:/gi.test(str) &&
            !/^javascript:;?$/gi.test(str) &&
            !/^javascript:void\(0\);?$/gi.test(str) &&
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
            window.XSS_MONITOR_REPORT_LOG('has_onerror', node.outerHTML , node);
        }
        if (node.hasAttribute('onload')) {
            window.XSS_MONITOR_REPORT_LOG('has_onload', node.outerHTML , node);
        }


        if (!window.XSS_MONITOR_REPORT_ONLY) {
            node.removeAttribute('onerror');
            node.removeAttribute('onload');
        }
    };

    // 存在内敛的 iframe src 不是http , 过滤
    var filterIframe = function (str) {
        var isMatchXssIframe = false;
        (str || '').replace(/<iframe.*?>/gi, function ($0, $1) {
            var arr = /src=['"]([^'"]+)/gi.exec($0);
            if (arr && checkAttrXss(arr[1])) {
                isMatchXssIframe = true;
                if (!window.XSS_MONITOR_REPORT_ONLY) {
                    return '';
                }
            }
            return $0;
        });

        if (isMatchXssIframe) {
            window.XSS_MONITOR_REPORT_LOG('filterIframe', str);
        }

        return str;
    };

    // 存在内敛的 script，过滤
    var filterScript = function (str) {

        var isMatchXssScript = false;
        (str || '').replace(/<script.*?>/gi, function ($0) {
            if (!/\bsrc=/gi.test($0)) {
                isMatchXssScript = true;
                if (!window.XSS_MONITOR_REPORT_ONLY) {
                    return '';
                }
            }
            return $0;
        });

        if (isMatchXssScript) {
            window.XSS_MONITOR_REPORT_LOG('filterScript', str);
        }

        return str;
    };


    var detectNode = function (nodes) {
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i];

            // 这些tag 不能存在在内敛代码的事件，存在攻击风险
            if (clearEventTagNAME[node.tagName]) {
                clearEvent(node);
            }

            if (node.tagName == 'A' && checkIsXssAnchor(node)) {
                window.XSS_MONITOR_REPORT_LOG('filterHref', node.outerHTML , node);
                if (!window.XSS_MONITOR_REPORT_ONLY) {
                    node.setAttribute('href', 'javascript:;');
                }
                // node.setAttribute("href" , "javascript:;")
            }

            // 内敛script 监控就可以
            if (node.tagName == 'SCRIPT' && !node.src && (!node.type || node.type == 'text/javascript')) {
                window.XSS_MONITOR_REPORT_LOG('has_innerScript', node.outerHTML , node);
            }

            if (node.childNodes && node.childNodes.length) {
                detectNode(node.childNodes);
            }
        }
    };

    var speedReport = [];
    var isSpeedReporting = false;
    var observer = new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {

            var startDate = new Date();
            detectNode(mutation.addedNodes);
            var spendTime = new Date - startDate;
            // console.log("detectNode : " + spendTime + " ms");

            speedReport.push(spendTime);

            if (isSpeedReporting){
                return ;
            }
            isSpeedReporting = true;

            setTimeout(function (){

                while(speedReport.length){
                    var sumibtReport = speedReport.splice(0,20);
                    var img = new Image();
                    img.src = 'https://mail.qq.com/xly_report/report?q=st%3Aspeed%3Dk%3D78501976%26v%3D' + sumibtReport.join("&q=st%3Aspeed%3Dk%3D78501976%26v%3D") + '&_t=' + Math.random();
                }

                speedReport = [];
                isSpeedReporting = false;

            },3000)

        });
    });


    var injectMonitor = function () {
        var anchor_raw_href = Object.getOwnPropertyDescriptor(window.HTMLAnchorElement.prototype, 'href');
        Object.defineProperty(window.HTMLAnchorElement.prototype, 'href', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    anchor_raw_href.set.apply(this, arguments);
                } else {
                    window.XSS_MONITOR_REPORT_LOG('filterHref', this.outerHTML , this);
                }
            }
        });

        var img_raw_src = Object.getOwnPropertyDescriptor(window.HTMLImageElement.prototype, 'src');
        Object.defineProperty(window.HTMLImageElement.prototype, 'src', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    img_raw_src.set.apply(this, arguments);
                } else {
                    window.XSS_MONITOR_REPORT_LOG('filterImgSrc', this.outerHTML , this);
                }
            }
        });

        var iframe_raw_src = Object.getOwnPropertyDescriptor(window.HTMLIFrameElement.prototype, 'src');
        Object.defineProperty(window.HTMLIFrameElement.prototype, 'src', {
            set: function (url) {
                if (!checkAttrXss(url)) {
                    iframe_raw_src.set.apply(this, arguments);
                } else {
                    window.XSS_MONITOR_REPORT_LOG('filterIframeSrc', this.outerHTML , this);
                }
            }
        });

        var element_raw_innerHTML = Object.getOwnPropertyDescriptor(window.Element.prototype, 'innerHTML');
        Object.defineProperty(window.Element.prototype, 'innerHTML', {
            set: function (value) {

                value = filterScript(value);
                value = filterIframe(value);

                element_raw_innerHTML.set.apply(this, arguments);
            }
        });
    };

    var aspectJquery = function () {
        if (!window.jQuery || !window.$ || isAspectJquery) {
            return;
        }

        /*   var orgFnHTML = $.fn.html ;
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
    /*
        observer.observe(document, {
            subtree: true,
            childList: true
        });
        injectMonitor();
        aspectJquery();*/

    document.addEventListener('DOMContentLoaded', function () {
        observer.observe(document, {
            subtree: true,
            childList: true
        });
        injectMonitor();
        aspectJquery();
    }, false);


})(window);
