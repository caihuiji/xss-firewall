xss-firewall  -  前端xss防火墙
-----
目前防范XSS 攻击，需要开发者在渲染HTML模板的时候对变量进行转义，然而总会存在忘记转义的情况下。我们无法保证每个开发者都能记得转义，但是我们可以在受到XSS 攻击的时候，进行拦截和上报。

<br>

## Getting Started

**如何使用**
```
//全局配置

window.XSS_FW_CONFIG = {
	reportOnly: true,                               // 只上报，不拦截
	reportUrl : '',                                 // 上报的URL
	reportBefore : function(){}                     // 上报之前的回调
	filterEvent : ['onerror' , 'onload'] ,          // 过滤内敛标签中的事件，默认只有 onerror,onload
 	checkAfterDomReady : true,                      // 是否在domready 后开始检测
							(由于使用了MutationObserver 扫描，建议保持默认值)
	ignoreToken: 'xssfw-token-' + Math.random(),    // 忽略属性检查的token 
};

<script src='./xss-firewall.js ></script>
```

**接收上报**

目前上报使用xhr2 的跨域post提交，如果是跨域请求，请在服务器端开启跨域。
上报格式如下：
```javascript
//type 
// has_innerScript - 存在内联的script
// filterHref,filterSetAttribute_href      - 过滤了 a href
// filterImgSrc    			   - 过滤了img src
// filterIframeSrc,filterSetAttribute_src  - 过滤了iframe src
// filterScript    			   - 过滤了 script
// filterIframe    			   - 过滤了 iframe 
// has_onerror,has_onload 		   - 过滤了 onerror , onload

var submitArray = [{type :'has_innerScript' , domStr :'<a href="javascript:alert(111)"' , url : 'http://test.com'  }] ;

post( 'xss-monitor=' + JSON.stringfy(submitArray))
```

更详细使用方式可以查看 ```test/demo.html```

### 浏览器支持

ie11+和其他常用的浏览器

<br>

## 为什么可以拦截

#### 漏洞原因
先来看看产生漏洞的原因：
- 插入html ，忘记了 htmlencode
- 设置 ```<a href >``` 值，或则 ```<iframe src>``` 时候，后台没有严格校验，被插入了 javascript:xxxx

#### 拦截方式
1. 假设现在漏洞已经产生，如何拦截:
- 插入的html片段带有 ```<script> ```标签 ，会当做XSS 攻击代码过滤掉并上报
- 插入的html片段带有 ```<iframe src="javascript:xxx"``` 会拦截并上报， 但是正常的src 不会拦截
- 插入的html片段带有 ```<img src="xxx" onload="" onerror="javascript:xxx"```  , onerror onload 会过滤并上报
- 插入的html片段带有 ```<a href="javascript:xxxx" ``` ,  href 属性会过滤掉并上报
  
2. 例如以下的攻击范本:
``` javascript
1. ><script>alert(11)</script><
2. ><img src="test1111.png" onerror="javascript:alert(1)" /><
3. <a href="javascript:alert(11);" 
4. iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
```
#### 忽略检查
存在很多情况，我们的属性是执行代码的，可以参考以下代码进行忽略检查：
```javascript
var divEl = document.querySelector('#test');
var xssfwtoken = window.XSS_FW_TOKEN;
divEl.innerHTML = '<a href="javascript:window.history.go(-2)" xssfw-ignore="'+xssfwtoken+'">';
```
但是 ```<script>``` 是不可以忽略检查的

<br>

## 其他

#### 开启了 csp(content-security-policy) ，还需要用xss-firewall 吗？
开启CSP ，可以最大程度的限制插入恶意的js和上报信息（用img 上报给恶意网站）。
但是还是存在漏洞 ```iframe src``` 和  ```href="javascript:window.location.href=xxxx"``` 上报信息的。

#### 用了vuejs或则reactjs ，还需要用xss-firewall 吗？
这些框架都是限制了开发者使用innerHTML插入代码，在渲染模版的时候变量都会默认进行html转义。
但是没有针对**漏洞原因2**进行处理

> 所以，xss-firewall 是最后一道防线和监控  ^_^






