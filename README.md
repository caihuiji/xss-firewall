xss 防火墙
-----

##背景 
>目前防范XSS 攻击，需要开发者在渲染HTML模板的时候对变量进行转义，然而总会存在忘记转义的情况下。我们无法保证每个开发者都能记得转义，但是我们能受到XSS 攻击的时候，进行拦截和上报。

**适用场景**
1. 浏览器
支持html5 的浏览器( ie9+)

## Getting Started

**如何使用**
```
//全局配置
window.XSS_FW_CONFIG = {
		reportOnly: true,                               // 只上报，不拦截
		reportUrl : '',                                 // 上报的URL
		reportBefore : false,                           // 上报之前的回调
		checkAfterDomReady : true,                      // 是否在domready 后开始检测(由于使用了MutationObserver 扫描，建议保持默认值)
		ignoreToken: 'xssfw-token-' + Math.random(),    // 忽略属性检查的token 
	};
<script src='./xss-firewall.js ></script>
```

## 为什么可以拦截


**漏洞的几个原因**

1. 插入html ，自行拼接html忘记了 htmlencode
2. 设置属性，没有考虑到 javascript:xxxx
3. 模板在属性里面渲染数据， 没有考虑到  javascript:

**可拦截哪些xss攻击**

1. 模板带有 <script> 标签 ，会当做XSS 攻击代码过滤掉上报
2. 模板带有 <iframe src="javascript:xxx" 会拦截， 但是正常的src 不会拦截
3. 模板带有 <img src="xxx" onerror="javascript:xxx" onload , onerror onload 会过滤，
4. 模板带有 <a href="javascript:xxxx" ,  href 属性 会过滤掉
  
以上代码不过滤，都有可能留有漏洞，来看看以下的攻击范本:
``` javascript
1. ><script>alert(11)</script><
2. ><img src="test1111.png" onerror="javascript:alert(1)" /><
3. <a href="javascript:alert(11);" 
4. iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
```



#漏洞点：
1. $el.html(xss);   // 限制提取 javascript 运行
2. el.innerHTML = xss  // 
3. el.setAttribute("src" , xss) // src 钩子
4. el.appendChild(xss);
5. document.write(xss);
6. <a href="xss" >
7. <img src="xss" onerror="xss"  />
8. <object src="javascript:xss">
9. <iframe src="javascript:xss"  />





钩子 拦截：
defineProperty ,监控 src , href ,  是否有注入风险
HTMLAnchorElement.href
HTMLImageElement.src
HTMLIFrameElement.src






