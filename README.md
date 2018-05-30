xss-firewall  -  前端xss防火墙
-----

## 背景 
目前防范XSS 攻击，需要开发者在渲染HTML模板的时候对变量进行转义，然而总会存在忘记转义的情况下。我们无法保证每个开发者都能记得转义，但是我们能受到XSS 攻击的时候，进行拦截和上报。


### Getting Started

**如何使用**
```
//全局配置

window.XSS_FW_CONFIG = {
	reportOnly: true,                               // 只上报，不拦截
	reportUrl : '',                                 // 上报的URL
	reportBefore : false,                           // 上报之前的回调
	checkAfterDomReady : true,                      // 是否在domready 后开始检测
							(由于使用了MutationObserver 扫描，建议保持默认值)
	ignoreToken: 'xssfw-token-' + Math.random(),    // 忽略属性检查的token 
};

<script src='./xss-firewall.js ></script>
```

### 浏览器支持

支持 html5 的浏览器 
ie9+


## 为什么可以拦截

#### 漏洞原因
xss-firewall 为什么可以拦截 xss 攻击，查看一下产生漏洞的原因：
- 插入html ，忘记了 htmlencode
- 设置 ```<a href >``` 值，或则 ```<iframe src>``` 时候，后台没有严格校验，被插入了 javascript:xxxx

#### 拦截方式
1. 假设现在漏洞已经产生，如何拦截:
- 模板带有 ```<script> ```标签 ，会当做XSS 攻击代码过滤掉上报
- 模板带有 ```<iframe src="javascript:xxx"``` 会拦截， 但是正常的src 不会拦截
- 模板带有 ```<img src="xxx" onerror="javascript:xxx"``` onload , onerror onload 会过滤，
- 模板带有 ```<a href="javascript:xxxx" ``` ,  href 属性 会过滤掉
  
2. 来看看以下的攻击范本:
``` javascript
1. ><script>alert(11)</script><
2. ><img src="test1111.png" onerror="javascript:alert(1)" /><
3. <a href="javascript:alert(11);" 
4. iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
```
#### 忽略检查
存在很多情况，我们的属性是执行代码的，可以参考以下代码进行忽略检查，
```javascript
var divEl = document.querySelector('#test');
var xssfwtoken = window.XSS_FW_TOKEN;
divEl.innerHTML = '<a href="javascript:window.history.go(-2)" xssfw-ignore="'+xssfwtoken+'">';
```
但是 ```<script>``` 是不可以忽略检查的






