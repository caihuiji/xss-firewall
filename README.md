css 主动防御

#背景
目前防范XSS 攻击，需要开发者在渲染HTML模板的时候对变量进行转义，然而总会存在忘记转义的情况下。我们无法保证每个开发者都能记得转义，但是我们能受到XSS 攻击的时候，进行拦截和上报。

#适用场景
浏览器
ie9+ , chrome , firefox
适合架构
1. view-logic 分离， 内敛的 script 不可编写，否则会当做XSS 攻击代码过滤掉上报
2. dom level 1 事件（内敛事件）不可存在，否则会当做xss攻击过滤掉

注意：
xss-firewall 只做最后一道防线，请确保在此之前 已经启动html转义和csp 

demo : 
#攻击范本：
``` javascript
1. ><script>alert(11)</script><
2. ><img src="javascript:alert(1)" onerror="javascript:alert(1)" /><
3. javascript:alert(11);
4. data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
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



#生成漏洞的几个原因：
1. 插入html ，自行拼接html忘记了 htmlencode
2. 设置属性，没有考虑到 javascript:
3. 模板在属性里面渲染数据， 没有考虑到  javascript:



#内敛html 拦截
1. jquery.html 替换
2. innerHTMl  (script 不能执行)

插入的DOM时候:html属性中有存在 src,href,onload,onerror 攻击
其中， src , href 可以设置 javascript 协议，即为攻击（非 javascript:;  javascript:void(0);）
onload onerror、onclick ....  应该是不允许的， 所以即为攻击(都改用在 javascript addEventListener 主动监听 )



钩子 拦截：
defineProperty ,监控 src , href ,  是否有注入风险
HTMLAnchorElement.href
HTMLImageElement.src
HTMLIFrameElement.src






