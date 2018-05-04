css 主动防御

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
8. <object src="xss">
9. <iframe src="xss"  />



#生成漏洞的几个原因：
1. 插入html ，自行拼接html忘记了 htmlencode
2. 设置属性，没有考虑到 javascript:
3. 模板在属性里面渲染数据， 没有考虑到  javascript:






