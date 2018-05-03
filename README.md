css 主动防御

#攻击范本：
><script>alert(11)</script><
><img src="javascript:alert(1)" onerror="javascript:alert(1)" /><
javascript:alert(11);


#漏洞点：
$el.html(xss);   // 限制提取 javascript 运行
el.innerHTML = xss  //
el.setAttribute("src" , xss) // src 钩子
#el.appendChild(xss);
//document.write(xss);
//<a href="xss" >
<img src="xss"  />
<object src="xss">
<iframe src="xss" onerror="xss" />


#生成漏洞的几个原因：
1. 插入html ，自行拼接html忘记了 htmlencode
2. 设置属性，没有考虑到 javascript:
3. 模板在属性里面渲染数据， 没有考虑到  javascript:






