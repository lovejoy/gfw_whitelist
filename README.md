# GFW 白名单


概述 
-----

著名 [autoproxy.pac](https://autoproxy.org) (GFW List)  是一个 GFW 黑名单，访问名单中网站需要通过代理，不在名单中的网站直接访问。有效使用黑名单，维护者和用户都需要时常更新此名单，否则可能不能访问最近被墙的网站。这些不便之处是推广翻墙运动的阻碍。

白名单的方法是白名单中的网站不走代理，其它网站全部通过代理访问。白名单的优点是对维护的要求较低。第一次安装后，即使很长时间不更新，也不会出现网站打不开的问题。当然，用户会要付出稍多一些流量。

现实上 GFW 已经开始白名单化，国外稍微有点意思的网站大都已经被墙，或者随时可能被墙。因此我们认为有必要开始维护一份白名单的 pac 文件。

***作者收录的国内 CDN 和“云”相关的域名还非常有限。希望同学们能够帮助补充。感谢。***
<br /> <br />

使用方法
---------

下载 gfw_whitelist.pac 文件后，修改代理服务器的 ip 地址和代理类型。然后将浏览器的代理设置中指向 gfw_whitelist.pac。


```
var ip_address = '172.16.66.77:3000';
```

```
var proxy_type = 'HTTPS'; // or 'SOCKS'
```

当 `proxy_type`  选为 `HTTPS` 时，此 pac 文件适合用于 [Google Chrome 的安全代理](http://www.chromium.org/developers/design-documents/secure-web-proxy)。

<br /> 


Google Chrome 安全代理 （SSL Secure Proxy）
-----------

_Firefox 好像也有支持安全代理了。作者还没有测试过。_

<img src="http://i.imgur.com/T2ZGc.png" style="float: right; width: 40%" alt="" /></a>

<div style="width: 55%" markdown="1">


Google Chrome 已经支持基于 https 和 SPDY 的安全代理。其原理和效果与 SSH，shadowsocks 以及 goagent 类似：

* 将普通流量封装在加密通道之中，这样 GFW 就看不见流量的内容；
* 域名的解析在代理服务器这端完成，所以本地不用担心域名污染的问题。配合 pac 的使用，可以享受国内 CDN 的服务。达到一次设置完全免维护；
* 本地不从服务器端取得 ip，只适合浏览器内的应用，不适合 VoIP，网络游戏等应用。

优点有：

* 在 PC 和 Mac 上 Chrome 已经原生支持，不需要依赖额外的客户端；
* 封装的协议是 https 或 SPDY，GFW 完全没有 DPI 识别的可能，这是翻墙终极方案的一部分；
* 由 Google 支持，客户端和服务器端的软件成熟并且稳定，未来更新也可靠。

现有的缺点有：

* 暂时只适用于 PC 和 Mac 上的 Chrome。 Android 的客户端有待开发。iOS 客户端的可行性暂时还不清楚。

***有兴趣开发客户端的同学，可以考虑编译封装 @tatsuhiro-t 的 C 程序库 [spdylay](https://github.com/tatsuhiro-t/spdylay) 。***

```
shrpx --client-proxy [-b <HOST,PORT>] [-f <HOST,PORT>] 
				   [OPTIONS...] [<PRIVATE_KEY> <CERT>]
```

</div>

<br />

其它节省流量的方法
----------------
<div style="width: 100%" markdown="1">
<img src="http://i.imgur.com/u15Aj.png" style="float: right; width: 40%" alt="" /></a>

<div style="width: 60%" markdown="1">

由于白名单的流量消耗较黑名单要高一些，在浏览器中安装下面的扩展，在提高网页浏览速度的同时，也能节省不少流量。

##### 屏蔽广告： Adblock Plus ＋ Easylist ＋ Chinalist

在 Firefox 或 Chrome 中安装 [Adblock Plus](http://adblockplus.org/en/) (ABP) 扩展，并在 ABP 的控制面板中加入 Easylist 和 [Chinalist](http://code.google.com/p/adblock-chinalist/)。这样可以有效的过滤广告大部分网站和网页。

`注意`：下载扩展和 ChinaList 的时候可能需要打开全局翻墙的 VPN 。

##### 屏蔽Flash： FlashControl 或 FlashBlock

在 Chrome 中安装 [FlashControl](https://chrome.google.com/webstore/detail/flashcontrol/mfidmkgnfgnkihnjeklbekckimkipmoe) 或在 Firefox 中安装 [FlashBlock](https://addons.mozilla.org/zh-cn/firefox/addon/flashblock/)，可以达到屏蔽 Flash 的效果。需要打开 Flash，比如视频，只要在被屏蔽的 Flash 上点击一次。

</div>
</div>

<br /> <br />




------

© 2012-2013 地下铁路，MIT License。 本文档使用了 [<span style="height:1em"> <img style="height: 1em" src="http://mouapp.com/Mou_128.png"></span>](//mouapp.com) 和 [marked](http://markedapp.com) 进行编辑。
