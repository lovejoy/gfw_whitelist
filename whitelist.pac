/*
            gfw_whitelist.pac
  
            GFW Whitelist
            - inspired by autoproxy and chnroutes
  
            v1.2
            Author: n0gfwall0@gmail.com
            License: MIT License

                                                          */


function FindProxyForURL(url, host)
{
    /* * * * * * * * * * * * * * * * * * * * * * * * * * 
     *                                                 *
     *  一定要换成你的ip地址                           *
     *  Replace your proxy ip-address:port here!!      *
     *                                                 *
     * * * * * * * * * * * * * * * * * * * * * * * * * */

    var ip_address = '127.0.0.1:1155';

    /* * * * * * * * * * * * * * * * * * * * * * * * * * 
     *                                                 *
     * 代理类型 (翻墙一般适用 SOCKS 或 HTTPS)          *
     * Proxy type                                      *
     *                                                 *
     * * * * * * * * * * * * * * * * * * * * * * * * * */
    var proxy_type = 'SOCKS'; // or 'SOCKS' 

    // HTTPS 是用于 Chrome 的安全代理
    // http://www.chromium.org/developers/design-documents/secure-web-proxy


    /* * * * * * * * * * * * * * * * * * * * * * * * * */
    var proxy = proxy_type + ' ' + ip_address;


    // Avoid calling any functions that might invoke the DNS resoultion.
    var url = url.toLowerCase();
    var host = host.toLowerCase();

    // skip local hosts
    if (isPlainHostName(host)) return 'DIRECT';

    // skip cn domains
    if (shExpMatch(host,"*.cn")) return 'DIRECT';

    // skip ftp
    if (shExpMatch(url, "ftp:*")) return 'DIRECT';

    // check if the ipv4 format (TODO: ipv6)
    //   http://home.deds.nl/~aeron/regex/
    var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
    if (re_ipv4.test(host)) {
        // in theory, we can add chnroutes test here.
        // but that is probably too much an overkill.
        return 'DIRECT';
    } 

    // a very long list. trust chrome will cache the results

    // skip top Chinese sites
    // source: 
    // (1) custom list
    // (2) https://dl-web.dropbox.com/u/3241202/apps/chn-cdn/dnsmasq.server.conf
    // (3) Domestic CDN and cloud
    // (4) alexa 500
    //     less all the cn domains
    //     less google.com.hk, google.com, google.co.uk, googleusercontent.com
    //     google.com.tw, tumblr.com, wikipedia.org, youtube, github, wordpress
    //     wsj.com, godaddy,stackoverflow.com, zaobao.com

    // custom list. feel free to add.
    // mostly ad servers and img servers
    if(
        dnsDomainIs(host,"google.com") || shExpMatch(host, "*.google.com") || 
        dnsDomainIs(host,"google.com.hk") || shExpMatch(host, "*.google.com.hk") || 
        dnsDomainIs(host,"mufg.jp") || shExpMatch(host, "*.mufg.jp") || 
        dnsDomainIs(host,"wikipedia.org") || shExpMatch(host, "*.wikipedia.org") || 
        dnsDomainIs(host,"wikimedia.org") || shExpMatch(host, "*.wikimedia.org") || 
        dnsDomainIs(host,"acm.org") || shExpMatch(host, "*.acm.org") || 
        dnsDomainIs(host,"sigir.org") || shExpMatch(host, "*.sigir.org") || 
        dnsDomainIs(host,"bing.com") || shExpMatch(host, "*.bing.com") || 
        dnsDomainIs(host,"yahoo.com") || shExpMatch(host, "*.yahoo.com") || 
        dnsDomainIs(host,"hotmail.com") || shExpMatch(host, "*.hotmail.com") || 
        dnsDomainIs(host,"msn.com") || shExpMatch(host, "*.msn.com") || 
        dnsDomainIs(host,"alexa.com") || shExpMatch(host, "*.alexa.com") || 
        dnsDomainIs(host,"google.co.jp") || shExpMatch(host, "*.google.co.jp") || 
        dnsDomainIs(host,"yahoo.co.jp") || shExpMatch(host, "*.yahoo.co.jp") || 
        dnsDomainIs(host,"ameba.co.jp") || shExpMatch(host, "*.ameba.co.jp") || 
        dnsDomainIs(host,"gmail.com") || shExpMatch(host, "*.gmail.com") || 
        dnsDomainIs(host,"evernote.com") || shExpMatch(host, "*.evernote.com") || 
        dnsDomainIs(host,"dropbox.com") || shExpMatch(host, "*.dropbox.com") || 
        dnsDomainIs(host,"fumi23.com") || shExpMatch(host, "*.fumi23.com") || 
        dnsDomainIs(host,"vector.co.jp") || shExpMatch(host, "*.vector.co.jp") || 
        dnsDomainIs(host,"excite.co.jp") || shExpMatch(host, "*.excite.co.jp") || 
        dnsDomainIs(host,"justsystems.com") || shExpMatch(host, "*.justsystems.com") || 
        dnsDomainIs(host,"2ch.net") || shExpMatch(host, "*.2ch.net") || 
        dnsDomainIs(host,"baidu.jp") || shExpMatch(host, "*.baidu.jp") || 
        dnsDomainIs(host,"mixi.jp") || shExpMatch(host, "*.mixi.jp") || 
        dnsDomainIs(host,"e-words.jp") || shExpMatch(host, "*.e-words.jp") || 
        dnsDomainIs(host,"asahi-net.or.jp") || shExpMatch(host, "*.asahi-net.or.jp") || 
        dnsDomainIs(host,"wikipedia.org") || shExpMatch(host, "*.wikipedia.org") || 
        dnsDomainIs(host,"slideshare.net") || shExpMatch(host, "*.slideshare.net") || 
        dnsDomainIs(host,"scribd.com") || shExpMatch(host, "*.scribd.com") || 
        dnsDomainIs(host,"impress.co.jp") || shExpMatch(host, "*.impress.co.jp") || 
        dnsDomainIs(host,"zing.vn") || shExpMatch(host, "*.zing.vn") || 
        dnsDomainIs(host,"vnexpress.net") || shExpMatch(host, "*.vnexpress.net") || 
        dnsDomainIs(host,"24h.com.vn") || shExpMatch(host, "*.24h.com.vn") || 
        dnsDomainIs(host,"vn-zoom.com") || shExpMatch(host, "*.vn-zoom.com") || 
        dnsDomainIs(host,"tinhte.vn") || shExpMatch(host, "*.tinhte.vn") || 
        dnsDomainIs(host,"ddth.com") || shExpMatch(host, "*.ddth.com") || 
        dnsDomainIs(host,"yume.vn") || shExpMatch(host, "*.yume.vn") || 
        dnsDomainIs(host,"webtretho.com") || shExpMatch(host, "*.webtretho.com") || 
        dnsDomainIs(host,"baamboo.com") || shExpMatch(host, "*.baamboo.com") || 
        dnsDomainIs(host,"goonline.vn") || shExpMatch(host, "*.goonline.vn") || 
        dnsDomainIs(host,"eva.vn") || shExpMatch(host, "*.eva.vn") || 
        dnsDomainIs(host,"truongton.net") || shExpMatch(host, "*.truongton.net") || 
        dnsDomainIs(host,"lamchame.com") || shExpMatch(host, "*.lamchame.com") || 
        dnsDomainIs(host,"tailieu.vn") || shExpMatch(host, "*.tailieu.vn") || 
        dnsDomainIs(host,"download.com.vn") || shExpMatch(host, "*.download.com.vn") || 
        dnsDomainIs(host,"bkav.com.vn") || shExpMatch(host, "*.bkav.com.vn") || 
        dnsDomainIs(host,"nhacso.net") || shExpMatch(host, "*.nhacso.net") || 
        dnsDomainIs(host,"vietgle.vn") || shExpMatch(host, "*.vietgle.vn") || 
        dnsDomainIs(host,"unikey.org") || shExpMatch(host, "*.unikey.org") || 
        dnsDomainIs(host,"my.comscore.com") || shExpMatch(host, "*.my.comscore.com") || 
        dnsDomainIs(host,"malaysiakini.com") || shExpMatch(host, "*.malaysiakini.com") || 
        dnsDomainIs(host,"cari.com.my") || shExpMatch(host, "*.cari.com.my") || 
        dnsDomainIs(host,"lelong.com.my") || shExpMatch(host, "*.lelong.com.my") || 
        dnsDomainIs(host,"mudah.com.my") || shExpMatch(host, "*.mudah.com.my") || 
        dnsDomainIs(host,"701panduan.com") || shExpMatch(host, "*.701panduan.com") || 
        dnsDomainIs(host,"carigold.com") || shExpMatch(host, "*.carigold.com") || 
        dnsDomainIs(host,"id.openrice.com") || shExpMatch(host, "*.id.openrice.com") || 
        dnsDomainIs(host,"lycos.com") || shExpMatch(host, "*.lycos.com") || 
        dnsDomainIs(host,"lowyat.net") || shExpMatch(host, "*.lowyat.net") || 
        dnsDomainIs(host,"jobstreet.com.my") || shExpMatch(host, "*.jobstreet.com.my") || 
        dnsDomainIs(host,"themalaysianinsider.com") || shExpMatch(host, "*.themalaysianinsider.com") || 
        dnsDomainIs(host,"wordpress.org") || shExpMatch(host, "*.wordpress.org") || 
        dnsDomainIs(host,"lineclear.com") || shExpMatch(host, "*.lineclear.com") || 
        dnsDomainIs(host,"rapidshare.com") || shExpMatch(host, "*.rapidshare.com") || 
        dnsDomainIs(host,"4shared.com") || shExpMatch(host, "*.4shared.com") || 
        dnsDomainIs(host,"ziddu.com") || shExpMatch(host, "*.ziddu.com") || 
        dnsDomainIs(host,"wikipedia.org") || shExpMatch(host, "*.wikipedia.org") || 
        dnsDomainIs(host,"hotfile.com") || shExpMatch(host, "*.hotfile.com") || 
        dnsDomainIs(host,"kaskus.us") || shExpMatch(host, "*.kaskus.us") || 
        dnsDomainIs(host,"filestube.com") || shExpMatch(host, "*.filestube.com") || 
        dnsDomainIs(host,"indowebster.com") || shExpMatch(host, "*.indowebster.com") || 
        dnsDomainIs(host,"stafaband.info") || shExpMatch(host, "*.stafaband.info") || 
        dnsDomainIs(host,"topshareware.com") || shExpMatch(host, "*.topshareware.com") || 
        dnsDomainIs(host,"dlitall.com") || shExpMatch(host, "*.dlitall.com") || 
        dnsDomainIs(host,"flickr.com") || shExpMatch(host, "*.flickr.com") || 
        dnsDomainIs(host,"imageshack.us") || shExpMatch(host, "*.imageshack.us") || 
        dnsDomainIs(host,"google.com.tr") || shExpMatch(host, "*.google.com.tr") || 
        dnsDomainIs(host,"mynet.com") || shExpMatch(host, "*.mynet.com") || 
        dnsDomainIs(host,"izlesene.com") || shExpMatch(host, "*.izlesene.com") || 
        dnsDomainIs(host,"gezginler.net") || shExpMatch(host, "*.gezginler.net") || 
        dnsDomainIs(host,"fizy.com") || shExpMatch(host, "*.fizy.com") || 
        dnsDomainIs(host,"imageshack.us") || shExpMatch(host, "*.imageshack.us") || 
        dnsDomainIs(host,"sahibinden.com") || shExpMatch(host, "*.sahibinden.com") || 
        dnsDomainIs(host,"dailymotion.com") || shExpMatch(host, "*.dailymotion.com") || 
        dnsDomainIs(host,"diziport.com") || shExpMatch(host, "*.diziport.com") || 
        dnsDomainIs(host,"timsah.com") || shExpMatch(host, "*.timsah.com") || 
        dnsDomainIs(host,"milliyet.com.tr") || shExpMatch(host, "*.milliyet.com.tr") || 
        dnsDomainIs(host,"hurriyet.com.tr") || shExpMatch(host, "*.hurriyet.com.tr") || 
        dnsDomainIs(host,"ekolay.net") || shExpMatch(host, "*.ekolay.net") || 
        dnsDomainIs(host,"as7apcool.com") || shExpMatch(host, "*.as7apcool.com") || 
        dnsDomainIs(host,"wikipedia.org") || shExpMatch(host, "*.wikipedia.org") || 
        dnsDomainIs(host,"bramjnet.com") || shExpMatch(host, "*.bramjnet.com") || 
        dnsDomainIs(host,"jsoftj.com") || shExpMatch(host, "*.jsoftj.com") || 
        dnsDomainIs(host,"tedata.net") || shExpMatch(host, "*.tedata.net") || 
        dnsDomainIs(host,"vodafone.com.eg") || shExpMatch(host, "*.vodafone.com.eg") || 
        dnsDomainIs(host,"etisalat.com.eg") || shExpMatch(host, "*.etisalat.com.eg") || 
        dnsDomainIs(host,"maktoob.yahoo.com") || shExpMatch(host, "*.maktoob.yahoo.com") || 
        dnsDomainIs(host,"masrawy.com") || shExpMatch(host, "*.masrawy.com") || 
        dnsDomainIs(host,"elaana.com") || shExpMatch(host, "*.elaana.com") || 
        dnsDomainIs(host,"arabseyes.com") || shExpMatch(host, "*.arabseyes.com") || 
        dnsDomainIs(host,"myegy.com") || shExpMatch(host, "*.myegy.com") || 
        dnsDomainIs(host,"mazika2day.com") || shExpMatch(host, "*.mazika2day.com") || 
        dnsDomainIs(host,"arabseed.com") || shExpMatch(host, "*.arabseed.com") || 
        dnsDomainIs(host,"arablionz.com") || shExpMatch(host, "*.arablionz.com") || 
        dnsDomainIs(host,"mawaly.com") || shExpMatch(host, "*.mawaly.com") || 
        dnsDomainIs(host,"sm3na.com") || shExpMatch(host, "*.sm3na.com") || 
        dnsDomainIs(host,"youm7.com") || shExpMatch(host, "*.youm7.com") || 
        dnsDomainIs(host,"almasry-alyoum.com") || shExpMatch(host, "*.almasry-alyoum.com") || 
        dnsDomainIs(host,"akhbarak.net") || shExpMatch(host, "*.akhbarak.net") || 
        dnsDomainIs(host,"ahram.org.eg") || shExpMatch(host, "*.ahram.org.eg") || 
        dnsDomainIs(host,"shorouknews.com") || shExpMatch(host, "*.shorouknews.com") || 
        dnsDomainIs(host,"moheet.com") || shExpMatch(host, "*.moheet.com") || 
        dnsDomainIs(host,"algomhuria.net.eg") || shExpMatch(host, "*.algomhuria.net.eg") || 
        dnsDomainIs(host,"dostor.org") || shExpMatch(host, "*.dostor.org") || 
        dnsDomainIs(host,"mawaly.com") || shExpMatch(host, "*.mawaly.com") || 
        dnsDomainIs(host,"imdb.com") || shExpMatch(host, "*.imdb.com") || 
        dnsDomainIs(host,"brg8.com") || shExpMatch(host, "*.brg8.com") || 
        dnsDomainIs(host,"yoo7.com") || shExpMatch(host, "*.yoo7.com") || 
        dnsDomainIs(host,"sptechs.com") || shExpMatch(host, "*.sptechs.com") || 
        dnsDomainIs(host,"zamalekfans.com") || shExpMatch(host, "*.zamalekfans.com") || 
        dnsDomainIs(host,"yallakora.com") || shExpMatch(host, "*.yallakora.com") || 
        dnsDomainIs(host,"filgoal.com") || shExpMatch(host, "*.filgoal.com") || 
        dnsDomainIs(host,"kooora.com") || shExpMatch(host, "*.kooora.com") || 
        dnsDomainIs(host,"bdr130.net") || shExpMatch(host, "*.bdr130.net") || 
        dnsDomainIs(host,"te3p.com") || shExpMatch(host, "*.te3p.com") || 
        dnsDomainIs(host,"jeddahbikers.com") || shExpMatch(host, "*.jeddahbikers.com") || 
        dnsDomainIs(host,"google.com.br") || shExpMatch(host, "*.google.com.br") || 
        dnsDomainIs(host,"orkut.com.br") || shExpMatch(host, "*.orkut.com.br") || 
        dnsDomainIs(host,"uol.com.br") || shExpMatch(host, "*.uol.com.br") || 
        dnsDomainIs(host,"live.com") || shExpMatch(host, "*.live.com") || 
        dnsDomainIs(host,"globo.com") || shExpMatch(host, "*.globo.com") || 
        dnsDomainIs(host,"blogspot.com") || shExpMatch(host, "*.blogspot.com") || 
        dnsDomainIs(host,"terra.com.br") || shExpMatch(host, "*.terra.com.br") || 
        dnsDomainIs(host,"orkut.com") || shExpMatch(host, "*.orkut.com") || 
        dnsDomainIs(host,"alexa.com") || shExpMatch(host, "*.alexa.com") || 
        dnsDomainIs(host,"olat.org") || shExpMatch(host, "*.olat.org") || 
        dnsDomainIs(host,"hg.olat.org") || shExpMatch(host, "*.hg.olat.org") || 
        dnsDomainIs(host,"sakaiproject.org") || shExpMatch(host, "*.sakaiproject.org") || 
        dnsDomainIs(host,"sakaiproject.org") || shExpMatch(host, "*.sakaiproject.org") || 
        dnsDomainIs(host,"opencastproject.org") || shExpMatch(host, "*.opencastproject.org") || 
        dnsDomainIs(host,"opencast.jira.com") || shExpMatch(host, "*.opencast.jira.com") || 
        dnsDomainIs(host,"code.google.com") || shExpMatch(host, "*.code.google.com") || 
        dnsDomainIs(host,"bigbluebutton.org") || shExpMatch(host, "*.bigbluebutton.org") || 
        dnsDomainIs(host,"github.com") || shExpMatch(host, "*.github.com") || 
        dnsDomainIs(host,"googleusercontent.com") || shExpMatch(host, "*.googleusercontent.com") || 
        dnsDomainIs(host,"php.net") || shExpMatch(host, "*.php.net") 
    ) {
        return "PROXY 172.22.18.17:8128";
    }
    if( shExpMatch(host, "(*\.|)homeinns.com") ||
        shExpMatch(host, "(*\.|)sinajs.com") || 
        shExpMatch(host, "(*\.|)douban.fm")    ||
        shExpMatch(host, "(*\.|)pixlr.com") || 
        shExpMatch(host, "(*\.|)jing.fm")      ||
        shExpMatch(host, "(*\.|)oadz.com")  ||
        shExpMatch(host, "(*\.|)youshang.com") ||
        shExpMatch(host, "(*\.|)kuaidi100.com") || 
        shExpMatch(host, "(*\.|)sinahk.net")   ||
        shExpMatch(host, "(*\.|)kuaidi100.com") || 
        shExpMatch(host, "(*\.|)adsame.com")   ||
        shExpMatch(host, "(*\.|)scorecardresearch.com") || 
        shExpMatch(host, "(*\.|)imrworldwide.com")||
        shExpMatch(host, "(*\.|)wrating.com") || 
        shExpMatch(host, "(*\.|)mediav.com")   ||
        shExpMatch(host, "(*\.|)lycos.com") || 
        shExpMatch(host, "(*\.|)gamesville.com")||
        shExpMatch(host, "(*\.|)lygo.com") || 
        shExpMatch(host, "(*\.|)quantserve.com")||
        shExpMatch(host, "(*\.|)miaozhen.com")  ||
        shExpMatch(host, "(*\.|)qstatic.com")  ||
        shExpMatch(host, "(*\.|)tremormedia.com")  ||
        shExpMatch(host, "(*\.|)yieldmanager.com")||
        shExpMatch(host, "(*\.|)adsonar.com")  ||
        shExpMatch(host, "(*\.|)adtechus.com") ||
        shExpMatch(host, "(*\.|)bluekai.com")   ||
        shExpMatch(host, "(*\.|)ipinyou.com")  ||
        shExpMatch(host, "(*\.|)bdstatic.com")   ||
        shExpMatch(host, "(*\.|)bdimg.com")    ||
        shExpMatch(host, "(*\.|)mediaplex.com")  ||
        shExpMatch(host, "(*\.|)ykimg.com")    ||
        shExpMatch(host, "(*\.|)irs01.com")  ||
        shExpMatch(host, "(*\.|)irs01.net")    ||
        shExpMatch(host, "(*\.|)mmstat.com")   ||
        shExpMatch(host, "(*\.|)tanx.com")     ||
        shExpMatch(host, "(*\.|)atdmt.com")   ||
        shExpMatch(host, "(*\.|)tudouui.com")  ||
        shExpMatch(host, "(*\.|)tdimg.com")   ||
        shExpMatch(host, "(*\.|)ku6img.com")   ||
        shExpMatch(host, "(*\.|)ku6cdn.com")   ||
        shExpMatch(host, "(*\.|)staticsdo.com")||
        shExpMatch(host, "(*\.|)snyu.com")  ||
        shExpMatch(host, "(*\.|)mlt01.com")    ||
        shExpMatch(host, "(*\.|)doubleclick.net") ||
        shExpMatch(host, "(*\.|)scanscout.com")||
        shExpMatch(host, "(*\.|)betrad.com") ||
        shExpMatch(host, "(*\.|)invitemedia.com")||
        shExpMatch(host, "(*\.|)adroll.com") ||
        shExpMatch(host, "(*\.|)mathtag.com")  ||
        shExpMatch(host, "(*\.|)2mdn.net")  ||
        shExpMatch(host, "(*\.|)rtbidder.net") ||
        shExpMatch(host, "(*\.|)compete.com")  ||
        shExpMatch(host, "(*\.|)vizu.com")     ||
        shExpMatch(host, "(*\.|)adnxs.com")  ||
        shExpMatch(host, "(*\.|)mookie1.com")  ||
        shExpMatch(host, "(*\.|)pubmatic.com")  ||
        shExpMatch(host, "(*\.|)serving-sys.com")|| 
        shExpMatch(host, "(*\.|)legolas-media.com")||
        shExpMatch(host, "(*\.|)harrenmedianetwork.com")||
        shExpMatch(host, "(*\.|)ytimg.com")||
        shExpMatch(host, "(*\.|)google-analytics.com")
    ) {

        return 'DIRECT';
    }


    // Chinese cloud
    if( 
        shExpMatch(host, "(*\.|)alipayobjects.com") ||
        shExpMatch(host, "(*\.|)aliyun.com") ||
        shExpMatch(host, "(*\.|)alicdn.com")
    ) {
        return 'DIRECT';
    }

    // ihipop's list
    if( 
        shExpMatch(host, "(*\.|)renren.com") ||
        shExpMatch(host, "(*\.|)sina.com") ||
        shExpMatch(host, "(*\.|)iask.com") ||
        shExpMatch(host, "(*\.|)cctv*.com") ||
        shExpMatch(host, "(*\.|)img.cctvpic.com") ||
        shExpMatch(host, "(*\.|)163.com") ||
        shExpMatch(host, "(*\.|)netease.com") ||
        shExpMatch(host, "(*\.|)126.net") ||
        shExpMatch(host, "(*\.|)qq.com") ||
        shExpMatch(host, "(*\.|)ptlogin2.qq.com") ||
        shExpMatch(host, "(*\.|)gtimg.com") ||
        shExpMatch(host, "(*\.|)taobao.com") ||
        shExpMatch(host, "(*\.|)taobaocdn.com") ||
        shExpMatch(host, "(*\.|)lxdns.com") ||
        shExpMatch(host, "(*\.|)sohu.com") ||
        shExpMatch(host, "(*\.|)ifeng.com") ||
        shExpMatch(host, "(*\.|)jysq.net") ||
        shExpMatch(host, "(*\.|)nipic.com") ||
        shExpMatch(host, "(*\.|)fastcdn.com") ||
        shExpMatch(host, "(*\.|)oeeee.com") ||
        shExpMatch(host, "(*\.|)mosso.com") ||
        shExpMatch(host, "(*\.|)pengyou.com") ||
        shExpMatch(host, "(*\.|)360buyimg.com") ||
        shExpMatch(host, "(*\.|)51buy.com") ||
        shExpMatch(host, "(*\.|)icson.com")
    ) {

        return 'DIRECT';
    }
  
    // alexa top 500 chinese sites
    if( 
        shExpMatch(host, "(*\.|)baidu.com")  ||
        shExpMatch(host, "(*\.|)qq.com") ||
        shExpMatch(host, "(*\.|)taobao.com")||
        shExpMatch(host, "(*\.|)163.com") ||
        shExpMatch(host, "(*\.|)weibo.com")  ||
        shExpMatch(host, "(*\.|)sohu.com") ||
        shExpMatch(host, "(*\.|)youku.com")  ||
        shExpMatch(host, "(*\.|)soso.com") ||
        shExpMatch(host, "(*\.|)ifeng.com") ||
        shExpMatch(host, "(*\.|)tmall.com") ||
        shExpMatch(host, "(*\.|)hao123.com") ||
        shExpMatch(host, "(*\.|)tudou.com") ||
        shExpMatch(host, "(*\.|)360buy.com") ||
        shExpMatch(host, "(*\.|)chinaz.com") ||
        shExpMatch(host, "(*\.|)alipay.com") ||
        shExpMatch(host, "(*\.|)sogou.com") ||
        shExpMatch(host, "(*\.|)renren.com") ||
        shExpMatch(host, "(*\.|)cnzz.com") ||
        shExpMatch(host, "(*\.|)douban.com") ||
        shExpMatch(host, "(*\.|)pengyou.com") ||
        shExpMatch(host, "(*\.|)yahoo.com") ||
        shExpMatch(host, "(*\.|)58.com") ||
        shExpMatch(host, "(*\.|)alibaba.com") ||
        shExpMatch(host, "(*\.|)56.com") ||
        shExpMatch(host, "(*\.|)xunlei.com") ||
        shExpMatch(host, "(*\.|)bing.com") ||
        shExpMatch(host, "(*\.|)iqiyi.com") ||
        shExpMatch(host, "(*\.|)csdn.net") ||
        shExpMatch(host, "(*\.|)soku.com") ||
        shExpMatch(host, "(*\.|)xinhuanet.com") ||
        shExpMatch(host, "(*\.|)ku6.com") ||
        shExpMatch(host, "(*\.|)aizhan.com") ||
        shExpMatch(host, "(*\.|)4399.com") ||
        shExpMatch(host, "(*\.|)yesky.com") ||
        shExpMatch(host, "(*\.|)soufun.com") ||
        shExpMatch(host, "(*\.|)youdao.com") ||
        shExpMatch(host, "(*\.|)china.com") ||
        shExpMatch(host, "(*\.|)hudong.com") ||
        shExpMatch(host, "(*\.|)ganji.com") ||
        shExpMatch(host, "(*\.|)kaixin001.com") ||
        shExpMatch(host, "(*\.|)paipai.com") ||
        shExpMatch(host, "(*\.|)live.com") ||
        shExpMatch(host, "(*\.|)alimama.com") ||
        shExpMatch(host, "(*\.|)mop.com") ||
        shExpMatch(host, "(*\.|)51.la") ||
        shExpMatch(host, "(*\.|)51job.com") ||
        shExpMatch(host, "(*\.|)dianping.com") ||
        shExpMatch(host, "(*\.|)126.com") ||
        shExpMatch(host, "(*\.|)admin5.com") ||
        shExpMatch(host, "(*\.|)it168.com") ||
        shExpMatch(host, "(*\.|)2345.com") ||
        shExpMatch(host, "(*\.|)huanqiu.com") ||
        shExpMatch(host, "(*\.|)arpg2.com") ||
        shExpMatch(host, "(*\.|)777wyx.com") ||
        shExpMatch(host, "(*\.|)chinanews.com") ||
        shExpMatch(host, "(*\.|)letv.com") ||
        shExpMatch(host, "(*\.|)jiayuan.com") ||
        shExpMatch(host, "(*\.|)39.net") ||
        shExpMatch(host, "(*\.|)twcczhu.com") ||
        shExpMatch(host, "(*\.|)cnblogs.com") ||
        shExpMatch(host, "(*\.|)microsoft.com") ||
        shExpMatch(host, "(*\.|)dangdang.com") ||
        shExpMatch(host, "(*\.|)pchome.net") ||
        shExpMatch(host, "(*\.|)pptv.com") ||
        shExpMatch(host, "(*\.|)vancl.com") ||
        shExpMatch(host, "(*\.|)zhaopin.com") ||
        shExpMatch(host, "(*\.|)apple.com") ||
        shExpMatch(host, "(*\.|)bitauto.com") ||
        shExpMatch(host, "(*\.|)etao.com") ||
        shExpMatch(host, "(*\.|)qunar.com") ||
        shExpMatch(host, "(*\.|)eastmoney.com") ||
        shExpMatch(host, "(*\.|)yihaodian.com") ||
        shExpMatch(host, "(*\.|)115.com") ||
        shExpMatch(host, "(*\.|)21cn.com") ||
        shExpMatch(host, "(*\.|)blog.163.com") ||
        shExpMatch(host, "(*\.|)hupu.com") ||
        shExpMatch(host, "(*\.|)duowan.com") ||
        shExpMatch(host, "(*\.|)52pk.net") ||
        shExpMatch(host, "(*\.|)baixing.com") ||
        shExpMatch(host, "(*\.|)iteye.com") ||
        shExpMatch(host, "(*\.|)verycd.com") ||
        shExpMatch(host, "(*\.|)suning.com") ||
        shExpMatch(host, "(*\.|)discuz.net") ||
        shExpMatch(host, "(*\.|)7k7k.com") ||
        shExpMatch(host, "(*\.|)mtime.com") ||
        shExpMatch(host, "(*\.|)msn.com") ||
        shExpMatch(host, "(*\.|)ccb.com") ||
        shExpMatch(host, "(*\.|)hc360.com") ||
        shExpMatch(host, "(*\.|)cmbchina.com") ||
        shExpMatch(host, "(*\.|)51.com") ||
        shExpMatch(host, "(*\.|)yoka.com") ||
        shExpMatch(host, "(*\.|)seowhy.com") ||
        shExpMatch(host, "(*\.|)chinabyte.com") ||
        shExpMatch(host, "(*\.|)qidian.com") ||
        shExpMatch(host, "(*\.|)ctrip.com") ||
        shExpMatch(host, "(*\.|)cnbeta.com") ||
        shExpMatch(host, "(*\.|)tom.com") ||
        shExpMatch(host, "(*\.|)tenpay.com") ||
        shExpMatch(host, "(*\.|)meituan.com") ||
        shExpMatch(host, "(*\.|)120ask.com") ||
        shExpMatch(host, "(*\.|)yahoo.co.jp") ||
        shExpMatch(host, "(*\.|)ebay.com") ||
        shExpMatch(host, "(*\.|)51cto.com") ||
        shExpMatch(host, "(*\.|)sdo.com") ||
        shExpMatch(host, "(*\.|)meilishuo.com") ||
        shExpMatch(host, "(*\.|)17173.com") ||
        shExpMatch(host, "(*\.|)xyxy.net") ||
        shExpMatch(host, "(*\.|)19lou.com") ||
        shExpMatch(host, "(*\.|)yiqifa.com") ||
        shExpMatch(host, "(*\.|)nuomi.com") ||
        shExpMatch(host, "(*\.|)eastday.com") ||
        shExpMatch(host, "(*\.|)onlinedown.net") ||
        shExpMatch(host, "(*\.|)oschina.net") ||
        shExpMatch(host, "(*\.|)zhubajie.com") ||
        shExpMatch(host, "(*\.|)amazon.com") ||
        shExpMatch(host, "(*\.|)babytree.com") ||
        shExpMatch(host, "(*\.|)kdnet.net") ||
        shExpMatch(host, "(*\.|)docin.com") ||
        shExpMatch(host, "(*\.|)qq937.com") ||
        shExpMatch(host, "(*\.|)tgbus.com") ||
        shExpMatch(host, "(*\.|)51buy.com") ||
        shExpMatch(host, "(*\.|)nipic.com") ||
        shExpMatch(host, "(*\.|)im286.com") ||
        shExpMatch(host, "(*\.|)baomihua.com") ||
        shExpMatch(host, "(*\.|)doubleclick.com") ||
        shExpMatch(host, "(*\.|)dh818.com") ||
        shExpMatch(host, "(*\.|)ads8.com") ||
        shExpMatch(host, "(*\.|)hiapk.com") ||
        shExpMatch(host, "(*\.|)ynet.com") ||
        shExpMatch(host, "(*\.|)sootoo.com") ||
        shExpMatch(host, "(*\.|)mogujie.com") ||
        shExpMatch(host, "(*\.|)gfan.com") ||
        shExpMatch(host, "(*\.|)ppstream.com") ||
        shExpMatch(host, "(*\.|)a135.net") ||
        shExpMatch(host, "(*\.|)ip138.com") ||
        shExpMatch(host, "(*\.|)zx915.com") ||
        shExpMatch(host, "(*\.|)lashou.com") ||
        shExpMatch(host, "(*\.|)crsky.com") ||
        shExpMatch(host, "(*\.|)iciba.com") ||
        shExpMatch(host, "(*\.|)uuzu.com") ||
        shExpMatch(host, "(*\.|)tuan800.com") ||
        shExpMatch(host, "(*\.|)haodf.com") ||
        shExpMatch(host, "(*\.|)youboy.com") ||
        shExpMatch(host, "(*\.|)ulink.cc") ||
        shExpMatch(host, "(*\.|)qiyou.com") ||
        shExpMatch(host, "(*\.|)88db.com") ||
        shExpMatch(host, "(*\.|)tao123.com") ||
        shExpMatch(host, "(*\.|)178.com") ||
        shExpMatch(host, "(*\.|)ci123.com") ||
        shExpMatch(host, "(*\.|)yolk7.com") ||
        shExpMatch(host, "(*\.|)tiexue.net") ||
        shExpMatch(host, "(*\.|)stockstar.com") ||
        shExpMatch(host, "(*\.|)xici.net") ||
        shExpMatch(host, "(*\.|)pcpop.com") ||
        shExpMatch(host, "(*\.|)linkedin.com") ||
        shExpMatch(host, "(*\.|)weiphone.com") ||
        shExpMatch(host, "(*\.|)doc88.com") ||
        shExpMatch(host, "(*\.|)adobe.com") ||
        shExpMatch(host, "(*\.|)shangdu.com") ||
        shExpMatch(host, "(*\.|)aili.com") ||
        shExpMatch(host, "(*\.|)anjuke.com") ||
        shExpMatch(host, "(*\.|)360doc.com") ||
        shExpMatch(host, "(*\.|)cnxad.com") ||
        shExpMatch(host, "(*\.|)west263.com") ||
        shExpMatch(host, "(*\.|)jiathis.com") ||
        shExpMatch(host, "(*\.|)gougou.com") ||
        shExpMatch(host, "(*\.|)whlongda.com") ||
        shExpMatch(host, "(*\.|)mnwan.com") ||
        shExpMatch(host, "(*\.|)onetad.com") ||
        shExpMatch(host, "(*\.|)duote.com") ||
        shExpMatch(host, "(*\.|)55bbs.com") ||
        shExpMatch(host, "(*\.|)iloveyouxi.com") ||
        shExpMatch(host, "(*\.|)gongchang.com") ||
        shExpMatch(host, "(*\.|)meishichina.com") ||
        shExpMatch(host, "(*\.|)qire123.com") ||
        shExpMatch(host, "(*\.|)55tuan.com") ||
        shExpMatch(host, "(*\.|)cocoren.com") ||
        shExpMatch(host, "(*\.|)xiaomi.com") ||
        shExpMatch(host, "(*\.|)phpwind.net") ||
        shExpMatch(host, "(*\.|)abchina.com") ||
        shExpMatch(host, "(*\.|)thethirdmedia.com")||
        shExpMatch(host, "(*\.|)coo8.com") ||
        shExpMatch(host, "(*\.|)aliexpress.com") ||
        shExpMatch(host, "(*\.|)onlylady.com") ||
        shExpMatch(host, "(*\.|)manzuo.com") ||
        shExpMatch(host, "(*\.|)elong.com") ||
        shExpMatch(host, "(*\.|)aibang.com") ||
        shExpMatch(host, "(*\.|)10010.com") ||
        shExpMatch(host, "(*\.|)3366.com") ||
        shExpMatch(host, "(*\.|)28tui.com") ||
        shExpMatch(host, "(*\.|)vipshop.com") ||
        shExpMatch(host, "(*\.|)1616.net") ||
        shExpMatch(host, "(*\.|)pp.cc") ||
        shExpMatch(host, "(*\.|)jumei.com") ||
        shExpMatch(host, "(*\.|)tui18.com") ||
        shExpMatch(host, "(*\.|)52tlbb.com") ||
        shExpMatch(host, "(*\.|)yinyuetai.com") ||
        shExpMatch(host, "(*\.|)eye.rs") ||
        shExpMatch(host, "(*\.|)baihe.com") ||
        shExpMatch(host, "(*\.|)iyaya.com") ||
        shExpMatch(host, "(*\.|)imanhua.com") ||
        shExpMatch(host, "(*\.|)lusongsong.com") ||
        shExpMatch(host, "(*\.|)taobaocdn.com") ||
        shExpMatch(host, "(*\.|)leho.com") ||
        shExpMatch(host, "(*\.|)315che.com") ||
        shExpMatch(host, "(*\.|)donews.com") ||
        shExpMatch(host, "(*\.|)cqnews.net") ||
        shExpMatch(host, "(*\.|)591hx.com") ||
        shExpMatch(host, "(*\.|)114la.com") ||
        shExpMatch(host, "(*\.|)gamersky.com") ||
        shExpMatch(host, "(*\.|)tangdou.com") ||
        shExpMatch(host, "(*\.|)91.com") ||
        shExpMatch(host, "(*\.|)uuu9.com") ||
        shExpMatch(host, "(*\.|)xinnet.com") ||
        shExpMatch(host, "(*\.|)dedecms.com") ||
        shExpMatch(host, "(*\.|)cnmo.com") ||
        shExpMatch(host, "(*\.|)51fanli.com") ||
        shExpMatch(host, "(*\.|)liebiao.com") ||
        shExpMatch(host, "(*\.|)yyets.com") ||
        shExpMatch(host, "(*\.|)lady8844.com") ||
        shExpMatch(host, "(*\.|)newsmth.net") ||
        shExpMatch(host, "(*\.|)ucjoy.com") ||
        shExpMatch(host, "(*\.|)duba.net") ||
        shExpMatch(host, "(*\.|)cnki.net") ||
        shExpMatch(host, "(*\.|)70e.com") ||
        shExpMatch(host, "(*\.|)funshion.com") ||
        shExpMatch(host, "(*\.|)qjy168.com") ||
        shExpMatch(host, "(*\.|)paypal.com") ||
        shExpMatch(host, "(*\.|)3dmgame.com") ||
        shExpMatch(host, "(*\.|)m18.com") ||
        shExpMatch(host, "(*\.|)caixin.com") ||
        shExpMatch(host, "(*\.|)linezing.com") ||
        shExpMatch(host, "(*\.|)53kf.com") ||
        shExpMatch(host, "(*\.|)makepolo.com") ||
        shExpMatch(host, "(*\.|)dospy.com") ||
        shExpMatch(host, "(*\.|)xiami.com") ||
        shExpMatch(host, "(*\.|)5173.com") ||
        shExpMatch(host, "(*\.|)vjia.com") ||
        shExpMatch(host, "(*\.|)hotsales.net") ||
        shExpMatch(host, "(*\.|)4738.com") ||
        shExpMatch(host, "(*\.|)mydrivers.com") ||
        shExpMatch(host, "(*\.|)alisoft.com") ||
        shExpMatch(host, "(*\.|)titan24.com") ||
        shExpMatch(host, "(*\.|)u17.com") ||
        shExpMatch(host, "(*\.|)jb51.net") ||
        shExpMatch(host, "(*\.|)diandian.com") ||
        shExpMatch(host, "(*\.|)dzwww.com") ||
        shExpMatch(host, "(*\.|)hichina.com") ||
        shExpMatch(host, "(*\.|)abang.com") ||
        shExpMatch(host, "(*\.|)qianlong.com") ||
        shExpMatch(host, "(*\.|)m1905.com") ||
        shExpMatch(host, "(*\.|)chinahr.com") ||
        shExpMatch(host, "(*\.|)zhaodao123.com") ||
        shExpMatch(host, "(*\.|)daqi.com") ||
        shExpMatch(host, "(*\.|)sourceforge.net") ||
        shExpMatch(host, "(*\.|)yaolan.com") ||
        shExpMatch(host, "(*\.|)5d6d.net") ||
        shExpMatch(host, "(*\.|)fobshanghai.com") ||
        shExpMatch(host, "(*\.|)q150.com") ||
        shExpMatch(host, "(*\.|)l99.com") ||
        shExpMatch(host, "(*\.|)ccidnet.com") ||
        shExpMatch(host, "(*\.|)aifang.com") ||
        shExpMatch(host, "(*\.|)aol.com") ||
        shExpMatch(host, "(*\.|)theplanet.com") ||
        shExpMatch(host, "(*\.|)chinaunix.net") ||
        shExpMatch(host, "(*\.|)hf365.com") ||
        shExpMatch(host, "(*\.|)ad1111.com") ||
        shExpMatch(host, "(*\.|)zhihu.com") ||
        shExpMatch(host, "(*\.|)blueidea.com") ||
        shExpMatch(host, "(*\.|)net114.com") ||
        shExpMatch(host, "(*\.|)07073.com") ||
        shExpMatch(host, "(*\.|)alivv.com") ||
        shExpMatch(host, "(*\.|)mplife.com") ||
        shExpMatch(host, "(*\.|)allyes.com") ||
        shExpMatch(host, "(*\.|)jqw.com") ||
        shExpMatch(host, "(*\.|)netease.com") ||
        shExpMatch(host, "(*\.|)1ting.com") ||
        shExpMatch(host, "(*\.|)yougou.com") ||
        shExpMatch(host, "(*\.|)dbank.com") ||
        shExpMatch(host, "(*\.|)made-in-china.com") ||
        shExpMatch(host, "(*\.|)36kr.com") ||
        shExpMatch(host, "(*\.|)wumii.com") ||
        shExpMatch(host, "(*\.|)zoosnet.net") ||
        shExpMatch(host, "(*\.|)xitek.com") ||
        shExpMatch(host, "(*\.|)ali213.net") ||
        shExpMatch(host, "(*\.|)exam8.com") ||
        shExpMatch(host, "(*\.|)jxedt.com") ||
        shExpMatch(host, "(*\.|)uniontoufang.com") ||
        shExpMatch(host, "(*\.|)zqgame.com") ||
        shExpMatch(host, "(*\.|)52kmh.com") ||
        shExpMatch(host, "(*\.|)yxlady.com") ||
        shExpMatch(host, "(*\.|)sznews.com") ||
        shExpMatch(host, "(*\.|)longhoo.net") ||
        shExpMatch(host, "(*\.|)game3737.com") ||
        shExpMatch(host, "(*\.|)51auto.com") ||
        shExpMatch(host, "(*\.|)booksky.org") ||
        shExpMatch(host, "(*\.|)iqilu.com") ||
        shExpMatch(host, "(*\.|)ddmap.com") ||
        shExpMatch(host, "(*\.|)cncn.com") ||
        shExpMatch(host, "(*\.|)ename.net") ||
        shExpMatch(host, "(*\.|)1778.com") ||
        shExpMatch(host, "(*\.|)blogchina.com") ||
        shExpMatch(host, "(*\.|)778669.com") ||
        shExpMatch(host, "(*\.|)dayoo.com") ||
        shExpMatch(host, "(*\.|)ct10000.com") ||
        shExpMatch(host, "(*\.|)zhibo8.cc") ||
        shExpMatch(host, "(*\.|)qingdaonews.com") ||
        shExpMatch(host, "(*\.|)zongheng.com") ||
        shExpMatch(host, "(*\.|)1o26.com") ||
        shExpMatch(host, "(*\.|)oeeee.com") ||
        shExpMatch(host, "(*\.|)tiancity.com") ||
        shExpMatch(host, "(*\.|)jinti.com") ||
        shExpMatch(host, "(*\.|)si.kz") ||
        shExpMatch(host, "(*\.|)tuniu.com") ||
        shExpMatch(host, "(*\.|)xiu.com") ||
        shExpMatch(host, "(*\.|)265.com") ||
        shExpMatch(host, "(*\.|)gamestlbb.com") ||
        shExpMatch(host, "(*\.|)2hua.com") ||
        shExpMatch(host, "(*\.|)moonbasa.com") ||
        shExpMatch(host, "(*\.|)sf-express.com") ||
        shExpMatch(host, "(*\.|)qiushibaike.com") ||
        shExpMatch(host, "(*\.|)ztgame.com") ||
        shExpMatch(host, "(*\.|)yupoo.com") ||
        shExpMatch(host, "(*\.|)kimiss.com") ||
        shExpMatch(host, "(*\.|)cnhubei.com") ||
        shExpMatch(host, "(*\.|)pingan.com") ||
        shExpMatch(host, "(*\.|)lafaso.com") ||
        shExpMatch(host, "(*\.|)rakuten.co.jp") ||
        shExpMatch(host, "(*\.|)zhenai.com") ||
        shExpMatch(host, "(*\.|)tiao8.info") ||
        shExpMatch(host, "(*\.|)7c.com") ||
        shExpMatch(host, "(*\.|)tianji.com") ||
        shExpMatch(host, "(*\.|)kugou.com") ||
        shExpMatch(host, "(*\.|)house365.com") ||
        shExpMatch(host, "(*\.|)flickr.com") ||
        shExpMatch(host, "(*\.|)xiazaiba.com") ||
        shExpMatch(host, "(*\.|)aipai.com") ||
        shExpMatch(host, "(*\.|)sodu.org") ||
        shExpMatch(host, "(*\.|)bankcomm.com") ||
        shExpMatch(host, "(*\.|)lietou.com") ||
        shExpMatch(host, "(*\.|)toocle.com") ||
        shExpMatch(host, "(*\.|)fengniao.com") ||
        shExpMatch(host, "(*\.|)99bill.com") ||
        shExpMatch(host, "(*\.|)bendibao.com") ||
        shExpMatch(host, "(*\.|)mapbar.com") ||
        shExpMatch(host, "(*\.|)nowec.com") ||
        shExpMatch(host, "(*\.|)yingjiesheng.com")||
        shExpMatch(host, "(*\.|)comsenz.com") ||
        shExpMatch(host, "(*\.|)meilele.com") ||
        shExpMatch(host, "(*\.|)otwan.com") ||
        shExpMatch(host, "(*\.|)61.com") ||
        shExpMatch(host, "(*\.|)meizu.com") ||
        shExpMatch(host, "(*\.|)readnovel.com") ||
        shExpMatch(host, "(*\.|)fenzhi.com") ||
        shExpMatch(host, "(*\.|)up2c.com") ||
        shExpMatch(host, "(*\.|)500wan.com") ||
        shExpMatch(host, "(*\.|)fx120.net") ||
        shExpMatch(host, "(*\.|)ftuan.com") ||
        shExpMatch(host, "(*\.|)17u.com") ||
        shExpMatch(host, "(*\.|)lehecai.com") ||
        shExpMatch(host, "(*\.|)28.com") ||
        shExpMatch(host, "(*\.|)bilibili.tv") ||
        shExpMatch(host, "(*\.|)huaban.com") ||
        shExpMatch(host, "(*\.|)szhome.com") ||
        shExpMatch(host, "(*\.|)miercn.com") ||
        shExpMatch(host, "(*\.|)fblife.com") ||
        shExpMatch(host, "(*\.|)chinaw3.com") ||
        shExpMatch(host, "(*\.|)smzdm.com") ||
        shExpMatch(host, "(*\.|)b2b168.com") ||
        shExpMatch(host, "(*\.|)265g.com") ||
        shExpMatch(host, "(*\.|)anzhi.com") ||
        shExpMatch(host, "(*\.|)chuangelm.com") ||
        shExpMatch(host, "(*\.|)php100.com") ||
        shExpMatch(host, "(*\.|)100ye.com") ||
        shExpMatch(host, "(*\.|)hefei.cc") ||
        shExpMatch(host, "(*\.|)mumayi.com") ||
        shExpMatch(host, "(*\.|)sttlbb.com") ||
        shExpMatch(host, "(*\.|)mangocity.com") ||
        shExpMatch(host, "(*\.|)fantong.com")
    ) {
        return 'DIRECT';
    } 

    // if none of above cases, it is always safe to use the proxy
    return proxy;
}


/*
    MIT License
    Copyright (C) 2012 n0gfwall0@gmail.com

    Permission is hereby granted, free of charge, to any person obtaining a 
    copy of this software and associated documentation files (the "Software"), 
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in 
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.

                                                                              */
