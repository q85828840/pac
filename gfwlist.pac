// 基于gfwlist官方规则的PAC脚本
// 规则来源：https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
// 生成时间: 2025-09-01 18:20:08
function FindProxyForURL(url, host) {
    var proxy = "PROXY 192.168.3.252:7890; SOCKS5 192.168.3.252:7891";
    var direct = "DIRECT";
    
    // 本地地址直连（RFC标准私有IP段）
    if (isPlainHostName(host) || 
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0")) {
        return direct;
    }
    
    // ==================== gfwlist官方规则（解码后核心片段）====================
    var rules = [
        // 谷歌系
        "||google.com", "||google.ac", "||google.ad", "||google.ae", "||google.af",
        "||google.ag", "||google.ai", "||google.al", "||google.am", "||google.co.ao",
        "||google.com.ar", "||google.as", "||google.at", "||google.com.au", "||google.az",
        "||google.ba", "||google.com.bd", "||google.be", "||google.bg", "||google.bi",
        "||google.com.bn", "||google.com.bo", "||google.com.br", "||google.bs", "||google.bt",
        "||google.co.bw", "||google.by", "||google.com.bz", "||google.ca", "||google.cd",
        "||google.cg", "||google.ch", "||google.ci", "||google.co.ck", "||google.cl",
        "||google.cm", "||google.cn", "||google.com.co", "||google.co.cr", "||google.com.cu",
        "||google.cv", "||google.com.cy", "||google.cz", "||google.de", "||google.dj",
        "||google.dk", "||google.dm", "||google.com.do", "||google.dz", "||google.com.ec",
        "||google.ee", "||google.com.eg", "||google.es", "||google.com.et", "||google.fi",
        "||google.com.fj", "||google.fm", "||google.fr", "||google.ge", "||google.gg",
        "||google.com.gh", "||google.com.gi", "||google.gl", "||google.gm", "||google.gp",
        "||google.gr", "||google.com.gt", "||google.gy", "||google.com.hk", "||google.hn",
        "||google.hr", "||google.ht", "||google.hu", "||google.co.id", "||google.ie",
        "||google.co.il", "||google.im", "||google.co.in", "||google.iq", "||google.is",
        "||google.it", "||google.je", "||google.com.jm", "||google.jo", "||google.co.jp",
        "||google.co.ke", "||google.com.kh", "||google.ki", "||google.kg", "||google.co.kr",
        "||google.kz", "||google.la", "||google.com.lb", "||google.li", "||google.lk",
        "||google.co.ls", "||google.lt", "||google.lu", "||google.lv", "||google.com.ly",
        "||google.co.ma", "||google.md", "||google.me", "||google.mg", "||google.mk",
        "||google.ml", "||google.com.mm", "||google.mn", "||google.ms", "||google.com.mt",
        "||google.mu", "||google.mv", "||google.mw", "||google.com.mx", "||google.com.my",
        "||google.co.mz", "||google.com.na", "||google.ne", "||google.nl", "||google.no",
        "||google.com.np", "||google.nr", "||google.nu", "||google.co.nz", "||google.com.om",
        "||google.com.pa", "||google.com.pe", "||google.com.pg", "||google.com.ph", "||google.com.pk",
        "||google.pl", "||google.pn", "||google.com.pr", "||google.ps", "||google.pt",
        "||google.com.py", "||google.com.qa", "||google.ro", "||google.ru", "||google.rw",
        "||google.com.sa", "||google.com.sb", "||google.sc", "||google.se", "||google.com.sg",
        "||google.sh", "||google.si", "||google.sk", "||google.com.sl", "||google.sn",
        "||google.so", "||google.sr", "||google.st", "||google.com.sv", "||google.td",
        "||google.tg", "||google.co.th", "||google.com.tj", "||google.tk", "||google.tl",
        "||google.tm", "||google.tn", "||google.to", "||google.com.tr", "||google.tt",
        "||google.com.tw", "||google.co.tz", "||google.com.ua", "||google.co.ug", "||google.co.uk",
        "||google.com.uy", "||google.co.uz", "||google.com.vc", "||google.co.ve", "||google.vg",
        "||google.co.vi", "||google.com.vn", "||google.vu", "||google.ws", "||google.co.za",
        "||google.co.zm", "||google.co.zw", "||gstatic.com", "||googleapis.com", "||google-analytics.com",
        "||googletagmanager.com", "||googleadservices.com", "||googleusercontent.com",
        // 脸书系
        "||facebook.com", "||fbcdn.net", "||facebook.net", "||fb.com", "||fbsbx.com",
        "||facebookmail.com", "||fb.me", "||fbcdn.com",
        // 推特系
        "||twitter.com", "||twimg.com", "||t.co", "||twitter.io", "||twttr.com",
        // 油管系
        "||youtube.com", "||youtube-nocookie.com", "||ytimg.com", "||youtube.googleapis.com",
        "||yt.be", "||youtubei.googleapis.com", "||youtubekids.com", "||youtubeeducation.com",
        // 其他主流平台
        "||instagram.com", "||instagr.am", "||cdninstagram.com", "||linkedin.com", "||linkedin.net",
        "||pinterest.com", "||pinterest.net", "||pinimg.com", "||reddit.com", "||redd.it",
        "||redditstatic.com", "||medium.com", "||medium.net", "||quora.com", "||quoracdn.net",
        "||github.com", "||github.io", "||githubusercontent.com", "||gitlab.com", "||gitlab.io",
        "||bitbucket.org", "||bitbucket.io", "||stackoverflow.com", "||stackexchange.com",
        "||serverfault.com", "||superuser.com", "||askubuntu.com", "||math.stackexchange.com",
        "||wikipedia.org", "||wikimedia.org", "||wikibooks.org", "||wikiquote.org", "||wikisource.org",
        "||wikiversity.org", "||wikivoyage.org", "||wikimediafoundation.org",
        // 新闻媒体
        "||nytimes.com", "||wsj.com", "||bloomberg.com", "||reuters.com", "||theguardian.com",
        "||bbc.com", "||bbc.co.uk", "||cnn.com", "||foxnews.com", "||abcnews.go.com",
        "||nbcnews.com", "||washingtonpost.com", "||latimes.com", "||usatoday.com",
        // 工具类
        "||dropbox.com", "||dropboxapi.com", "||dropboxusercontent.com", "||flickr.com",
        "||flic.kr", "||tumblr.com", "||tumblr.co", "||vimeo.com", "||dailymotion.com",
        "||soundcloud.com", "||spotify.com", "||spotify.net", "||deezer.com", "||bandcamp.com"
    ];
    // =========================================================================
    
    // 规则匹配逻辑
    for (var i = 0; i < rules.length; i++) {
        var rule = rules[i];
        if (matchRule(host, url, rule)) {
            return proxy;
        }
    }
    
    return direct;
}

// 规则匹配函数（支持gfwlist标准格式）
function matchRule(host, url, rule) {
    if (rule === "" || rule[0] === '!') return false;
    
    // 处理通配符域名规则（如 ||domain.com）
    if (rule.startsWith("||")) {
        var domain = rule.slice(2).split('/')[0]; // 截取域名（排除路径）
        return host === domain || host.endsWith('.' + domain);
    }
    // 处理子域名规则（如 *.domain.com）
    if (rule.startsWith("*.")) {
        var suffix = rule.slice(2);
        return host === suffix || host.endsWith('.' + suffix);
    }
    // 处理路径规则（如 /path）
    if (rule.startsWith("/")) {
        return url.startsWith(rule);
    }
    // 处理通配符规则（如 *domain*）
    return shExpMatch(host, rule) || shExpMatch(url, rule);
}

// 兼容旧浏览器（补全endsWith方法）
if (!String.prototype.endsWith) {
    String.prototype.endsWith = function(suffix) {
        return this.indexOf(suffix, this.length - suffix.length) !== -1;
    };
}
