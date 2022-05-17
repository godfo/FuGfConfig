# FuGfConfig

## 特别声明

本项目中所有内容只供学习和研究使用，不得将本项目中任何内容用于违反任何国家/地区/组织等的法律法规或相关规定的其他用途。

## 支持

本项目对 Quan X、Loon、AdGuard Home 提供完全支持

对小火箭提供能用的支持（仅仅是能用

优先级： AdGuard Home = Loon > Quan X > 小火箭

## 使用方法

### Quan X

建议配合 ios_rule_script 项目中的 [Quan X 去广告](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/QuantumultX/Advertising) 一起使用（已去重

优先级从高到低：

```
CustomAdRules
AdRules
CustomRules
AppleRules
GFWRules
TelegramRules
BasicRules
```

### Loon

#### Loon 分流规则

优先级从高到低：

```
NoAdProxy
NoAdDirect
AdRules
FuckRogueSoftware
ProxyRules
TelegramRules
AppleNoChinaCDNRules
AppleRules
AppleAPIRules
AppleCDNRules
GFWRules
DirectRules
BaseRules
```

若有精准去广告的需求，请在未来使用 `PreciseNoAd`，此规则集会尽可能克制，确保对正常功能的影响到最低
(现阶段并不完善，规则不完整，先鸽着

```
# 对疑似误杀的广告分流规则的修正
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Advertising/NoAdProxyRules.conf, policy=PROXY, tag=NoAdProxy, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Advertising/NoAdDirectRules.conf, policy=DIRECT, tag=NoAdDirect, enabled=true

# 去广告
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Advertising/AdRules.conf, policy=Advertising, tag=CustomAd, enabled=true

# 自定义的代理
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/ProxyRules.conf, policy=PROXY, tag=CustomProxy, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/TelegramRules.conf, policy=PROXY, tag=TelegramRules, enabled=true

# Apple 规则
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Apple/AppleNoChinaCDNRules.conf, policy=AppleNoChinaCDN, tag=AppleNoChinaCDN, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Apple/AppleRules.conf, policy=Apple, tag=Apple, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Apple/AppleAPIRules.conf, policy=AppleAPI, tag=AppleAPI, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/Apple/AppleCDNRules.conf, policy=AppleCDN, tag=AppleCDN, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/GFWRules.conf, policy=PROXY, tag=FuckGFW, enabled=true

# 自定义的直连
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/DirectRules.conf, policy=DIRECT, tag=CustomDirect, enabled=true

https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonRemoteRule/BaseRules.conf, policy=DIRECT, tag=BaseRules, enabled=true

```

### 对于 FuckRogueSoftware 规则的说明

此规则极其激进，对某些国内软件强屏蔽，包括但不限于广告，跟踪，数据分析，仅保证软件最低程度功能的正常使用，使用需谨慎

```
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/FuckRogueSoftware.conf, policy=Advertising, tag=FuckRogueSoftware, enabled=true
```

### 对于 Apple 解锁功能

请查看 [iRingo 解锁完整的 Apple 功能和集成服务](https://github.com/VirgilClyne/iRingo) 仓库

**建议优先采用上文仓库的规则**

### 对于 Apple 分流规则

请参考 [这篇文章](https://blog.royli.dev/2019/better-proxy-rules-for-apple-services)

对于本项目

AppleRules 是与本地化息息相关的规则，比如地图、天气、查找、Facetime、Apple Pay
( iCloud 上传与下载也归于此规则集

AppleCDNRules 是苹果的全球 CDN

AppleNoChinaCDNRules 是大陆没有的 CDN 节点

AppleAPIRules 是苹果的 API 域名

请把 NoChinaCDN 和 APIRules 放在最前面

#### 使用中国区账号（App Store + iCloud）

AppleRules 直连

AppleCDNRules 直连

AppleNoChinaCDNRules 代理

AppleAPIRules 直连

#### 使用美国区账号（App Store + iCloud）

AppleRules 直连

AppleCDNRules 直连

AppleNoChinaCDNRules 代理

AppleAPIRules 代理

建议 AppleAPIRules 依然直连，上文是根据上述文章给出的建议，请结合自身情况使用

### Loon 插件

#### DNSMap

对常用的国内域名进行 DNS 解析分流 ，国内走国内的各大 Doh

```
# DNS 映射
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonPlugin/DNSMap.plugin, tag=DNS Map, enabled=true
```

#### DNSMapAd

对一些广告域名 DNS 解析重定向至 `127.0.0.1`

有用没用的诸君自己看着用吧

```
# DNS 去广告映射
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonPlugin/DNSMapAd.plugin, tag=DNS Map Ad, enabled=true
```

#### 抖音屏蔽

部分规则来自 <https://gist.github.com/JamesHopbourn/b5cf9219bdacfa8b6dbb3414276c149b>

在此表示感谢

```
# FuckDouyin
https://raw.githubusercontent.com/dunlanl/FuGfConfig/main/ConfigFile/Loon/LoonPlugin/FuckDouyin.plugin, proxy=Advertising, tag=Fuck Douyin, enabled=true
```

### 光明的未来

可以预见的未来越来越光明啦

特此提前准备了白名单模式，随时准备敬献。

## 感谢

本项目的数据大部分来自一下项目，在此对他们表示感谢（以下排名不分先后

[ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)

[NextDNS 维护的系统级跟踪列表](https://github.com/nextdns/metadata/tree/master/privacy/native)

[Shadowrocket-ADBlock-Rules](https://github.com/h2y/Shadowrocket-ADBlock-Rules)

[neohosts](https://github.com/neoFelhz/neohosts)

[gfwlist](https://github.com/gfwlist/gfwlist)

[SS-Rule-Snippet](https://github.com/Hackl0us/SS-Rule-Snippet#%E5%85%B3%E4%BA%8E%E9%A1%B9%E7%9B%AE)

[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master)
