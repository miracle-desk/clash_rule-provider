# [ clash rule-Ads + rule-security ] Generate form AdGuard Home & other

`rule_allAds.yaml` adalah gabungan dari semua rule yang ada di sini

`rule_allAds.yaml` digabung menggunakan parsing, jika beberapa baris terdapat penulisan karakter sama persis maka hanya 1 baris saja yang dimasukkan. Penggunaan parsing bertujuan menghindari penulisan domain host dan ip berulang
```yaml
rule-providers:
  rule_allAds:
    type: http
    behavior: classical
    path: "./rule_provider/rule_allAds.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_allAds.yaml
    interval: 43200 # Update rules every 12 hours

rules:
- RULE-SET,rule_allAds,REJECT
```

Note : Untuk rule OISD pilih salah satu saja, karena dalam OISD full sudah include OISD small. Sebagai ilustrasi rule OISD small cocok untuk adblock ringan tidak begitu agresive

Untuk menggunakan, edit `config.yaml` pada `/etc/openclash/config/config.yaml` seperti ini:
```yaml
rule-providers:
  rule_ABPindo:
    type: http
    behavior: classical
    path: "./rule_provider/rule_ABPindo.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_ABPindo.yaml
    interval: 43200 # Update rules every 12 hours
  rule_AdAway:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdAway.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdAway.yaml
    interval: 43200 # Update rules every 12 hours
  rule_AdGuardDNS-filter:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdGuardDNS-filter.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdGuardDNS-filter.yaml
    interval: 43200 # Update rules every 12 hours
  rule_CHN-antiAD:
    type: http
    behavior: classical
    path: "./rule_provider/rule_CHN-antiAD.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_CHN-antiAD.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Dandelion-AntiMalware:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Dandelion-AntiMalware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Dandelion-AntiMalware.yaml
    interval: 43200 # Update rules every 12 hours
  rule_HaGeZi-Personal:
    type: http
    behavior: classical
    path: "./rule_provider/rule_HaGeZi-Personal.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_HaGeZi-Personal.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Malicious-URLhaus:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Malicious-URLhaus.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Malicious-URLhaus.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Malware-Websites:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Malware-Websites.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Malware-Websites.yaml
    interval: 43200 # Update rules every 12 hours
  rule_NoCoin-filter:
    type: http
    behavior: classical
    path: "./rule_provider/rule_NoCoin-filter.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_NoCoin-filter.yaml
    interval: 43200 # Update rules every 12 hours
  rule_NoTracking:
    type: http
    behavior: classical
    path: "./rule_provider/rule_NoTracking.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_NoTracking.yaml
    interval: 43200 # Update rules every 12 hours
  rule_oisd-full:
    type: http
    behavior: classical
    path: "./rule_provider/rule_oisd-full.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-full.yaml
    interval: 43200 # Update rules every 12 hours
  rule_oisd-small:
    type: http
    behavior: classical
    path: "./rule_provider/rule_oisd-small.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-small.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Phishing-URL:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Phishing-URL.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Phishing-URL.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Scam-byDurableNapkin:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Scam-byDurableNapkin.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Scam-byDurableNapkin.yaml
    interval: 43200 # Update rules every 12 hours
  rule_ShadowWhisperer-Malware:
    type: http
    behavior: classical
    path: "./rule_provider/rule_ShadowWhisperer-Malware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_ShadowWhisperer-Malware.yaml
    interval: 43200 # Update rules every 12 hours
  rule_Stalkerware: # Untuk Android+iOS
    type: http
    behavior: classical
    path: "./rule_provider/rule_Stalkerware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Stalkerware.yaml
    interval: 43200 # Update rules every 12 hours
  rule_StevenBlackList: #block: fakenews+gambling
    type: http
    behavior: classical
    path: "./rule_provider/rule_StevenBlackList.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_StevenBlackList.yaml
    interval: 43200 # Update rules every 12 hours
  rule_custom:
    type: http
    behavior: classical
    path: "./rule_provider/rule_custom.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/openclash/main/backup/rule_provider/rule_custom.yaml
    interval: 43200 # Update rules every 12 hours
    
rules:
- RULE-SET,rule_ABPindo,REJECT                  #regionalAds
- RULE-SET,rule_AdAway,REJECT                   #general
- RULE-SET,rule_AdGuardDNS-filter,REJECT        #general
- RULE-SET,rule_CHN-antiAD,REJECT               #regionalAds
- RULE-SET,rule_Dandelion-AntiMalware,REJECT    #security
- RULE-SET,rule_HaGeZi-Personal,REJECT          #general
- RULE-SET,rule_Malicious-URLhaus,REJECT        #security
- RULE-SET,rule_Malware-Websites,REJECT         #security
- RULE-SET,rule_NoCoin-filter,REJECT            #security
- RULE-SET,rule_NoTracking,REJECT               #general
- RULE-SET,rule_oisd-full,REJECT                #general
- RULE-SET,rule_oisd-small,REJECT               #general
- RULE-SET,rule_Phishing-URL,REJECT             #security
- RULE-SET,rule_StevenBlackList,REJECT          #general[fakenews+gambling]
- RULE-SET,rule_Scam-byDurableNapkin,REJECT     #security
- RULE-SET,rule_ShadowWhisperer-Malware,REJECT  #security
- RULE-SET,rule_Stalkerware,REJECT              #security
- RULE-SET,rule_custom,REJECT                   #general
```

## PENTING ! : Jangan semua rule di masukkan, itu akan memakan ram yang cukup besar pada device. Jadi ambil atau gunakan sesuai spec dan kebutuhan
