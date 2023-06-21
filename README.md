# [ clash_rule-Ads + security ] Generate form AdGuard Home & other
`rule_allAds.yaml` gabungan dari semua rule yang ada di sini kecuali `rule_custom.yaml`

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
    interval: 86400 # Update rules every 24 hours
  rule_AdAway:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdAway.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdAway.yaml
    interval: 86400 # Update rules every 24 hours
  rule_AdGuardDNS-filter:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdGuardDNS-filter.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdGuardDNS-filter.yaml
    interval: 86400 # Update rules every 24 hours
  rule_CHN-antiAD:
    type: http
    behavior: classical
    path: "./rule_provider/rule_CHN-antiAD.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_CHN-antiAD.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Dandelion-AntiMalware:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Dandelion-AntiMalware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Dandelion-AntiMalware.yaml
    interval: 86400 # Update rules every 24 hours
  rule_HaGeZi-Personal:
    type: http
    behavior: classical
    path: "./rule_provider/rule_HaGeZi-Personal.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_HaGeZi-Personal.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Malicious-URLhaus:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Malicious-URLhaus.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Malicious-URLhaus.yaml
    interval: 86400 # Update rules every 24 hours
  rule_NoCoin-filter:
    type: http
    behavior: classical
    path: "./rule_provider/rule_NoCoin-filter.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_NoCoin-filter.yaml
    interval: 86400 # Update rules every 24 hours
  rule_NoTracking:
    type: http
    behavior: classical
    path: "./rule_provider/rule_NoTracking.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_NoTracking.yaml
    interval: 86400 # Update rules every 24 hours
  rule_oisd-full:
    type: http
    behavior: classical
    path: "./rule_provider/rule_oisd-full.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-full.yaml
    interval: 86400 # Update rules every 24 hours
  rule_oisd-small:
    type: http
    behavior: classical
    path: "./rule_provider/rule_oisd-small.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-small.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Phishing-URL:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Phishing-URL.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Phishing-URL.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Scam-byDurableNapkin:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Scam-byDurableNapkin.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Scam-byDurableNapkin.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Stalkerware: # Untuk Android+iOS
    type: http
    behavior: classical
    path: "./rule_provider/rule_Stalkerware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Stalkerware.yaml
    interval: 86400 # Update rules every 24 hours
  rule_StevenBlackList: #block: fakenews+gambling
    type: http
    behavior: classical
    path: "./rule_provider/rule_StevenBlackList.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_StevenBlackList.yaml
    interval: 86400 # Update rules every 24 hours
  rule_custom:
    type: http
    behavior: classical
    path: "./rule_provider/rule_custom.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/Openclash/main/Backup/rule_provider/rule_custom.yaml
    interval: 86400 # Update rules every 24 hours
    
rules:
- RULE-SET,rule_ABPindo,REJECT
- RULE-SET,rule_AdAway,REJECT
- RULE-SET,rule_AdGuardDNS-filter,REJECT
- RULE-SET,rule_CHN-antiAD,REJECT
- RULE-SET,rule_Dandelion-AntiMalware,REJECT
- RULE-SET,rule_HaGeZi-Personal,REJECT
- RULE-SET,rule_Malicious-URLhaus,REJECT
- RULE-SET,rule_NoCoin-filter,REJECT
- RULE-SET,rule_NoTracking,REJECT
- RULE-SET,rule_oisd-full,REJECT
- RULE-SET,rule_oisd-small,REJECT
- RULE-SET,rule_Phishing-URL,REJECT
- RULE-SET,rule_StevenBlackList,REJECT
- RULE-SET,rule_Scam-byDurableNapkin,REJECT
- RULE-SET,rule_Stalkerware,REJECT
- RULE-SET,rule_custom,REJECT
```
