# clash-rule [test] generate form AdGuard Home & other

Note : Untuk rule OISD pilih salah satu saja, karena dalam OISD full sudah include OISD small. Sebagai ilustrasi rule OISD small cocok untuk adblock ringan tidak begitu agresive

Untuk menggunakan, edit `config.yaml` pada `/etc/openclash/config/config.yaml` seperti ini:
```
rule-providers:
  rule_AdGuardDNS-filter:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdGuardDNS-filter.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdGuardDNS-filter.yaml
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
  rule_AdAway:
    type: http
    behavior: classical
    path: "./rule_provider/rule_AdAway.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_AdAway.yaml
    interval: 86400 # Update rules every 24 hours
  rule_antiAD:
    type: http
    behavior: classical
    path: "./rule_provider/rule_CHN-antiAD.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_CHN-antiAD.yaml
    interval: 86400 # Update rules every 24 hours
  rule_antiMalware:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Dandelion-AntiMalware.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Dandelion-AntiMalware.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Malicious-URLhaus:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Malicious-URLhaus.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Malicious-URLhaus.yaml
    interval: 86400 # Update rules every 24 hours
  rule_Phishing-URL:
    type: http
    behavior: classical
    path: "./rule_provider/rule_Phishing-URL.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_Phishing-URL.yaml
    interval: 86400 # Update rules every 24 hours
  rule_StevenBlackList: # only block: fakenews, gambling, social (unblock "tiktok", "pinterest", "twitter", "linkedin", "facebook", "instagram", "whatsapp")
    type: http
    behavior: classical
    path: "./rule_provider/rule_StevenBlackList.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_StevenBlackList.yaml
    interval: 86400 # Update rules every 24 hours
  rule_custom:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-small.yaml
    path: "./rule_provider/rule_custom.yaml"
    interval: 86400 # Update rules every 24 hours
    
rules:
- RULE-SET,rule_AdGuardDNS-filter,REJECT
- RULE-SET,rule_oisd-full,REJECT
- RULE-SET,rule_oisd-small,REJECT
- RULE-SET,rule_AdAway,REJECT
- RULE-SET,rule_antiAD,REJECT
- RULE-SET,rule_antiMalware,REJECT
- RULE-SET,rule_Malicious-URLhaus,REJECT
- RULE-SET,rule_Phishing-URL,REJECT
- RULE-SET,rule_StevenBlackList,REJECT
- RULE-SET,rule_custom,REJECT
```
