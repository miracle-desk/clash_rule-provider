# clash-rule
Note : Untuk rule OISD pilih salah satu saja, karena dalam OISD full sudah include OISD small. Sebagai ilustrasi rule OISD small cocok untuk adblock ringan tidak begitu agresive

Untuk menggunakan, edit `config.yaml` pada `/etc/openclash/config/config.yaml` seperti ini:
```
rule-providers:
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
    url: https://raw.githubusercontent.com/miracle-desk/my_adblock_list/main/rule_oisd-full.yaml
    interval: 86400 # Update rules every 24 hours
  rule_custom:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/miracle-desk/clash_rule-provider/main/rule_oisd-small.yaml
    path: "./rule_provider/rule_custom.yaml"
    interval: 86400 # Update rules every 24 hours
    
rules:
- RULE-SET,rule_oisd-full,REJECT
- RULE-SET,rule_oisd-small,REJECT
- RULE-SET,rule_custom,REJECT
```
