# clash-rule
trial automatic update rule adblock openclash

Untuk menggunakan, edit `config.yaml` pada `/etc/openclash/config/config.yaml` seperti ini:
```
rule-providers:
  rule_oisd-full:
    type: http
    behavior: classical
    path: "./rule_provider/rule_oisd-full.yaml"
    url: https://raw.githubusercontent.com/miracle-desk/my_adblock_list/main/rule_oisd-full.yaml
    interval: 86400 # Update rules every 24 hours
  rule_custom:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/miracle-desk/Openclash/main/Backup/rule_provider/rule_custom.yaml
    path: "./rule_provider/rule_custom.yaml"
    interval: 86400 # Update rules every 24 hours
    
rules:
- RULE-SET,rule_oisd-full,REJECT
- RULE-SET,rule_custom,REJECT
```
