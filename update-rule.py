import requests
import ipaddress

def get_update_rule(url):
    try:
        r = requests.get(url)
        update_rule = r.text.split("\n")
        update_rule = [line.replace("  - DOMAIN,", "").replace("  - DOMAIN-SUFFIX,", "").replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1 ", "").replace("0.0.0.0 ", "").replace("^", "") for line in update_rule if not line.startswith(('#', '!', '/', '@', '-', '&', 'payload:'))]
        domains = []
        ips = []
        for line in update_rule:
            if line:
                if line[0].isdigit():
                    # Jika baris dimulai dengan angka, itu kemungkinan adalah alamat IP
                    try:
                        # Coba parsing IP dengan modul ipaddress
                        ip = ipaddress.ip_network(line.strip().split('$')[0])
                        ips.append(ip.with_prefixlen)
                    except ValueError:
                        # Jika parsing gagal, abaikan baris ini
                        pass
                else:
                    # Jika bukan alamat IP, itu kemungkinan adalah domain
                    domain = line.split("$")[0].strip()
                    if domain.endswith(".") and domain.startswith("*"):
                        domain_suffix = domain + "*"
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)
                    elif domain.startswith("*"):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix) 
                    elif domain.endswith("."):
                        domain_suffix = domain + "*"
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)                   
                    elif domain.startswith("."):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*" + domain_suffix)
                    elif domain.startswith("://"):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*." + domain_suffix)
                    # jika domain memiliki karakter "tiktok", "pinterest" dkk maka domain tersebut tidak akan ditambahkan
                    elif any(prefix in domain for prefix in ("autodesk", "tiktok", "pinterest", "pinimg", "twitter", "linkedin", "facebook", "instagram", "whatsapp")):
                        continue
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

update_rule_ABPindo = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt")
if update_rule_ABPindo:
    with open("rule_ABPindo.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_ABPindo))

update_rule_AdAway = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt")
if update_rule_AdAway:
    with open("rule_AdAway.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_AdAway))

update_rule_AdGuardDNS_filter = get_update_rule("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
if update_rule_AdGuardDNS_filter:
    with open("rule_AdGuardDNS-filter.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_AdGuardDNS_filter))  

update_rule_antiAD = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt")
if update_rule_antiAD:
    with open("rule_CHN-antiAD.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_antiAD)) 

update_Dandelion_AntiMalware = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt")
if update_Dandelion_AntiMalware:
    with open("rule_Dandelion-AntiMalware.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_Dandelion_AntiMalware))

update_rule_HaGeZi_Personal = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt")
if update_rule_HaGeZi_Personal:
    with open("rule_HaGeZi-Personal.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_HaGeZi_Personal))

update_rule_Malicious_URLhaus = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt")
if update_rule_Malicious_URLhaus:
    with open("rule_Malicious-URLhaus.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Malicious_URLhaus))

update_rule_NoCoin_filter = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt")
if update_rule_NoCoin_filter:
    with open("rule_NoCoin-filter.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_NoCoin_filter))

update_rule_NoTracking = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_32.txt")
if update_rule_NoTracking:
    with open("rule_NoTracking.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_NoTracking))

update_rule_oisd_full = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt")
if update_rule_oisd_full:
    with open("rule_oisd-full.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_full))

update_rule_oisd_small = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt")
if update_rule_oisd_small:
    with open("rule_oisd-small.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_small))

update_rule_Phishing_URL = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt")
if update_rule_Phishing_URL:
    with open("rule_Phishing-URL.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Phishing_URL))

update_rule_Scam_byDurableNapkin = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt")
if update_rule_Scam_byDurableNapkin:
    with open("rule_Scam-byDurableNapkin.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Scam_byDurableNapkin))

update_rule_Stalkerware = get_update_rule("https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt")
if update_rule_Stalkerware:
    with open("rule_Stalkerware.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Stalkerware))

update_rule_StevenBlackList = get_update_rule("https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social-only/hosts")
if update_rule_StevenBlackList:
    with open("rule_StevenBlackList.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_StevenBlackList))
