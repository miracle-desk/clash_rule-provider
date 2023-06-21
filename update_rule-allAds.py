import requests
import ipaddress

def get_rule_update(url):
    try:
        r = requests.get(url)
        update_rule_update = r.text.split("\n")
        update_rule_update = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("0.0.0.0", "").replace("^", "") for line in update_rule_update if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_update:
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
                    if domain.startswith("*."):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)                       
                    elif domain.startswith("."):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*" + domain_suffix)
                    elif domain.endswith("."):
                        domain_suffix = domain + "*"
                        domains.append("  - DOMAIN-SUFFIX," + domain_suffix)
                    elif domain.startswith("://"):
                        domain_suffix = domain + ""
                        domains.append("  - DOMAIN-SUFFIX,*." + domain_suffix)
                    # jika domain memiliki karakter "github", "tiktok", "pinterest", "twitter", "linkedin", "facebook", "instagram", "whatsapp" maka domain tersebut tidak akan ditambahkan
                    elif any(prefix in domain for prefix in ("github", "tiktok", "pinterest", "pinimg", "twitter", "linkedin", "facebook", "instagram", "whatsapp")):
                        continue
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        return rules
    except Exception as e:
        print(e)
        return None

update_rule_allAds = []
urls = [
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt',  #01 ABPindo
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt',   #02 AdAway
        'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',    #03 AdGuardDNS_filter
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt',  #04 CHN-antiAD
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt',  #05 Dandelion_AntiMalware
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt',  #06 HaGeZi_Personal
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt',  #07 Malicious_URLhaus
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt',   #08 NoCoin_filter
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_32.txt',  #09  NoTracking
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt',  #10 oisd_full
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt',   #11 oisd_small
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt',  #12 Phishing_URL
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt',  #13 Scam_byDurableNapkin
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt',  #15 Stalkerware
        'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social-only/hosts'  #16 StevenBlackList
    ]
for url in urls:
    update_rule_allAds += get_rule_update(url)

# Parsing untuk menghapus baris duplikat, meyisakan 1 baris saja dari agar domain tidak menumpuk tertulis berualang
update_rule_allAds = list(set(update_rule_allAds))

if update_rule_allAds:
    with open("rule_allAds.yaml", "w", encoding='utf-8') as f:
        f.write("payload:\n")
        f.write("\n".join(update_rule_allAds))
