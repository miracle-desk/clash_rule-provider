import requests
import ipaddress

def get_rule_oisd_full(url):
    try:
        r = requests.get(url)
        update_rule_oisd_full = r.text.split("\n")
        update_rule_oisd_full = [line.replace("||", "").replace("|", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_oisd_full if not line.startswith(('#', '!', '@', '/', '*', ':', '&'))]
        domains = []
        ips = []
        for line in update_rule_oisd_full:
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
                    domains.append(domain)
        rules = ["  - DOMAIN-SUFFIX," + domain for domain in domains] + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None
def get_rule_oisd_small(url):
    try:
        r = requests.get(url)
        update_rule_oisd_small = r.text.split("\n")
        update_rule_oisd_small = [line.replace("||", "").replace("|", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_oisd_small if not line.startswith(('#', '!', '@', '/', '*', ':', '&'))]
        domains = []
        ips = []
        for line in update_rule_oisd_small:
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
                    domains.append(domain)
        rules = ["  - DOMAIN-SUFFIX," + domain for domain in domains] + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None
def get_rule_AdAway(url):
    try:
        r = requests.get(url)
        update_rule_AdAway = r.text.split("\n")
        update_rule_AdAway = [line.replace("||", "").replace("|", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_AdAway if not line.startswith(('#', '!', '@', '/', '*', ':','&'))]
        domains = []
        ips = []
        for line in update_rule_AdAway:
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
                    domains.append(domain)
        rules = ["  - DOMAIN," + domain for domain in domains] + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None
def get_rule_antiAD(url):
    try:
        r = requests.get(url)
        update_rule_antiAD = r.text.split("\n")
        update_rule_antiAD = [line.replace("||", "").replace("|", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_antiAD if not line.startswith(('#', '!', '@', '/', '*', ':','&'))]
        domains = []
        ips = []
        for line in update_rule_antiAD:
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
                    domains.append(domain)
        rules = ["  - DOMAIN-SUFFIX," + domain for domain in domains] + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None
def get_rule_Dandelion_AntiMalware(url):
    try:
        r = requests.get(url)
        update_Dandelion_AntiMalware = r.text.split("\n")
        update_Dandelion_AntiMalware = [line.replace("||", "").replace("|", "").replace("127.0.0.1", "").replace("^", "") for line in update_Dandelion_AntiMalware if not line.startswith(('#', '!', '@', '/', '*', ':', '&'))]
        domains = []
        ips = []
        for line in update_Dandelion_AntiMalware:
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
                    domains.append(domain)
        rules = ["  - DOMAIN-SUFFIX," + domain for domain in domains] + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

update_rule_oisd_full = get_rule_oisd_full("https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt")
if update_rule_oisd_full:
    with open("rule_oisd-full.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_full))
update_rule_oisd_small = get_rule_oisd_small("https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt")
if update_rule_oisd_small:
    with open("rule_oisd-small.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_small))
update_rule_AdAway = get_rule_AdAway("https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt")
if update_rule_AdAway:
    with open("rule_AdAway.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_AdAway))
update_rule_antiAD = get_rule_antiAD("https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt")
if update_rule_antiAD:
    with open("rule_CHN-antiAD.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_antiAD)) 
update_Dandelion_AntiMalware = get_rule_Dandelion_AntiMalware("https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt")
if update_Dandelion_AntiMalware:
    with open("rule_Dandelion-AntiMalware.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_Dandelion_AntiMalware))