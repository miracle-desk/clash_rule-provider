import requests
import ipaddress

def get_rule_ABPindo(url):
    try:
        r = requests.get(url)
        update_rule_ABPindo = r.text.split("\n")
        update_rule_ABPindo = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_ABPindo if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_ABPindo:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_AdAway(url):
    try:
        r = requests.get(url)
        update_rule_AdAway = r.text.split("\n")
        update_rule_AdAway = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_AdAway if not line.startswith(('#', '!', '/', '@', '-', '&'))]
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_AdGuardDNS_filter(url):
    try:
        r = requests.get(url)
        update_AdGuardDNS_filter = r.text.split("\n")
        update_AdGuardDNS_filter = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_AdGuardDNS_filter if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_AdGuardDNS_filter:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_antiAD(url):
    try:
        r = requests.get(url)
        update_rule_antiAD = r.text.split("\n")
        update_rule_antiAD = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_antiAD if not line.startswith(('#', '!', '/', '@', '-', '&'))]
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_Dandelion_AntiMalware(url):
    try:
        r = requests.get(url)
        update_Dandelion_AntiMalware = r.text.split("\n")
        update_Dandelion_AntiMalware = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_Dandelion_AntiMalware if not line.startswith(('#', '!', '/', '@', '-', '&'))]
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_HaGeZi_Personal(url):
    try:
        r = requests.get(url)
        update_rule_HaGeZi_Personal = r.text.split("\n")
        update_rule_HaGeZi_Personal = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_HaGeZi_Personal if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_HaGeZi_Personal:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_NoCoin_filter(url):
    try:
        r = requests.get(url)
        update_rule_NoCoin_filter = r.text.split("\n")
        update_rule_NoCoin_filter = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("0.0.0.0", "").replace("^", "") for line in update_rule_NoCoin_filter if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_NoCoin_filter:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_NoTracking(url):
    try:
        r = requests.get(url)
        update_rule_NoTracking = r.text.split("\n")
        update_rule_NoTracking = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_NoTracking if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_NoTracking:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_oisd_full(url):
    try:
        r = requests.get(url)
        update_rule_oisd_full = r.text.split("\n")
        update_rule_oisd_full = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_oisd_full if not line.startswith(('#', '!', '/', '@', '-', '&'))]
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_oisd_small(url):
    try:
        r = requests.get(url)
        update_rule_oisd_small = r.text.split("\n")
        update_rule_oisd_small = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_oisd_small if not line.startswith(('#', '!', '/', '@', '-', '&'))]
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_Phishing_URL(url):
    try:
        r = requests.get(url)
        update_rule_Phishing_URL = r.text.split("\n")
        update_rule_Phishing_URL = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_Phishing_URL if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_Phishing_URL:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_Scam_byDurableNapkin(url):
    try:
        r = requests.get(url)
        update_rule_Scam_byDurableNapkin = r.text.split("\n")
        update_rule_Scam_byDurableNapkin = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_Scam_byDurableNapkin if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_Scam_byDurableNapkin:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_Stalkerware(url):
    try:
        r = requests.get(url)
        update_rule_Stalkerware = r.text.split("\n")
        update_rule_Stalkerware = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_Stalkerware if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_Stalkerware:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_StevenBlackList(url):
    try:
        r = requests.get(url)
        update_rule_StevenBlackList = r.text.split("\n")
        update_rule_StevenBlackList = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("0.0.0.0", "").replace("^", "") for line in update_rule_StevenBlackList if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_StevenBlackList:
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
                    # jika domain memiliki karakter "tiktok", "pinterest", "twitter", "linkedin", "facebook", "instagram", "whatsapp" maka domain tersebut tidak akan ditambahkan
                    elif any(prefix in domain for prefix in ("tiktok", "pinterest", "pinimg", "twitter", "linkedin", "facebook", "instagram", "whatsapp")):
                        continue
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

def get_rule_Malicious_URLhaus(url):
    try:
        r = requests.get(url)
        update_rule_Malicious_URLhaus = r.text.split("\n")
        update_rule_Malicious_URLhaus = [line.replace("||", "").replace("|", "").replace("://", "").replace("127.0.0.1", "").replace("^", "") for line in update_rule_Malicious_URLhaus if not line.startswith(('#', '!', '/', '@', '-', '&'))]
        domains = []
        ips = []
        for line in update_rule_Malicious_URLhaus:
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
                    else:
                        domains.append("  - DOMAIN," + domain)
        rules = domains + ["  - IP-CIDR," + ip for ip in ips]
        rules.insert(0, "payload:")
        return rules
    except Exception as e:
        print(e)
        return None

update_rule_ABPindo = get_rule_ABPindo("https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt")
if update_rule_ABPindo:
    with open("rule_ABPindo.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_ABPindo))

update_rule_AdAway = get_rule_AdAway("https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt")
if update_rule_AdAway:
    with open("rule_AdAway.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_AdAway))

update_rule_AdGuardDNS_filter = get_AdGuardDNS_filter("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
if update_rule_AdGuardDNS_filter:
    with open("rule_AdGuardDNS-filter.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_AdGuardDNS_filter))  

update_rule_antiAD = get_rule_antiAD("https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt")
if update_rule_antiAD:
    with open("rule_CHN-antiAD.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_antiAD)) 

update_Dandelion_AntiMalware = get_rule_Dandelion_AntiMalware("https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt")
if update_Dandelion_AntiMalware:
    with open("rule_Dandelion-AntiMalware.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_Dandelion_AntiMalware))

update_rule_HaGeZi_Personal = get_rule_HaGeZi_Personal("https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt")
if update_rule_HaGeZi_Personal:
    with open("rule_HaGeZi-Personal.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_HaGeZi_Personal))

update_rule_Malicious_URLhaus = get_rule_Malicious_URLhaus("https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt")
if update_rule_Malicious_URLhaus:
    with open("rule_Malicious-URLhaus.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Malicious_URLhaus))

update_rule_NoCoin_filter = get_rule_NoCoin_filter("https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt")
if update_rule_NoCoin_filter:
    with open("rule_NoCoin-filter.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_NoCoin_filter))

update_rule_NoTracking = get_rule_NoTracking("https://adguardteam.github.io/HostlistsRegistry/assets/filter_32.txt")
if update_rule_NoTracking:
    with open("rule_NoTracking.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_NoTracking))

update_rule_oisd_full = get_rule_oisd_full("https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt")
if update_rule_oisd_full:
    with open("rule_oisd-full.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_full))

update_rule_oisd_small = get_rule_oisd_small("https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt")
if update_rule_oisd_small:
    with open("rule_oisd-small.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_oisd_small))

update_rule_Phishing_URL = get_rule_Phishing_URL("https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt")
if update_rule_Phishing_URL:
    with open("rule_Phishing-URL.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Phishing_URL))

update_rule_Scam_byDurableNapkin = get_rule_Scam_byDurableNapkin("https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt")
if update_rule_Scam_byDurableNapkin:
    with open("rule_Scam-byDurableNapkin.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Scam_byDurableNapkin))

update_rule_Stalkerware = get_rule_Stalkerware("https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt")
if update_rule_Stalkerware:
    with open("rule_Stalkerware.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_Stalkerware))

update_rule_StevenBlackList = get_rule_StevenBlackList("https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social-only/hosts")
if update_rule_StevenBlackList:
    with open("rule_StevenBlackList.yaml", "w", encoding='utf-8') as f:
        f.write("\n".join(update_rule_StevenBlackList))
