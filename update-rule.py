import requests

def get_rule_oisd_full(url):
    try:
        r = requests.get(url)
        update_rule_oisd_full = r.text.split("\n")
        update_rule_oisd_full = [line.replace("||", "").replace("^", "") for line in update_rule_oisd_full if not line.startswith('!')]
        update_rule_oisd_full = ["  - DOMAIN-SUFFIX," + domain for domain in update_rule_oisd_full if domain]
        update_rule_oisd_full.insert(0, "payload:")
        return update_rule_oisd_full
    except Exception as e:
        print(e)
        return None
def get_rule_oisd_small(url):
    try:
        r = requests.get(url)
        update_rule_oisd_small = r.text.split("\n")
        update_rule_oisd_small = [line.replace("||", "").replace("^", "") for line in update_rule_oisd_small if not line.startswith('!')]
        update_rule_oisd_small = ["  - DOMAIN-SUFFIX," + domain for domain in update_rule_oisd_small if domain]
        update_rule_oisd_small.insert(0, "payload:")
        return update_rule_oisd_small
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
<<<<<<< HEAD
        f.write("\n".join(update_rule_oisd_small))
=======
        f.write("\n".join(update_rule_oisd_small))
>>>>>>> ae817bf7a007f368d8546fddf836f50bdf741afb
