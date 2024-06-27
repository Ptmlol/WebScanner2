import os
import random

from colorama import Fore


class DataStorage:
    sql_dict = {}
    html_inj = []
    xss_inj = None
    word_list = []
    urls = set()

    def __init__(self):
        self.related_domains = set()
        self.links_other = set()

        with open(os.getcwd() + '/Payloads/UserAgents/user_agents.txt', 'r', encoding="utf8") as f:
            self.user_agents = f.readlines()
        f.close()

    # https://github.com/payloadbox/sql-injection-payload-list
    # https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
    @staticmethod
    def payloads(p_type):  # returns a list of payloads depending on the chosen type
        try:
            # Get the payload type from the Payload Local Repo.
            if p_type == 'SQL':
                for filename in os.listdir(os.getcwd() + '/Payloads/SQL'):
                    with open(os.path.join(os.getcwd() + '/Payloads/SQL', filename), 'r', encoding="utf8") as f:
                        DataStorage.sql_dict[filename.split('.')[0]] = f.read().splitlines()
                f.close()
                all_sql_values = []
                for value in DataStorage.sql_dict.values():
                    if isinstance(value, list):
                        all_sql_values.extend(value)
                    else:
                        all_sql_values.append(value)
                return all_sql_values
            # https://github.com/InfoSecWarrior/Offensive-Payloads/blob/main/Html-Injection-Payloads.txt
            elif p_type == 'HTML':
                for filename in os.listdir(os.getcwd() + '/Payloads/HTML'):
                    with open(os.path.join(os.getcwd() + '/Payloads/HTML', filename), 'r', encoding="utf8") as f:
                        DataStorage.html_inj = f.readlines()
                f.close()
                return DataStorage.html_inj
            # https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
            elif p_type == 'XSS':
                for filename in os.listdir(os.getcwd() + '/Payloads/XSS'):
                    with open(os.path.join(os.getcwd() + '/Payloads/XSS', filename), 'r', encoding="utf8") as f:
                        DataStorage.xss_inj = f.readlines()
                f.close()
                return DataStorage.xss_inj
            elif p_type == "WORDS":
                for filename in os.listdir(os.getcwd() + '/Payloads/WordLists/'):
                    with open(os.path.join(os.getcwd() + '/Payloads/WordLists/', filename), 'r', encoding="utf8") as f:
                        DataStorage.word_list.extend(f.readlines())
                f.close()
                return DataStorage.word_list
            elif p_type == "LFI":
                for filename in os.listdir(os.getcwd() + '/Payloads/LFI-RFI'):
                    with open(os.path.join(os.getcwd() + '/Payloads/LFI-RFI', filename), 'r', encoding="utf8") as f:
                        DataStorage.rfi_inj = f.readlines()
                f.close()
                return DataStorage.rfi_inj
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong. Payload files cannot be read.")
            print(Fore.RESET)
            print("Error: ", e)
            pass

    @staticmethod
    def inject_type(p_type):
        try:
            # Based on filename, get the injection type, used for SQL.
            for key, value in DataStorage.sql_dict.items():
                if isinstance(value, list) and p_type in value:
                    return key
            return None
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong. Injection type cannot be resolved to this payload")
            print(Fore.RESET)
            print("Error: ", e)
            pass

    # https://github.com/koutto/jok3r-pocs/blob/master/exploits/drupal-cve-2014-3704/exploit-drupal-cve-2014-3704.py
    def random_agent_gen(self):
        # returns random legitimate user agent
        return random.choice(self.user_agents)
