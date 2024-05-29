import platform
import random
import ssl
import sys
import time
from io import UnsupportedOperation
import json
from colorama import Fore
import requests
import urllib.parse
import urllib.request
from bs4 import BeautifulSoup
import argparse
import os
from CustomImports import html_report
# import queue
# import socket
# import ssl
# from datetime import datetime
# from configparser import ConfigParser
# from tkinter import *
# from tkinter.ttk import *
# from tkinter.font import *
# import threading
# import ctypes
# import sys
import re
import http.cookies
# import subprocess
# import shutil
# import webbrowser

firstCallSpider = 1


# try:
#     config_object = ConfigParser()
#     config_object.read("config/config.ini")
# except Exception as e:
#     print(e)
#
# port_set = set()
# server_set = set()
# comment_set = set()
# script_set = set()
#
# linux_servers = ["apache", "nginx", "caddy", "openlitespeed", "hiawatha"]
# windows_servers = ["IIS"]
# mixed_servers = ["nodejs", "lighttpd"]
# privilege_data = ["groupID=grp001&orderID=0001", "grpID=2&item=1", "grp=group1", "role=5"]
#
# sql_injection_dict_normal = {}
# sql_injection_dict_injected = {}
# nosql_injection_dict_normal = {}
# nosql_injection_dict_injected = {}
#
# links_potential_role_definition = []
# links_vulnerable_to_lfi = []
# links_without_secure_cookie_with_sessid = []
# links_browser_cache_weakness = []
# links_lfi_directory_transversal = []
# links_cookie_directory_transversal = []
# links_bypass_authorization = []
# links_special_header = []
# links_xee_vuln = []
# links_xss_link = []
# links_privilege_escal = []
# links_idor = []
# links_javascript_code = []
# links_html_injection = []
# links_host_header_injection = []
# links_ssrf_injection = []
#
# links_forms_dict_xss = {}
# links_forms_dict_file_upload = {}
# links_forms_dict_code_exec = {}
# links_forms_dict_sql_injection = {}
# links_forms_dict_nosql_injection = {}
# links_forms__dict_sensitive_info = {}
# links_forms_files_in_form = {}
# links_forms_dict_ssi_injection = {}
# final_list = []
#
# session_id = ""
# prev_session_id = ""
#
# dtd_url = []
# temp_dir = None
#
# stable_directory = os.getcwd()
#
# class LoginTests:
#     def __init__(self, user, login_url, pass_file, wrong_username, good_password, certain_wrong_passwd, logout_url, file_for_report, error_file):
#         try:
#             self.error_file = error_file
#             self.report_file = file_for_report
#             self.username = user
#             self.password_found = False
#             self.login_url = login_url
#             self.logged_in = False
#             self.pass_file = pass_file
#             self.password = None
#             self.wrong_un = wrong_username
#             self.wrong_passwords = certain_wrong_passwd
#             self.credentials_error_vuln = False
#             self.good_password = good_password
#             self.session = requests.session()
#             self.logout_url = logout_url
#
#             self.test_lockout()
#             self.test_account_enum()
#             self.test_brute_force()
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when initializing login tests. Error: ", e, file=self.error_file)
#             pass
#
#     def brute_force(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Trying BruteForcing Login")
#             except Exception:
#                 pass
#             with open(config_object["FILE"]["password_dict"], "rb") as f:
#                 pass_list = f.readlines()
#                 f.close()
#             pass_q = queue.Queue()
#             if len(pass_list):
#                 for passwd in pass_list:
#                     try:
#                         passwd = passwd.decode("utf-8").rstrip()
#                         pass_q.put(passwd)
#                     except Exception as e:
#                         print(e)
#                         passwd = passwd.decode("latin-1").rstrip()
#                         pass_q.put(passwd)
#
#             for pass_word in pass_q.queue:
#                 http = requests.post(
#                     self.login_url,
#                     data={
#                         config_object["CREDENTIAL"]["username_field"]: self.username,
#                         config_object["CREDENTIAL"]["password_field"]: pass_word,
#                         config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                     }
#                 )
#                 if http.url == config_object["WEBURL"]["index"]:
#                     self.password = pass_word
#                     self.password_found = True
#                     return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying brute force tests. Error: ", e, file=self.error_file)
#             print("[Error Info] Login LINK:", self.login_url, file=self.error_file)
#             pass
#
#     def account_enumeration(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Trying to enumerate accounts")
#             except Exception:
#                 pass
#             print("Checking for Account Enumeration and Possible Guessable Users...", file=self.report_file)
#             wrong_password_res = requests.post(
#                 self.login_url,
#                 data={
#                     config_object["CREDENTIAL"]["username_field"]: self.username,
#                     config_object["CREDENTIAL"]["password_field"]: self.wrong_passwords,
#                     config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                 }
#             )
#             wrong_password_res_content = str(wrong_password_res.content)
#             wrong_username_res = requests.post(
#                 self.login_url,
#                 data={
#                     config_object["CREDENTIAL"]["username_field"]: self.wrong_un,
#                     config_object["CREDENTIAL"]["password_field"]: self.good_password,
#                     config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                 }
#             )
#             wrong_username_req_content = str(wrong_username_res.content)
#             if wrong_username_req_content != wrong_password_res_content:
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking for account enumeration. Error: ", e, file=self.error_file)
#             print("[Error Info] Login LINK:", self.login_url, file=self.error_file)
#             pass
#
#     def get_correct_password(self):
#         try:
#             if self.password_found:
#                 return self.password
#             return False
#         except Exception:
#             pass
#
#     def check_login_attempts(self, n):
#         try:
#             try:
#                 my_gui.update_list_gui("Checking Lock-Out Mechanism")
#             except Exception:
#                 pass
#             self.session = requests.session()
#             for i in range(n):
#                 self.session.post(
#                     self.login_url,
#                     data={
#                         config_object["CREDENTIAL"]["username_field"]: self.username,
#                         config_object["CREDENTIAL"]["password_field"]: self.wrong_passwords[0],
#                         config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                     }
#                 )
#             correct_login = self.session.post(
#                 self.login_url,
#                 data={
#                     config_object["CREDENTIAL"]["username_field"]: self.username,
#                     config_object["CREDENTIAL"]["password_field"]: self.good_password,
#                     config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                 }
#             )
#             if correct_login.url == config_object["WEBURL"]["index"]:
#                 self.session.post(self.logout_url)
#                 self.session.close()
#                 print("[!!!-!!!] Wrong Password Lock Out Mechanism not triggered after ", n, " times", file=self.report_file)
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking for wrong pw lock-out. Error: ", e, file=self.error_file)
#             print("[Error Info] Login LINK:", self.login_url, file=self.error_file)
#             pass
#
#     def test_lockout(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing Lock-Out Mechanism")
#             except Exception:
#                 pass
#             if self.check_login_attempts(int(config_object["TEST"]["lock_out_mechanism_attempts"])):
#                 print("[!!!-!!!] Weak Lockout Mechanism found for a number of invalid password attempts", file=self.report_file)
#             else:
#                 print("OK! Wrong Password Lock Out Mechanism detected", file=self.report_file)
#             return
#         except Exception:
#             pass


class DataStorage:
    def __init__(self):
        self.xss_inj = None
        self.urls = []
        self.related_domains = []
        self.sql_dict = {}
        self.html_inj = []

    # https://github.com/payloadbox/sql-injection-payload-list
    # https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
    def payloads(self, p_type):  # returns a list of payloads depending on the chosen type
        try:
            # Get the payload type from the Payload Local Repo.
            if p_type == 'SQL':
                for filename in os.listdir(os.getcwd() + '/Payloads/SQL'):
                    with open(os.path.join(os.getcwd() + '/Payloads/SQL', filename), 'r', encoding="utf8") as f:
                        self.sql_dict[filename.split('.')[0]] = f.read().splitlines()
                f.close()
                all_sql_values = []
                for value in self.sql_dict.values():
                    if isinstance(value, list):
                        all_sql_values.extend(value)
                    else:
                        all_sql_values.append(value)
                return all_sql_values
    # https://github.com/InfoSecWarrior/Offensive-Payloads/blob/main/Html-Injection-Payloads.txt
            elif p_type == 'HTML':
                for filename in os.listdir(os.getcwd() + '/Payloads/HTML'):
                    with open(os.path.join(os.getcwd() + '/Payloads/HTML', filename), 'r', encoding="utf8") as f:
                        self.html_inj = f.readlines()
                f.close()
                return self.html_inj
    # https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection #TODO: better filter XSS
            elif p_type == 'XSS':
                for filename in os.listdir(os.getcwd() + '/Payloads/XSS'):
                    with open(os.path.join(os.getcwd() + '/Payloads/XSS', filename), 'r', encoding="utf8") as f:
                        self.xss_inj = f.readlines()
                f.close()
                return self.xss_inj
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong. Payload files cannot be read.")
            print(Fore.RESET)
            print("Error: ", e)
            pass

    def inject_type(self, p_type): # TODO: Pritify the injection types to match human readable formats.
        try:
            # Based on filename, get the injection type, used for SQL primary.
            for key, value in self.sql_dict.items():
                if isinstance(value, list) and p_type in value:
                    return key
            return None
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong. Injection type cannot be resolved to this payload")
            print(Fore.RESET)
            print("Error: ", e)
            pass

    # https://github.com/koutto/jok3r-pocs/blob/master/exploits/drupal-cve-2014-3704/exploit-drupal-cve-2014-3704.py
    @staticmethod
    def random_agent_gen():
        user_agent = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.77.4 (KHTML, like Gecko) Version/7.0.5 Safari/537.77.4',
            'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
            'Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.59.10 (KHTML, like Gecko) Version/5.1.9 Safari/534.59.10',
            'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D167 Safari/9537.53',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9',
            'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
            'Mozilla/5.0 (Windows NT 5.1; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
            'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) GSA/4.1.0.31802 Mobile/11D257 Safari/9537.53',
            'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/36.0.1985.125 Chrome/36.0.1985.125 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:30.0) Gecko/20100101 Firefox/30.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10) AppleWebKit/600.1.3 (KHTML, like Gecko) Version/8.0 Safari/600.1.3',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36']
        # returns random legitimate user agent
        return random.choice(user_agent)


class ScanConfigParameters:
    def __init__(self, url, ignored_links_path):
        try:
            # Initialize Scanner Configuration Parameters.
            self.url = url
            # Initialize Session for current run
            self.session = requests.Session()
            # Initialize Data Storage.
            self.DataStorage = DataStorage()
            # Setup initial requirements and prepare files.
            self.setup(ignored_links_path)
        except Exception:
            print(Fore.RED + "\n[ERROR] Something went wrong during initialization. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()

    def setup(self, ignored_links_path):
        try:  # Test connection
            test_get = self.session.get(self.url)
            if test_get.status_code == 404: # If page is not found, scanner will not start.
                print("[Error] Bad URL provided (404). Quitting..")
                quit()
        except requests.ConnectionError: # If ConnectionError identified, try to change the HTTP protocol.
            try: # Switch to HTTP if HTTPs is unsupported
                self.url = self.url.replace("https://", "http://")
                self.session.get(self.url)
            except requests.ConnectionError: # Switch to HTTPs if HTTP is unsupported
                self.url = self.url.replace("http://", "https://")
                self.session.get(self.url)
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong while testing the initial connection. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()

        try:  # Create Error file
            # Try to read an exiting error file, create one is none is found.
            self.err_file = open('err_file.log', 'a')
            # Check if file is empty before writing.
            if os.stat('err_file.log').st_size == 0:
                self.err_file.write("Error File\n")
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong when opening the Error File. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()

        try:  # Link Ignore file # TODO: or change to a config
            #  Try to read an existing link Ignore file, create one if none is found.
            self.ignored_links = open(ignored_links_path + '/linkignore.log', 'r')
            # Check if file is empty before writing.
            if os.stat(ignored_links_path + '/linkignore.log').st_size == 0:
                self.ignored_links.write("www.example_url.com")
            # Add the ignored links to a class variable
            self.ignored_links = self.ignored_links.read()
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong when opening the Ignored Links file. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()


class Utilities(ScanConfigParameters):
    def __init__(self, url, ignored_links_path, username=None, password=None):  # Inherits Config Class
        ScanConfigParameters.__init__(self, url, ignored_links_path)

    def process_login(self, username, password, sec_level=None):
        try:
            # Check for username and password if provided, do nothing if not provided.
            if username and password:
                # Extract the login form information to perform login.
                if self.extract_do_login(self.session.get(self.url).url, username, password, sec_level):
                    print("Login Successful")
                    return True
                else:
                    print("Login Failed. Make sure you provided the right credentials.")
                    quit()
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when attempting to process the login.")
            quit()

    def extract_do_login(self, url, username, password, sec_level=None):
        try:
            # Treat login form as an usual form, extract it.
            login_form = self.extract_forms(url)
            for l_form in login_form:
                # Extract form details and check where data needs to be populated, position one generally username,
                # position two, generally password.
                login_data_new = self.extract_form_details(l_form)
                for idx, (key, value) in enumerate(login_data_new.items()):
                    if login_data_new[key]:
                        continue
                    else:
                        if idx == 0:
                            login_data_new[key] = username
                        elif idx == 1:
                            login_data_new[key] = password
                    # Check if the app requires a "security_level" - test for BWapp App.
                    if key == "security_level" and sec_level is None:
                        sec_level = str(input("Please provide desired security level (0. low, 1. medium, 2. high). \nOption: "))
                        if self.check_sec_input(sec_level):
                            login_data_new[key] = sec_level
                    elif key == "security_level" and sec_level:
                        login_data_new[key] = sec_level
                # Do login and check redirect to index page.
                login_response = self.submit_form(url, l_form, login_data_new)
                if login_response.url != url:
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when attempting to extract the login details. Quitting..", url)
            quit()

    def check_sec_input(self, sec_level):
        try:
            # Check if provided security level is valid recursively.
            if str(sec_level) != '0' and str(sec_level) != '1' and str(sec_level) != '2':
                sec_level = str(input("Please provide choose a valid option (0. low, 1. medium, 2. high)! \nOption: "))
                self.check_sec_input(sec_level)
            return sec_level
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when checking security level (BWapp).")
            pass

    def spider(self, url):
        try:
            # Check if this is the first call, and if it is, add the provided URL to the list.
            global firstCallSpider
            if firstCallSpider:
                response = self.session.get(url)
                self.DataStorage.urls.append(url)
                firstCallSpider = 0
            else:
                response = self.session.get(url)
            # If 200, then endpoint is accessible
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                # Build up URls list by extracting all hrefs and anchors
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and not href.startswith('#'):
                        extracted_url = urllib.parse.urljoin(url, href)
                        # Ensure the app does not scan other webapps by checking if the harvested URL has the same domain as the URL provided by user.
                        if re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)", extracted_url).group(
                                1) == re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)",
                                                self.url).group(1):
                            # Add URLs to main list object, ignore the user - ignored ones.
                            if extracted_url not in self.DataStorage.urls and extracted_url not in self.ignored_links:
                                self.DataStorage.urls.append(extracted_url)
                                self.spider(extracted_url)
                        else:  # TODO: Build site map by adding the related domains (other than the app domain) to a list (one hop only)
                            self.DataStorage.related_domains.append(extracted_url)
            # IF it's not 200 and not 4XX, means that there are some ways of accessing the URL.
            if response.status_code != 200 and response.status_code != 404 and response.status_code != 500:
                # TODO: Create site map.
                pass
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when crawling for links.", url)
            pass

    def extract_headers(self, url):
        try:
            # Get headers of an URL.
            return self.session.get(url).headers
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when getting the headers.", url)
            pass

    def extract_forms(self, url):
        try:
            # Extract all forms from an URL.
            response = self.session.get(url, timeout=300)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")
            return parsed_html.findAll("form")
        except requests.HTTPError as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms from links. A HTTP error occurred.", url)
            pass
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms from links.", url)
            pass

    def extract_form_details(self, form):
        form_data = {}
        try:
            # Extract input fields and their names from the form
            input_fields = form.find_all('input')
            for field in input_fields:
                if field.get('name'):
                    form_data[field.get('name')] = '' # might need back field.get('value', '')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract button fields - for action (submit, search, etc.)
            form_fields = form.find_all('button')
            for field in form_fields:
                if field.get('name'):
                    form_data[field.get('name')] = field.get('value', 'submit')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract Select for drop-downs
            form_option = form.find_all('select')
            for field in form_option:
                if field.get('name'):
                    form_data[field.get('name')] = ''
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract Textarea for big inputs (wall of texts)
            form_textarea = form.find_all('textarea')
            for field in form_textarea:
                if field.get('name'):
                    form_data[field.get('name')] = ''
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass
        return form_data

    def extract_iframes(self, url):
        try:
            # Extract iFrames the same way forms are extracted
            response = self.session.get(url, timeout=300)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")  # , from_encoding="iso-8859-1")
            return parsed_html.findAll("iframe")
        except requests.HTTPError as e:
            self.print_except_message('error', e, "Something went wrong when extracting iframes from links. A HTTP error occurred", url)
            pass
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting iframes from links.", url)
            pass

    def extract_inputs(self, url):
        try:
            # Extract Inputs the same way forms are extracted
            response = self.session.get(url, timeout=300)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")  # , from_encoding="iso-8859-1")
            return parsed_html.findAll("input")
        except requests.HTTPError as e:
            self.print_except_message('error', e, "Something went wrong when extracting inputs from links. A HTTP error occurred", url)
            pass
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting inputs from links.", url)
            pass

    def build_iframe_url(self, url, iframe, payload):
        try:  # Get the src value of the iframe to get the destination of the payload.
            url = url.copy()
            if iframe['src'] in url:
                url = url.replace(iframe['src'], payload)
                return url
            return None
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when building iframe URL.", url)
            pass

    def submit_form(self, url, form, form_data):
        try:
            # Get the action (URL or PATH)
            action = form.get("action")
            # Get the method (GET, POST, PUT etc.)
            if form.get("method"):
                method = form.get("method").upper()
            else:
                return 0
            # Check if action is URL or if it is path relative to URL.
            if action.startswith('http'):
                action_url = action
            else:
                action_url = urllib.parse.urljoin(url, action)

            # Send data accordingly to method.
            if method == 'GET':
                response = self.session.get(action_url, params=form_data, timeout=300)
            else:
                response = self.session.post(action_url, data=form_data, timeout=300)
            response.raise_for_status()
            return response
        except requests.HTTPError as e:
            self.print_except_message('error', e, "Something went wrong when submitting a form. A HTTP error occurred", url)
            pass
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when submitting a form.", url)
            pass

    def custom_user_agent(self, user_agent):
        try:
            # Create custom user-agent based on provided input
            return {'User-Agent': user_agent}
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when modifying the User-Agent.")
            pass

    def extract_injection_fields_from_form(self, form_data):
        try:
            keys_to_populate = []
            # Find the emtpy form values, meaning they await user input, add them to a list and return the list
            for key, value in form_data.items():
                if form_data[key]:
                    continue
                else:
                    keys_to_populate.append(key)
            return keys_to_populate
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting the empty inputs from a form.")
            pass

    def extract_name_value(self, form_data):
        try:
            if 'name' in str(form_data):
                return form_data['name']
            return 0
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting name value from a form.")
            pass

    def extract_cookies(self):
        try:
            return self.session.cookies.get_dict()
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when saving cookies.")
            pass

    def check_scan_build_url(self, url, username=None, password=None, static_scan=None, sec_level=None):
        try:
            # Full scan required
            if static_scan is None:
                # Check if static scan is not required
                if self.session.get(url, timeout=300).url != url or "login" in self.session.get(url, timeout=300).url:
                    # if username or password not provided and are required, throw error
                    if not (username and password):
                        print("You need to provide login credentials first, check --help for details!")
                        quit()
                    # If login is required and static scan not, do login and crawl web app.
                    elif self.process_login(username, password, sec_level):
                        # Scan first time for URL provided by Main, then continue with others.
                        self.spider(url)
                else:
                    # If login is not required, perform crawling.
                    self.spider(url)

            # Static Scan required
            else:
                if self.session.get(url, timeout=300).url != url or "login" in self.session.get(url, timeout=300).url:
                    # if username or password not provided and are required, throw error
                    if not (username and password):
                        print("You need to provide login credentials first, check --help for details!")
                        quit()
                    elif self.process_login(username, password, sec_level):
                        self.DataStorage.urls.append(url)
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when checking for login requirements or scan options. Quitting..")
            quit()

    def extract_non_form_inputs(self, url):
        try:
            name_list = []
            action_urls = []
            input_list = self.extract_inputs(url)
            for input in input_list:
                name_list.append(self.extract_name_value(input))
            for name in name_list:
                action_urls.append(str(url + '?' + str(name) + '='))
            return action_urls
        except Exception as e:
            self.print_except_message('error', e,"Something went wrong when extracting non-form inputs", url)
            pass

    def extract_forms_and_form_data(self, url):
        try:
            form_list = []
            form_data_list = []
            # Extract forms from each URL
            for form in self.extract_forms(url):
                # For each form extract the details needed for payload submission
                form_data = self.extract_form_details(form)
                # Ignore page default forms
                if any([True for key, value in form_data.items() if key == 'form_security_level' or key == 'form_bug']):
                    continue
                form_list.append(form)
                form_data_list.append(form_data)
            return form_list, form_data_list
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting form and form data", url)
            pass

    def no_form_input_content(self, url, payload):  # TODO: Need to get the .JS from sources also to work flawlessly
        try:
            # Extract inputs outside of form or with no method/action in form
            input_list_fin = set()
            form_data = {}
            response_list = []
            soup = BeautifulSoup(self.session.get(url, timeout=300).content, 'html.parser')
            input_list = soup.findAll('input')
            for input in input_list:
                if input.find_parent('form'):
                    parent_attr = input.find_parent('form').attrs
                    if not (('action' in parent_attr) or ('button' in parent_attr)):
                        input_list_fin.add(input)
                else:
                    input_list_fin.add(input)
            if input_list_fin:
                for field in input_list_fin:
                    if field.get('name'):
                        form_data[field.get('name')] = payload

            # Harvest page for scripts containing path, since none can be found
            # Brute-force inputs for destination path.
            potential_paths = re.findall(r'["\']([^"\']*\.php)["\']', self.session.get(url).text)
            new_temp_url = re.match('^https?:\/\/([^\/]+\/)*', url)
            potential_paths.append(url)
            for potential_path in potential_paths:
                # Ignore commonly used words unrelated with what is needed.
                if 'logout' in str(potential_path).lower() or 'reset' in str(potential_path).lower() or 'change' in str(potential_path).lower():
                    continue
                new_url = str(new_temp_url.group()) + potential_path
                if self.session.get(new_url).status_code == 200:
                    response_list.append(self.session.post(new_url, params=form_data))
            return response_list
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting inputs outside of forms or with forms with no method.", url)
            pass

    def check_hidden_tag(self, url, form_data):
        try:
            inputs = self.extract_inputs(url)
            for input in inputs:
                if input['name'] in form_data:
                    if input['type'] == 'hidden':
                        return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when checking for hidden inputs.", url)
            pass

    def print_except_message(self, m_type, error=None, custom_message=None, url=None):
        try:
            if m_type == 'warning':
                if error:
                    if custom_message:
                        print(Fore.LIGHTRED_EX + "\n[WARNING] " + custom_message)
                        print(Fore.RESET)
                        print(error)
                    else:
                        print(Fore.LIGHTRED_EX + "\n[WARNING] " + error)
                else:
                    if custom_message:
                        print(Fore.LIGHTRED_EX + "\n[WARNING] " + custom_message)

            if m_type == 'error':
                if error:
                    if custom_message:
                        print(Fore.RED + "\n[ERROR] " + custom_message + "\nPlease check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR] URL:" + url + "\nDetails: " + custom_message + "\nError Details: " + error, file=self.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR] " + "\nDetails: " + custom_message + "\nError Details: " + error, file=self.err_file)
                    else:
                        print(Fore.RED + "\n[ERROR] Please check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR] URL:" + url + "\nError Details: " + error, file=self.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR] " + error, file=self.err_file)
            print(Fore.RESET)
        except Exception:
            print(Fore.RED + "[ERROR] Something went wrong when printing to Error File.")
            print(Fore.RESET)
            pass


# Scanner class handles scan jobs
class Scanner(Utilities):
    def __init__(self, url, ignored_links_path, username=None, password=None, static_scan=None, comprehensive_scan=None):
        self.Utils = Utilities.__init__(self, url, ignored_links_path, username, password)
        self.comprehensive_scan = comprehensive_scan
        self.check_scan_build_url(url, username, password, static_scan)
        self.username = username
        self.password = password
        self.ignored_links_path = ignored_links_path

    def scan(self):
        try:
            # Scan harvested URLs
            for url in self.DataStorage.urls:
                # Call all functions for tests for each URL. ignore links ignored in file
                if url in self.ignored_links:
                    continue
                # Form and URL scan
                self.scan_html(url)
                self.scan_iframe(url)
                self.scan_code_exec(url)
                self.scan_php_exec(url)
                self.scan_ssi(url)
                self.scan_sql(url)
                self.scan_role_def_dir(url)
                self.scan_role_def_cookie(url)
                #self.scan_browser_cache(url) # Ok, just whole app is vuln
                # self.scan_session(url) # TODO : Fix Strong Sessions
                self.scan_xss(url)
                # self.t_i_xml(url) # TODO: Fix XML
                self.scan_idor(url)

                html_report.write_html_report()
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when attempting to initialize scan function. Quitting..")
            quit()

# Injections

    def t_i_sql(self, url, form, form_data):
        try:
            # Initialize default Confidence for forms/URLs and SQL types list
            confidence = 0
            sql_type_list = set()
            time_based = False
            # Get Initial ~ normal response time with no Payload
            response_wo_1 = self.submit_form(url, form, "")
            if not response_wo_1:
                return 0, 0, 0
            response_time_wo_1 = response_wo_1.elapsed.total_seconds()
            response_time_wo_2 = self.submit_form(url, form, "").elapsed.total_seconds()
            response_time_wo_3 = self.submit_form(url, form, "").elapsed.total_seconds()

            if not response_time_wo_1 or not response_time_wo_2 or not response_time_wo_3:
                return 0, 0, 0

            # Create average response time
            avg_response_time = (response_time_wo_1 + response_time_wo_2 + response_time_wo_3) / 3

            # Find the injection points for the SQL Payload
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for sql_payload in self.DataStorage.payloads("SQL"):
                # Populate injection keys with payloads.
                for injection_key in injection_keys:
                    form_data[injection_key] = sql_payload
                # Check time based only once, heavy load on time of execution.
                if time_based and self.DataStorage.inject_type(sql_payload) == 'time_based_sql':
                    continue
                response_injected = self.submit_form(url, form, form_data)
                if not response_injected:
                    return 0, 0, 0
                payload_response_time = response_injected.elapsed.total_seconds()
                # Get time of response and check.
                if payload_response_time > avg_response_time and payload_response_time > 2 and time_based is False:
                    # Vulnerable to Time based SQL type X, increase confidence
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                    time_based = True
                    continue

                if "error" in response_injected.text.lower():  # TODO: Might need to create other detection condition.
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                # Check if comprehensive scan is required, if not, jump out on 3 vulnerabilities hit, for time management.

                if self.comprehensive_scan is False and confidence > 0:
                    return True, sql_type_list, confidence
                # Check if vulnerability is found or not, if comprehensive is required.
                elif self.comprehensive_scan is True and sql_payload == self.DataStorage.payloads("SQL")[-1] and confidence > 0:
                    return True, sql_type_list, confidence
            return False, [], 0
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
            pass

    def t_i_sql_nfi(self, url):
        try:
            for sql_payload in self.DataStorage.payloads("SQL"):
                if not self.DataStorage.inject_type(sql_payload) == 'time_based_sql':
                    continue
                response_injected = self.no_form_input_content(url, sql_payload)
                if not response_injected:
                    return 0
                for response_inj in response_injected:
                    if response_inj.elapsed.total_seconds() > 4.5:
                        return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SQL Injection with no form inputs.", url)
            pass

    def t_ua_sql(self, url):
        try:
            # Get Initial ~ normal response time with no Payload
            response_time_wo = self.session.get(url, timeout=300).elapsed.total_seconds()
            # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
            time_based = False
            for sql_payload in self.DataStorage.payloads("SQL"):
                # Inject headers with payloads
                headers = self.custom_user_agent(sql_payload)
                try:
                    response = self.session.get(url, timeout=300, headers=headers)
                except Exception:
                    continue
                # Check response type (time or feedback)
                if time_based is False and response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                    time_based = True
                    continue
                if "error" in response.text.lower():  # TODO: Might need to create other detection condition.
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e,"Something went wrong when testing for User-Agent SQL Injection.", url)
            pass

    def scan_sql(self, url):
        try:
            # Scan inputs in form
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                # Test SQL Injections and print results
                sql_vuln, sql_type, sql_conf = self.t_i_sql(url, form, form_data_list[index])
                if sql_vuln:
                    if 0 < sql_conf <= 3:
                        html_report.add_vulnerability('SQL Injection', 'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}.'.format(url, sql_type), 'Medium')
                    else:
                        html_report.add_vulnerability('SQL Injection', 'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}'.format(url, sql_type), 'Critical')
            # Bulk up User-Agent SQL Injection detection in the same function
            if self.t_ua_sql(url):
                html_report.add_vulnerability('SQL Injection - User Agent',
                                              'SQL Injection vulnerability identified on URL: {} using custom User-Agent.'.format(
                                                  url), 'Critical')

            # Scan inputs outside forms/with no actionable form
            if self.t_i_sql_nfi(url):
                html_report.add_vulnerability('SQL Injection',
                                              'Time based (Blind) SQL Injection vulnerability identified on URL: {}.'.format(
                                                  url), 'Medium')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
            pass

    def t_i_html(self, url, form, form_data):
        try:
            # Select injection points from form details
            confidence = 0
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for html_payload in self.DataStorage.payloads("HTML"):
                # Inject each payload into each injection point
                for injection_key in injection_keys:
                    form_data[injection_key] = html_payload
                response_injected = self.submit_form(url, form, form_data)
                if not response_injected:
                    return 0, 0
                # Check for html_payload (tags included) in response, success execution if available.
                if html_payload in response_injected.text:
                    confidence += 1
                if self.comprehensive_scan is False and confidence > 0:
                    return True, confidence
                elif self.comprehensive_scan is True and html_payload == self.DataStorage.payloads("HTML")[-1] and confidence > 0:
                    return True, confidence
            return False, 0
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
            pass

    def t_i_html_nfi(self, url):
        try:
            for html_payload in self.DataStorage.payloads("HTML"):
                # Inject each payload into each injection point
                response_injected = self.no_form_input_content(url, html_payload)
                if not response_injected:
                    return 0
                # Check for html_payload (tags included) in response, success execution if available.
                for response_inj in response_injected:
                    if html_payload in response_inj.text:
                        return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing HTML Injection with non-form inputs.", url)
            pass

    def scan_html(self, url):
        try:
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                html_vuln, confidence = self.t_i_html(url, form, form_data_list[index])
                # Print if Vulnerabilities are found.
                if html_vuln:
                    if 0 < confidence <= 3:
                        html_report.add_vulnerability('HTML Injection',
                                                      'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                          url), 'Low')
                    else:
                        html_report.add_vulnerability('HTML Injection',
                                                      'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                          url), 'High')
            # Test on non-form inputs
            if self.t_i_html_nfi(url):
                html_report.add_vulnerability('HTML Injection',
                                              'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'Medium')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
            pass

    def t_i_iframe(self, url, iframe):
        try:
            # iFrame payload is another page.
            iframe_payload = 'https://www.google.com'
            iframe_url = self.build_iframe_url(url, iframe, iframe_payload)
            # If iFrame loads the new page it means it is vulnerable.
            if iframe_url:
                if iframe_payload in self.session.get(iframe_url).text.lower():
                    html_report.add_vulnerability('iFrame Injection',
                                                  'iFrame Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for iFrame Injection.", url)
            pass

    def scan_iframe(self, url):
        try:
            # Perform tests for each iFrame
            for iframe in self.extract_iframes(url):
                self.t_i_iframe(url, iframe)
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for iFrame Injection.", url)
            pass

    def t_i_code_exec(self, url, form, form_data):  # TODO: maybe add more payloads
        try:
            # Detects blind and standard Code Exec (Ping for 3 seconds)
            code_exec_payload = "| ping -c 3 127.0.0.1"
            # Get injection points and inject the payload.
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for injection_key in injection_keys:
                form_data[injection_key] = code_exec_payload
            response = self.submit_form(url, form, form_data)
            if not response:
                return 0
            # Detect both blind and standard Code Execs.
            if response.elapsed.total_seconds() > 1.5:
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.", url)
            pass

    def t_i_code_exec_nfi(self, url):
        try:
            # Detects blind and standard Code Exec (Ping for 3 seconds)
            code_exec_payload = "| ping -c 3 127.0.0.1"
            response_injected = self.no_form_input_content(url, code_exec_payload)
            if not response_injected:
                return 0
            # Detect both blind and standard Code Execs.
            for response_inj in response_injected:
                if response_inj.elapsed.total_seconds() > 1.5:
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection in non-form inputs.", url)
            pass

    def scan_code_exec(self, url):
        try:
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                if self.t_i_code_exec(url, form, form_data_list[index]):
                    html_report.add_vulnerability('Code Execution Injection',
                                                  'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High')

            # Non-form input
            if self.t_i_code_exec_nfi(url):
                html_report.add_vulnerability('Code Execution Injection',
                                              'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.", url)
            pass

    def t_i_php_exec(self, url):
        try:
            # URL escaped since it is injected into URL
            php_exec_payload = "%60ping%20-c%203%20127.0.0.1%60"
            # Extract all injectable values, since it is applied for URL, look into URL only
            values_after_equal = re.findall('(?<==)[^&]+', url)
            if values_after_equal:
                for value in values_after_equal:
                    # Injection into URL each value
                    url = url.replace(value, php_exec_payload)
            else:
                return
            # Get response time, detects both blind and standard PHP injections
            response = self.session.get(url)
            if response.elapsed.total_seconds() > 1.5:
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.", url)
            pass

    def scan_php_exec(self, url):
        try:
            if self.t_i_php_exec(url):
                html_report.add_vulnerability('PHP Code Execution Injection',
                                              'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.", url)
            pass

    def t_i_ssi(self, url, form, form_data):
        try:
            # Non-blind detection. Search for UNIX time format in response.
            ssi_payload = '<!--#exec cmd=uptime -->'
            # Inject only injectable fields
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for injection_key in injection_keys:
                form_data[injection_key] = ssi_payload
            response = self.submit_form(url, form, form_data)
            if not response:
                return 0
            return re.findall('\d\d:\d\d:\d\d', str(response.text))
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).", url)
            pass

    def t_i_ssi_nfi(self, url):
        try:
            # Non-blind detection. Search for UNIX time format in response.
            ssi_payload = '<!--#exec cmd=uptime -->'
            response_injected = self.no_form_input_content(url, ssi_payload)
            if not response_injected:
                return 0
            for response_inj in response_injected:
                if re.findall('\d\d:\d\d:\d\d', str(response_inj.text)):
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes) in non-form inputs.", url)
            pass

    def scan_ssi(self, url):
        try:
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                if self.t_i_ssi(url, form, form_data_list[index]):
                    html_report.add_vulnerability('SSI Code Execution Injection',
                                                  'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High')
            # Scan non-form inputs
            if self.t_i_ssi_nfi(url):
                html_report.add_vulnerability('SSI Code Execution Injection',
                                              'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).", url)
            pass

    def t_i_xml(self, url):
        try:
            ajax_xml_urls = self.extract_non_form_inputs(url)
            print(ajax_xml_urls)
            # for sql_payload in self.DataStorage.payloads("SQL"):
            #     response = self.session.get(action_url + sql_payload)
            #     if "error" in response.text.lower():
            #         return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for XML Injection.", url)
            pass

# Broken Authentication & Session Mgmt

    def t_ba_role_definition_cookie(self):
        try:
            cookie_dict = self.extract_cookies()
            if "isadmin" in str(cookie_dict).lower():
                if str(cookie_dict.lower()["isAdmin"]).lower() == "true" or \
                        str(cookie_dict.lower()["isAdministrator"]).lower() == "true" or \
                        str(cookie_dict.lower()["admin"]).lower() == "true" or \
                        str(cookie_dict.lower()["administrator"]).lower() == "true":
                    return True
            if "role" in str(cookie_dict).lower():
                if str(cookie_dict.lower()["role"]).lower() == "admin" or \
                        str(cookie_dict.lower()["role"]).lower() == "administrator" or \
                        str(cookie_dict.lower()["role"]).lower() == "manager" or \
                        str(cookie_dict.lower()["role"]).lower() == "auditor" or \
                        str(cookie_dict.lower()["role"]).lower() == "mod":
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.")
            pass

    def scan_role_def_cookie(self, url):
        try:
            if self.t_ba_role_definition_cookie():
                html_report.add_vulnerability('Administrator roles defined in Cookie',
                                              'Administrator roles defined in Cookie identified on URL: {}. Session can be hijacked!'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.", url)
            pass

    def t_ba_role_definition_directories(self, url):
        try:
            link = url.lower()
            if "admin" in link or "administrator" in link or "mod" in link or "moderator" in link:
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition directories.", url)
            pass

    def scan_role_def_dir(self, url):
        try:
            if self.t_ba_role_definition_directories(url):
                html_report.add_vulnerability('Administrator roles defined in URL',
                                              'Administrator roles defined in URL identified on URL: {}. Session can be hijacked!'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition directories.", url)
            pass

    def t_ba_session(self, url):
        try:
            cookie_dict = self.extract_cookies()
            if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(cookie_dict).lower():
                if 'secure' not in str(cookie_dict).lower() or 'httponly' not in str(cookie_dict).lower():
                    return True, cookie_dict
            return False, None
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when checking the session.", url)
            pass

    def scan_session(self, url):
        try:
            session_vuln, curr_session_cookies = self.t_ba_session(url)
            if session_vuln:
                if self.t_ba_strong_session(url, curr_session_cookies):
                    html_report.add_vulnerability('Insecure Session (HTTPS)',
                                                  'Insecure Session (HTTPS) identified on URL: {}. Session was successfully hijacked!'.format(
                                                      url), 'Medium')
                else:
                    html_report.add_vulnerability('Insecure Session (HTTP)',
                                                  'Insecure Session (HTTP) identified on URL: {}. Session was successfully hijacked!'.format(
                                                      url), 'Medium')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when checking the session.", url)
            pass

    def t_ba_browser_cache_weakness(self, url):
        try:
            response = self.session.get(url)
            if "Cache-Control" in str(response.headers):
                if (response.headers["Cache-Control"] != "no-store" and response.headers["Cache-Control"] == "no-cache, must-revalidate") or\
                        (response.headers["Cache-Control"] == "no-store" and
                         response.headers["Cache-Control"] != "no-cache, must-revalidate"):
                    return False
            return True
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing browser cache.", url)
            pass

    def scan_browser_cache(self, url):
        try:
            if self.t_ba_browser_cache_weakness(url):
                html_report.add_vulnerability('Cache Weakness',
                                              'Potential Browser Cache Weakness vulnerability identified.'.format(
                                                  url), 'Low')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing browser cache.", url)
            pass

    def t_ba_strong_session(self, url, cookies):
        try:
            new_user = CreateUserSession(url, self.ignored_links_path, self.username, self.password, "2")
            new_user_cookies = new_user.extract_cookies()
            for key, value in cookies.items():
                if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(key).lower():
                    current_session = value
            for key, value in new_user_cookies.items():
                if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(key).lower() and current_session:
                    new_user.session.cookies[str(key)] = str(current_session)
                    print(new_user.session.cookies.get_dict()) # TODO: Find why session wont be chanced ffs and check alternative ways of identification
            new_user_response = new_user.session.get(url)
            # print("old", cookies)
            # print(new_user.session.cookies.get_dict())
            # if 'login' not in new_user_response.url.lower():
            #     return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for strong sessions.", url)
            pass

# Cross Site Scripting

    def t_i_xss(self, url, form, form_data):
        try:
            confidence = 0
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for xss_payload in self.DataStorage.payloads("XSS"):
                # Inject each payload into each injection point
                for injection_key in injection_keys:
                    form_data[injection_key] = xss_payload
                response_injected = self.submit_form(url, form, form_data)
                if not response_injected:
                    return False, 0
                if xss_payload.lower() in response_injected.text.lower():
                    confidence += 1
                if self.comprehensive_scan is False and confidence > 0:
                    return True, confidence
                elif self.comprehensive_scan is True and xss_payload == self.DataStorage.payloads("XSS")[ -1] and confidence > 0:
                    return True, confidence
            return False, 0
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
            pass

    def t_i_xss_nfi(self, url):
        try:
            for xss_payload in self.DataStorage.payloads("XSS"):
                response_injected = self.no_form_input_content(url, xss_payload)
                if not response_injected:
                    return False
                for response_inj in response_injected:
                    if xss_payload.lower() in response_inj.text.lower():
                        return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
            pass

    def t_ua_xss(self, url):
        try:
            for payload in self.DataStorage.payloads("XSS"):
                # Inject headers with payloads
                headers = self.custom_user_agent(payload)
                try:
                    response = self.session.get(url, timeout=300, headers=headers)
                except Exception:
                    continue
                # Check response type (time or feedback)
                if payload.lower() in response.text.lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for User-Agent XSS Injections.", url)
            pass

    def scan_xss(self, url):
        try:
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                xss_vuln, confidence = self.t_i_xss(url, form, form_data_list[index])
                if xss_vuln:
                    if 0 < confidence <= 3:
                        html_report.add_vulnerability('XSS Injection',
                                                      'XSS Injection vulnerability identified on form. URL: {}'.format(
                                                          url), 'High')
                    else:
                        html_report.add_vulnerability('XSS Injection',
                                                      'XSS Injection vulnerability identified on form. URL: {}'.format(
                                                          url), 'Critical')
            if self.t_i_xss_nfi(url):
                html_report.add_vulnerability('XSS Injection',
                                              'XSS Injection vulnerability identified on URL: {}'.format(
                                                  url), 'High')
            if self.t_ua_xss(url):
                html_report.add_vulnerability('XSS Injection',
                                              'XSS Injection vulnerability identified using custom User-Agent. URL: {}'.format(
                                                  url), 'Critical')
            return 0
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
            pass

# Insecure Direct Object References
    def t_idor(self, url, form_data):
        try:
            if self.check_hidden_tag(url, form_data):
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
            pass

    def t_idor_nfi(self, url): # TODO: Modify IDOR to be generic
        try:
            attempts = 0
            sub_string = re.findall('[?](.*)[=]*\d', url)
            if sub_string:
                index_from_url = int(str(re.findall('\d', str(sub_string))))
                response = self.session.get(url)
                while attempts < 10:
                    try:
                        url.replace(str(index_from_url), index_from_url + 1)
                        response_2 = self.session.get(url)
                        if response != response_2 and str(response_2.status_code).startswith("2"):
                            return True
                    except Exception:
                        index_from_url += 1
                        attempts += 1
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
            pass

    def scan_idor(self, url):
        try:
            if self.t_idor_nfi(url):
                html_report.add_vulnerability('IDOR',
                                              'Insecure direct object reference (IDOR) vulnerability identified. URL: {}'.format(
                                                  url), 'Medium')
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                if self.t_idor(url, form_data_list[index]):
                    html_report.add_vulnerability('IDOR',
                                                  'Insecure direct object reference (IDOR) vulnerability identified on form. URL: {}'.format(
                                                      url), 'Medium')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
            pass


class CreateUserSession(Utilities):
    try:
        def __init__(self, url, ignored_links_path, username, password, sec_level=None):
            self.user = Utilities.__init__(self, url, ignored_links_path, username, password)
            # self.check_scan_build_url(url, username, password, sec_level=sec_level)
    except Exception as e:
        print(Fore.RED + "\n[ERROR] Something went wrong when creating a new user session. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)

#     def search_paths(self): # TODO: Find way to find hidden URLs/ alternative paths
#         try:
#             with open(config_object["FILE"]["hidden_url_dict"], "r") as file:
#                 paths = file.read().split("\n")
#                 file.close()
#             for hidden_path in paths:
#                 if self.target_url + hidden_path not in self.visited and\
#                         self.target_url + hidden_path not in self.ignored_links and\
#                         self.target_url + hidden_path not in self.target_links and\
#                         "logout" not in self.target_url + hidden_path and\
#                         len(self.visited) <= int(config_object['TEST']['max_number_of_hidden_links']):
#                     response = self.session.get(self.target_url + hidden_path)
#                     if response.status_code == 200:
#                         link_visited = self.target_url + hidden_path
#                         self.visited.append(str(link_visited))
#             if self.visited:
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when searching for paths. Error: ", e, file=self.error_file)
#             pass
#
#

    # def test_nosql(self, form, url):  # Add more payloads
    #     try:
    #         global nosql_injection_dict_normal, nosql_injection_dict_injected
    #         no_nosql_payload = ""
    #         response_wh_payload = self.submit_form(form, no_nosql_payload, url)
    #         normal_response_time = response_wh_payload.elapsed.total_seconds()
    #         nosql_detect_payload = "';sleep(5000); ';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);"  # https://www.objectrocket.com/blog/mongodb/code-injection-in-mongodb/
    #         response_w_payload = self.submit_form(form, nosql_detect_payload, url)
    #         nosql_response_time = response_w_payload.elapsed.total_seconds()
    #
    #         if nosql_response_time > normal_response_time and nosql_response_time > 1:
    #             nosql_injection_dict_normal[url] = normal_response_time
    #             nosql_injection_dict_injected[url] = nosql_response_time
    #             return True
    #         return False
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when testing for NOSQL Injection. Error: ", e, file=self.error_file)
    #         print("[Error Info] FORM:", form, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
    #
    # def javascript_exec(self, url):  # Add more payloads
    #     try:
    #         try:
    #             my_gui.update_list_gui("Testing for JS Code Execution")
    #         except Exception:
    #             pass
    #         js_payload = '/?javascript:alert(testedforjavascriptcodeexecutionrn3284)'
    #         if url[-1] != '/':
    #             new_url = url + js_payload
    #         else:
    #             new_url = url + js_payload[1:]
    #         response = self.session.get(new_url)
    #         return 'alert(testedforjavascriptcodeexecutionrn3284)' in str(response.text).lower()
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when testing Javascript code execution. Error: ", e,
    #               file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
    #
    #
    # def host_header_injection(self, url):
    #     try:
    #         try:
    #             my_gui.update_list_gui("Testing for HH Injection")
    #         except Exception:
    #             pass
    #         host = {'Host': 'www.google.com'}
    #         x_host = {'X-Forwarded-Host': 'www.google.com'}
    #         if self.session.get(url, headers=host).status_code == 200:
    #             return True
    #         elif self.session.get(url, headers=x_host).status_code == 200:
    #             return True
    #         return False
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when testing Host Header Injection. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
    #
    # def ssrf_injection(self, url):  # Add more payloads
    #     try:
    #         try:
    #             my_gui.update_list_gui("Testing for SSRF Injection")
    #         except Exception:
    #             pass
    #         ssrf_payload = "=https://www.google.com/"
    #         url = url.replace('=', ssrf_payload)
    #         response = self.session.get(url)
    #         if response.status_code == 200:
    #             return True
    #         ssrf_payload = '=file:///etc/passwd'
    #         url = url.replace('=', ssrf_payload)
    #         if "root:" in self.get_content(url).text.lower():
    #             return True
    #         return False
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when testing Server Side Request Forgery. Error: ", e,
    #               file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass




    #

    #
    #
    # def check_hidden_path(self, h_path):
    #     try:
    #         try:
    #             my_gui.update_list_gui("Searching for hidden paths")
    #         except Exception:
    #             pass
    #         response = self.session.get(self.target_url + h_path)
    #         if response == 200:
    #             return True
    #         return False
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when checking hidden paths. Error: ", e, file=self.error_file)
    #         print("[Error Info]  Hidden Path:", h_path, file=self.error_file)
    #         pass

    # # Get Info
    # def fingerprint(self, url):
    #     try:
    #         try:
    #             my_gui.update_list_gui("Fingerprinting application")
    #         except Exception:
    #             pass
    #         global server_set
    #         header_for_link = self.extract_headers(url)
    #         server_set.add(header_for_link["Server"])
    #         return
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when searching for application server. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass

    #
    # def get_comments_dtds_scripts_from_content(self, url):
    #     try:
    #         try:
    #             my_gui.update_list_gui("Trying to get comments and scripts from source")
    #         except Exception:
    #             pass
    #         global comment_set, dtd_url
    #         content = self.session.get(url)
    #         comments = re.findall('(?<=<!--)(.*)(?=-->)', str(content.text))
    #         if 'strict.dtd' in str(content.text).lower() or 'loose.dtd' in str(content.text).lower() or 'frameset.dtd' in str(content.text).lower():
    #             dtd_url.append(url)
    #         if comments:
    #             comments_list = [comm for comm in comments if comm]
    #             for comm in comments_list:
    #                 comment_set.add(comm)
    #         js_inside_html = re.findall('(?<=<script>)(.*)(?=</script>)', str(content.text).lower())
    #         if js_inside_html:
    #             js_code_list = [code for code in js_inside_html if code]
    #             for js_code in js_code_list:
    #                 script_set.add(js_code)
    #         return
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when trying to get comments from DOM. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass


#     # Vulnerabilities
#
#     # A3:2017-Sensitive Data Exposure
#     # checking certificate...
#
#     def check_tls(self, to_check=None):  # needs change
#         try:
#             try:
#                 my_gui.update_list_gui("Testing TLS")
#             except Exception:
#                 pass
#             context = ssl.create_default_context()
#             with socket.create_connection((self.target_url, 443)) as sockk:
#                 with context.wrap_socket(sockk, server_hostname=self.target_url) as tlssock:
#                     y = getattr(tlssock, to_check)
#                     return y()
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking TLS. Most likely you don't have any certificate. Error: ", e, file=self.error_file)
#             pass
#
#     def check_tls_version(self):
#         try:
#             print("\nChecking TLS extensions version...", file=self.report_file)
#             version = self.check_tls("version")
#             if version:
#                 found = True
#             else:
#                 found = False
#             legacy_tls = [x.strip() for x in config_object["TLSVERSION"]["tlsversion"].split(',')]
#             for legacy in legacy_tls:
#                 if str(version).lower() == legacy:
#                     print(version.lower, file=self.report_file)
#                     print(
#                         "[!!!-!!!] Found Legacy Version for TLS extension, this version contains cryptographic weaknesses: " + str(
#                             version), file=self.report_file)
#             if not found:
#                 print("[???-???] Cannot find the version of the TLS extension...", file=self.report_file)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking TLS version. Most likely you don't have any certificate. Error: ", e, file=self.error_file)
#             pass
#
#     def check_tls_validity(self):
#         try:
#             print("\nChecking Validity of Digital Certificate...", file=self.report_file)
#             sep = " "
#             stripped = self.check_tls("getpeercert")["notAfter"].split(sep, -1)[:-1]
#             if not stripped:
#                 print("[???-???] Cannot check validity of the TLS extension...", file=self.report_file)
#                 return
#             str1 = " "
#             good_date = str1.join(stripped)
#             date_time_obj = datetime.strptime(good_date, '%b %d %H:%M:%S %Y')
#             if not date_time_obj:
#                 print("[???-???] Cannot check validity of the TLS extension...", file=self.report_file)
#                 return
#             print("Certificate expires in: ", date_time_obj-datetime.today(), file=self.report_file)
#             return
#         except Exception as e:
#             print("[???-???] Cannot check validity of the TLS extension...", file=self.report_file)
#             print("\n[ERROR] Something went wrong when checking TLS validity. Most likely you don't have any certificate. Error: ", e, file=self.error_file)
#             pass
#
#     def check_tls_issuer(self):
#         try:
#             print("\nChecking Digital Certificate Issuer...", file=self.report_file)
#             ssl_context = ssl.create_default_context()
#             with ssl_context.wrap_socket(socket.socket(), server_hostname=self.target_url) as s:
#                 s.connect((self.target_url, 443))
#                 cert = s.getpeercert()
#             if cert:
#                 subject = dict(x[0] for x in cert['subject'])
#                 issued_to = subject['commonName']
#                 issuer = dict(x[0] for x in cert['issuer'])
#                 issued_by = issuer['commonName']
#                 if issued_to and issued_by:
#                     print("Digital Certificate is issued by: ", issued_by, file=self.report_file)
#                     print("Digital Certificate is issued to: ", issued_to, file=self.report_file)
#                     return
#             else:
#                 print("[???-???] Cannot check issuer of the TLS extension...", file=self.report_file)
#                 return
#         except Exception as e:
#             print("[???-???] Cannot check issuer of the TLS extension...", file=self.report_file)
#             print("\n[ERROR] Something went wrong when checking TLS issuer. Most likely you don't have any certificate. Error: ", e, file=self.error_file)
#             pass


#     # A5:2017-Broken Access Control
#     # Directory Traversal File Include # https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#basic-lfi
#
#     def lfi_script(self, url, script):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for LFI")
#             except Exception:
#                 pass
#             lfi_script = script
#             url = url.replace("=", "=" + lfi_script)
#             if "root:" in self.get_content(url).text.lower():
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing LFI. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             print("[Error Info] SCRIPT:", script, file=self.error_file)
#             pass
#
#     def rfi_script(self, url, script):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for RFI")
#             except Exception:
#                 pass
#             rfi_script = script
#             url = url.replace("=", "=" + rfi_script)
#             if self.get_content(url).url != url:
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing RFI. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             print("[Error Info] SCRIPT:", script, file=self.error_file)
#             pass
#
#     def test_lfi_directory_transversal(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for LFI Directory Transversal")
#             except Exception:
#                 pass
#             if self.local_file_inclusion(url):
#                 return 1
#             if "=" in url:
#                 if server_set in linux_servers or server_set in mixed_servers:
#                     if self.lfi_script(url, "../../../etc/passwd") or \
#                             self.lfi_script(url, "../../../etc/passwd%00") or \
#                             self.lfi_script(url, "%252e%252e%252fetc%252fpasswd") or \
#                             self.lfi_script(url, "%252e%252e%252fetc%252fpasswd%00") or \
#                             self.lfi_script(url, "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd") or \
#                             self.lfi_script(url, "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00") or \
#                             self.lfi_script(url, "....//....//etc/passwd") or \
#                             self.lfi_script(url, "..///////..////..//////etc/passwd") or \
#                             self.lfi_script(url, "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"):
#                         return 1
#                 elif server_set in windows_servers in mixed_servers:
#                     if self.lfi_script(url, "../") or \
#                             self.lfi_script(url, "..\/") or \
#                             self.lfi_script(url, "%2e%2e%2f") or \
#                             self.lfi_script(url, "%252e%252e%252f") or \
#                             self.lfi_script(url, "%c0%ae%c0%ae%c0%af") or \
#                             self.lfi_script(url, "%uff0e%uff0e%u2215") or \
#                             self.lfi_script(url, "%uff0e%uff0e%u2216") or \
#                             self.lfi_script(url, "..././"):
#                         return 1
#                 if self.rfi_script(url, "https://www.google.com/"):
#                     return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing LFI directory transversal. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def test_cookie_directory_transversal(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for Cookie Directory Transversal")
#             except Exception:
#                 pass
#             dummy_session = OtherUser(config_object["CREDENTIAL"]["username_2"], config_object["CREDENTIAL"]["known_password_2"], err_file=self.error_file).session
#             cookie_dict = self.extract_cookies(url, dummy_session)
#             key_list = list(cookie_dict.keys())
#             for key in key_list:
#                 dummy_session.cookies.set(key, "../")
#                 if self.get_content(url, dummy_session).url is not url:
#                     dummy_session.close()
#                     return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing cookie directory transversal. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     # Bypassing Authorization Schema
#     # Horizontal
#
#     def test_bypass_auth(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Trying to bypass authentication")
#             except Exception:
#                 pass
#             if config_object["WEBURL"]["private_info_url"] == "None":
#                 return
#             first_user_session_id = None
#             second_user_session_id = None
#             response_first_user = None
#             response_second_user = None
#             dummy_user = OtherUser(config_object["CREDENTIAL"]["username_2"],
#                                    config_object["CREDENTIAL"]["known_password_2"], url, err_file=self.error_file)
#             dummy_session = dummy_user.session
#             dummy_session.get(url)
#             cookie_dict = self.extract_cookies(url, dummy_session)
#             key_list = list(cookie_dict.keys())
#             for key in key_list:
#                 if key.lower() == "sid" or "sessionid" or "session" or "sessiontoken" or "sessid":
#                     first_user_session_id = cookie_dict[key]
#                 else:
#                     return 0
#
#             if first_user_session_id:
#                 second_user_session_id = dummy_user.get_sess_id()
#             if second_user_session_id:
#                 data = {
#                     config_object["CREDENTIAL"]["username_field"]: config_object["CREDENTIAL"]["username"]
#                 }
#                 response_first_user = dummy_session.post(config_object["WEBURL"]["private_info_url"], data=data)
#                 for key in key_list:
#                     if key.lower() == "sid" or "sessionid" or "session" or "sessiontoken" or "sessid":
#                         dummy_session.cookies.set(key, second_user_session_id)
#                 response_second_user = dummy_session.post(config_object["WEBURL"]["private_info_url"], data=data)
#             if response_first_user and response_second_user:
#                 if str(response_first_user.text) == str(response_second_user.text):
#                     return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying to bypass authentication. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     # Special Request Header
#
#     def test_special_req_header(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for special request headers")
#             except Exception:
#                 pass
#             response_wo_headers = self.session.get(url)
#             response_w_x_original = self.session.get(url, headers={"X-Original-URL": "/donotexistrandomstring1238123"})
#             response_w_x_rewrite = self.session.get(url, headers={"X-Rewrite-URL": "/donotexistrandomstring1238123"})
#             if response_wo_headers.status_code == 404 or response_w_x_original.status_code == 404 or response_w_x_rewrite.status_code == 404:
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing special headers. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#         # Privilege Escalation
#
#     def test_privilege_escalation(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for privilege escalation")
#             except Exception:
#                 pass
#             response = self.session.get(url)
#             if "grp" or "group" or "role" in str(response.text).lower() or "grp" or "group" or "role" in response.url.lower():
#                 for data in privilege_data:
#                     response = self.session.post(url, data=data)
#                     if response.status_code != 401:
#                         return 1
#             if "X-Forwarded-For:" in response.headers:
#                 print("\n[WARN] X-Forwarded-For header present on link: ", file=self.report_file)
#                 print(url, file=self.report_file)
#                 print("Hackers may change the IP value!", file=self.report_file)
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing privilege escalation. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#
#
#     # A6:2017-Security Misconfigurations
#     # Test File Extensions Handling for Sensitive Information
#     # Present Extensions (analyze robots.txt)
#
#     def search_extensions_robots(self):  # https://github.com/danielmiessler/RobotsDisallowed/blob/master/top1000.txt
#         try:
#             try:
#                 my_gui.update_list_gui("Checking robots.txt")
#             except Exception:
#                 pass
#             f = open(config_object['FILE']['robots_dict'], "r")
#             print("\nAnalyzing robots.txt for interesting urls..!", file=self.report_file)
#             potential_display = []
#             unwanted_display_of_url = []
#             dir_list = [line.strip() for line in f.readlines()]
#             f.close()
#             robots_url = str(config_object["WEBURL"]["target"]) + "/robots.txt"
#             req_robots = self.session.get(robots_url)
#             robots_urls = re.findall('Disallow: (.*)', req_robots.text)
#             if not len(robots_urls) <= 3:
#                 print("Directories ignored by search engines:", file=self.report_file)
#                 print(*robots_urls, sep="\n", file=self.report_file)
#             else:
#                 print("No directories found inside robots.txt", file=self.report_file)
#                 return
#             print("Testing for something interesting...", file=self.report_file)
#             for item in dir_list:
#                 if item in robots_urls:
#                     potential_display.append(item)
#                 check_disallow_url = str(config_object["WEBURL"]["target"]) + str(item)
#                 if self.check_response(check_disallow_url):
#                     unwanted_display_of_url.append(check_disallow_url)
#             if potential_display:
#                 print("[!!!-!!!]Potential display of sensitive information found in robots.txt: ", file=self.report_file)
#                 print(*potential_display, sep="\n")
#             if unwanted_display_of_url:
#                 print("[!!!-???]Got OK response from the following URLs. Sensitive information might be revealed. Manual check needed: ", file=self.report_file)
#                 print(*unwanted_display_of_url, sep="\n", file=self.report_file)
#             if not potential_display or not unwanted_display_of_url:
#                 print("[END]Nothing interesting found on robots.txt. It may be empty.", file=self.report_file)
#             print("[END] End of analyzing robots.txt", file=self.report_file)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when analyzing robots.txt. Error: ", e, file=self.error_file)
#             pass
#
#     # Form present extensions
#
#     def check_forms_files(self, form):
#         try:
#             try:
#                 my_gui.update_list_gui("Checking forms for file extensions")
#             except Exception:
#                 pass
#             action = form.get("action")
#             if not action:
#                 return False
#             elif "." in action and '/' not in action and '\\' not in action:
#                 inputs_list = form.findAll("input", type='hidden')
#                 for inputs in inputs_list:
#                     input_type = inputs.get("type")
#                     if str(input_type).lower() == "hidden":
#                         return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking form 'action' attribute. Error: ", e, file=self.error_file)
#             print("[Error Info] FORM:", form, file=self.error_file)
#             pass
#
#     # HTTP Methods
#
#     def test_http(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing HTTP Methods")
#             except Exception:
#                 pass
#             test_data = {"test": 'test'}
#             response = self.session.put(str(config_object['WEBURL']['target']) + '/test.html', data=test_data)
#             if str(response.status_code).startswith("3") or str(response.status_code).startswith("2"):
#                 return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing HTTP Methods. Error: ", e, file=self.error_file)
#             pass
#
#     # HTTP Strict Transport Security
#
#     def test_hsts(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing HSTS")
#             except Exception:
#                 pass
#             headers = self.extract_headers(config_object['WEBURL']['target'])
#             if 'strict' not in str(headers).lower():
#                 return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Strict Transport on headers. Error: ", e, file=self.error_file)
#             pass
#
#     # Test RIA
#
#     def test_ria(self, link_list):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing RIA")
#             except Exception:
#                 pass
#             content = None
#             for link in link_list:
#                 if 'clientaccesspolicy.xml' in link.lower() or 'crossdomain.xml' in link.lower():
#                     content = self.session.get(link)
#                 try:
#                     if '*' in content:
#                         return True
#                 except TypeError:
#                     pass
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing RIA. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK LIST:", link_list, file=self.error_file)
#             pass
#
#     # File Upload Vulnerability Extension
#
#     def create_file_dir(self, subdir):
#         try:
#             global temp_dir
#             filenames = ["filefortest.php", "fIleForTest.Php.JpEG", "fiL3ForTest.hTMl.JPG", "shell.phPWND", "fIleForTest.eXe.jsp"]
#             here = os.path.dirname(os.path.realpath(__file__))
#             temp_dir = os.path.join(here, subdir)
#             if not os.path.exists(temp_dir):
#                 os.mkdir(temp_dir)
#             for filename in filenames:
#                 if not os.path.isfile("./" + filename):
#                     filepath = os.path.join(here, subdir, filename)
#                     test_file = open(filepath, 'w+')
#                     test_file.write("This is unharmful content to be uploaded to the site")
#                     test_file.close()
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when creating temporary files. Error: ", e, file=self.error_file)
#             print("[Error Info] SUBDIR Name:", subdir, file=self.error_file)
#             pass
#
#     def file_upload(self, form, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing File Upload Injection")
#             except Exception:
#                 pass
#             is_file = False
#             inputs_list = form.find_all("inputs")
#             response = self.get_content(url)
#             if 'multipart/form-data' in str(response.content).lower():
#                 is_file = True
#             for inputs in inputs_list:
#                 if inputs.get("type").lower() == "file":
#                     is_file = True
#             if is_file is True:
#                 self.create_file_dir("temp")
#                 cur_path = os.path.join(os.path.dirname(__file__), 'temp')
#                 dir_listing = os.listdir(cur_path)
#                 os.chdir(cur_path)
#                 for i in dir_listing:
#                     path_for_file = os.path.relpath('..\\temp\\' + i, cur_path)
#                     f = open(path_for_file, 'rb')
#                     files = {'uploaded': f}
#                     if self.submit_form(form, "value", url, files).status_code == 200:
#                         f.close()
#                         if os.getcwd() != stable_directory:
#                             os.chdir(stable_directory)
#                         return True
#             if os.getcwd() != stable_directory:
#                 os.chdir('..')
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing file upload. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             print("[Error Info] FORM:", form, file=self.error_file)
#             pass
#
#
#     # Test LFI
#
#     def local_file_inclusion(self, url):
#         try:
#             lfi_script = "~"
#             url = url.replace("=", "=" + lfi_script)
#             if self.check_response(url):
#                 return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing LFI. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     # MISC
#
#     def hidden_paths(self):
#         try:
#             if self.search_paths():
#                 print("Possible Hidden Paths Found:", file=self.map_file)
#                 print(*self.visited, sep="\n", file=self.map_file)
#             return
#         except Exception:
#             pass
#
#     def admin_directories(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Searching for admin directories")
#             except Exception:
#                 pass
#             links_admin_path = []
#             has_admin_directories = self.test_role_definition_directories()
#             if has_admin_directories:
#                 for link in has_admin_directories:
#                     links_admin_path.append(link)
#                 print("\n[!!!---???] Possible Admin Path discovered for links:", file=self.report_file)
#                 print(*links_admin_path, sep="\n", file=self.report_file)
#                 print("[END] End of admin paths", file=self.report_file)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when searching for admin directories. Error: ", e, file=self.error_file)
#             pass
#
#     def create_return_merge_links(self):
#         try:
#             global final_list
#             visible_links = len(self.target_links)
#             invisible_links_length = len(self.visited)
#             print("\nVisible Links Length:", visible_links, "\nHidden Links Length:", invisible_links_length, file=self.report_file)
#             final_list = self.target_links + self.visited
#             # print("\n[!!!-!!!] Performing tests on NOT hidden links", file=self.report_file)
#             return visible_links, final_list
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when merging hidden links with visible links lists. Error: ", e, file=self.error_file)
#             pass
#
#     def gather_info(self, url=None):
#         try:
#             if not url:
#                 try:
#                     my_gui.update_list_gui("Gathering general information")
#                 except Exception:
#                     pass
#                 print("\n\t\t\t############################# Web Application Architecture #############################", file=self.map_file)
#                 print("\nFound links in this order:\n", file=self.map_file)
#                 self.spider()
#                 print("[END] End of visible links found!", file=self.map_file)
#                 print("\n\nStarting search for hidden links..", file=self.map_file)
#                 self.hidden_paths()
#                 print("[END] End of hidden links found!\n", file=self.map_file)
#                 print("\n[NMAP] Nmap Scan Results", file=self.report_file)
#                 self.get_port_info(test=(True if config_object['TEST']['nmap_scan'].lower() == "true" else False))
#                 print("[END] End of Nmap Scan Results", file=self.report_file)
#             else:
#                 self.fingerprint(url)
#                 self.get_port(url)
#                 self.get_comments_dtds_scripts_from_content(url)
#             return
#
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when gathering information about server running on application. Error: ", e, file=self.error_file)
#             pass
#
#     # Test Suit Classifier
#
#     def test_injections(self, url, form=None, test=False):
#         try:
#             if test:
#                 if form and url:
#                     if self.t_i_xss_in_form(form, url):
#                         links_forms_dict_xss[url] = form
#                     if self.test_sql(form, url):
#                         links_forms_dict_sql_injection[url] = form
#                     if self.code_exec(form, url):
#                         links_forms_dict_code_exec[url] = form
#                     if self.ssi_injection(form, url):
#                         links_forms_dict_ssi_injection[url] = form
#                     if self.test_nosql(form, url):
#                         links_forms_dict_nosql_injection[url] = form
#                 elif "=" in url:
#                     if self.t_i_xss_in_link(url):
#                         links_xss_link.append(url)
#                     if self.t_i_html(url):
#                         links_html_injection.append(url)
#                     if self.ssrf_injection(url):
#                         links_ssrf_injection.append(url)
#                 elif url:
#                     if self.javascript_exec(url):
#                         links_javascript_code.append(url)
#                     if self.host_header_injection(url):
#                         links_host_header_injection.append(url)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Injections. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def test_broken_auth(self, url=None, test=False):
#         try:
#             if test:
#                 if not url:
#                     self.admin_directories()
#                 else:
#                     if "=" in url:
#                         if self.check_session_id(url):
#                             print("\n[!!!-!!!]SessionID Hijack Vulnerability found", file=self.report_file)
#                         if self.local_file_inclusion(url):
#                             links_vulnerable_to_lfi.append(url)
#                     else:
#                         if self.test_role_definition_cookie(url):
#                             links_potential_role_definition.append(url)
#                         if self.test_browser_cache_weakness(url):
#                             links_browser_cache_weakness.append(url)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Broken Authentication. Error: ", e, file=self.error_file)
#             pass
#
#     def test_sensitive_data_exposure(self, url=None, form=None, test=False):
#         try:
#             if test:
#                 if not url:
#                     self.check_tls_version()
#                     self.check_tls_validity()
#                     self.check_tls_issuer()
#                 else:
#                     if form:
#                         if self.check_form_action(form):
#                             links_forms__dict_sensitive_info[url] = form
#                     elif self.check_secure_tag_cookie_sessid(url):
#                         links_without_secure_cookie_with_sessid.append(url)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Sensitive Data Exposure. Error: ", e, file=self.error_file)
#             pass
#
#     def test_xml_external_entities(self, url=None, test=False):
#         try:
#             if test:
#                 if self.inject_xml(url):
#                     links_xee_vuln.append(url)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing XML External Entities. Error: ", e, file=self.error_file)
#             pass
#
#     def test_broken_access_control(self, url=None, test=False):
#         try:
#             if test:
#                 if '=' in url:
#                     if self.test_idor(url):
#                         links_idor.append(url)
#                 else:
#                     if self.test_lfi_directory_transversal(url):
#                         links_lfi_directory_transversal.append(url)
#                     if self.test_cookie_directory_transversal(url):
#                         links_cookie_directory_transversal.append(url)
#                     if self.test_special_req_header(url):
#                         links_special_header.append(url)
#                     if self.test_bypass_auth(url):
#                         links_bypass_authorization.append(url)
#                     if self.test_privilege_escalation(url):
#                         links_privilege_escal.append(url)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Broken Access Control. Error: ", e, file=self.error_file)
#             pass
#
#     def test_security_misconfiguration(self, url=None, form=None, test=False):
#         try:
#             if test:
#                 if not url:
#                     self.search_extensions_robots()
#                     if self.test_http():
#                         print("\n[!!!---!!!] HTTP PUT Method got OK status. Application might be vulnerable!", file=self.report_file)
#                     if self.test_hsts():
#                         print(
#                             "\n[!!!---!!!] HTTP Strict Transport Security NOT found. Application is vulnerable to sniffing and certificate invalidation vulnerability!", file=self.report_file)
#                     if self.test_ria(final_list):
#                         print(
#                             "\n[!!!---???] Overly permissive policy file found. Tester must review Crossdomain.xml / Clientaccesspolicy.xml", file=self.report_file)
#                 else:
#                     if form:
#                         if self.check_forms_files(form):
#                             links_forms_files_in_form[url] = form
#                         if self.file_upload(form, url):
#                             links_forms_dict_file_upload[url] = form
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing Security Misconfiguration. Error: ", e, file=self.error_file)
#             pass
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Scan Web Application for Vulnerabilities')
        # Provide argument for URL. URL does not require flag but requires 'URL'.
        parser.add_argument("url", type=str, help="Provide an URL to scan")
        # Provide custom path to ignored links file, default is working directory.
        parser.add_argument("-i", "--ignored_links_path", help="Absolute Path to ignored links file", default=os.getcwd())
        # Get Credentials for login if needed. Flags not mandatory/
        parser.add_argument("-u", "--username", help="Username to login with")
        parser.add_argument("-p", "--password", help="Password to login with")
        # Provide static scan argument, default is crawling. Static (or single) only tests the provided URL.
        parser.add_argument("-s", "--static_scan", help="Scan a single URL provided in the terminal", action="store_true", default=False)
        # Comprehensive tests forces the all tests to be performed.
        parser.add_argument("-c", "--comprehensive_scan", help="Scan the application against all vulnerability tests available", action="store_true", default=False)

        args = parser.parse_args()
        # If username and password is provided, continue with checking if static flag is required or not.
        if args.username and args.password:
            if args.static_scan:
                # Sent the relevant arguments in relation to the required scan type.
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.ignored_links_path, args.username, args.password,
                                      static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.ignored_links_path, args.username, args.password,
                                      static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
            # If static scan not required, continue without flag and perform scan type.
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.ignored_links_path, args.username, args.password,
                                      comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.ignored_links_path, args.username, args.password,
                                      comprehensive_scan=args.comprehensive_scan)
        # If no username AND password is provided, determine scan type and try to scan. If username and password are required but not provided, app will throw an error.
        elif not (args.username and args.password):
            if args.static_scan:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.ignored_links_path, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.ignored_links_path, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.ignored_links_path, comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.ignored_links_path,
                                      comprehensive_scan=args.comprehensive_scan)
        Scanner.scan()
    except Exception as e:
        print(Fore.RED + "\n[ERROR] FATAL ERROR OCCURRED. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)
        quit()
