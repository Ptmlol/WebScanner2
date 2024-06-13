from datetime import datetime

from werkzeug.exceptions import InternalServerError

from Classes.ScanConfig import ScanConfig
from bs4 import BeautifulSoup
from bs4 import MarkupResemblesLocatorWarning
import warnings
import requests
import urllib.parse
import urllib.request
import re
from colorama import Fore


from CustomImports import html_report

firstCallSpider = 1

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class Utilities(ScanConfig):
    def __init__(self, url):  # Inherits Config Class
        ScanConfig.__init__(self, url)

    def process_login(self, username, password, sec_level=None):
        try:
            # Check for username and password if provided, do nothing if not provided.
            if username and password:
                # Extract the login form information to perform login.
                if self.do_login(self.session.get(self.url).url, username, password, sec_level):
                    print("Login Successful")
                    return True
                else:
                    print("Login Failed. Make sure you provided the right credentials.")
                    quit()
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when attempting to process the login.")
            quit()

    def do_login(self, url, username, password, sec_level=None):
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
            Utilities.print_except_message('error', e,
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
            Utilities.print_except_message('error', e, "Something went wrong when checking security level (BWapp).")
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
            Utilities.print_except_message('error', e, "Something went wrong when crawling for links.", url)
            pass

    @staticmethod
    def extract_headers(url):
        try:
            # Get headers of an URL.
            return ScanConfig.session.get(url).headers
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when getting the headers.", url)
            pass

    @staticmethod
    def extract_forms(url):
        try:
            # Extract all forms from an URL.

            response = ScanConfig.session.get(url, timeout=10)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")
            return parsed_html.findAll("form")
        except requests.HTTPError as e:
            if e.response.status_code == 500:
                return None
            Utilities.print_except_message('error', e,
                                      "Something went wrong when extracting forms from links. A HTTP error occurred.",
                                      url)
            pass
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting forms from links.", url)
            pass

    @staticmethod
    def extract_form_details(form):
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
            Utilities.print_except_message('error', e, "Something went wrong when extracting forms details.")
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
            Utilities.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract Select for drop-downs
            form_option = form.find_all('select')
            for field in form_option:
                if field.get('name'):
                    form_data[field.get('name')] = ''
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass

        try:
            # Extract Textarea for big inputs (wall of texts)
            form_textarea = form.find_all('textarea')
            for field in form_textarea:
                if field.get('name'):
                    form_data[field.get('name')] = ''
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting forms details.")
            pass
        return form_data


    @staticmethod
    def extract_inputs(url):
        try:
            # Extract Inputs the same way forms are extracted
            response = ScanConfig.session.get(url, timeout=300)
            response.raise_for_status()
            parsed_html = BeautifulSoup(response.content, "html.parser")  # , from_encoding="iso-8859-1")
            return parsed_html.findAll("input")
        except requests.HTTPError as e:
            Utilities.print_except_message('error', e,
                                      "Something went wrong when extracting inputs from links. A HTTP error occurred",
                                      url)
            pass
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting inputs from links.", url)
            pass

    @staticmethod
    def submit_form(url, form, form_data):
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
                response = ScanConfig.session.get(action_url, params=form_data, timeout=10)
            else:
                response = ScanConfig.session.post(action_url, data=form_data, timeout=10)
            response.raise_for_status()
            return response
        except requests.HTTPError:
            # pass as the application is unable to handle the error
            # Utilities.print_except_message('error', e, "Something went wrong when submitting a form. A HTTP error occurred", url)
            pass
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when submitting a form.", url)
            pass

    @staticmethod
    def prepare_xml_inj(url, payload):
        try:
            # Extract injectable tags from URL
            extracted_uri, extracted_tag = Utilities.extract_xml_tags(url)
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
            Utilities.print_except_message('error', e, "Something went wrong when testing for XML Injection.", url)
            pass

    @staticmethod
    def custom_user_agent(user_agent):
        try:
            # Create custom user-agent based on provided input
            return {'User-Agent': user_agent}
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when modifying the User-Agent.")
            pass

    @staticmethod
    def extract_injection_fields_from_form(form_data):
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
            Utilities.print_except_message('error', e, "Something went wrong when extracting the empty inputs from a form.")
            pass

    def extract_name_value(self, form_data):
        try:
            if 'name' in str(form_data):
                return form_data['name']
            return 0
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting name value from a form.")
            pass

    @staticmethod
    def extract_cookies():
        try:
            return ScanConfig.session.cookies.get_dict()
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when saving cookies.")
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
            Utilities.print_except_message('error', e,
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
            Utilities.print_except_message('error', e, "Something went wrong when extracting non-form inputs", url)
            pass

    @staticmethod
    def extract_forms_and_form_data(url):
        try:
            form_list = []
            form_data_list = []
            # Extract forms from each URL
            forms = Utilities.extract_forms(url)
            if not forms:
                return None, None
            for form in forms:
                # For each form extract the details needed for payload submission
                form_data = Utilities.extract_form_details(form)
                # Ignore page default forms
                if any([True for key, value in form_data.items() if key == 'form_security_level' or key == 'form_bug']):
                    continue
                form_list.append(form)
                form_data_list.append(form_data)
            return form_list, form_data_list
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting form and form data", url)
            pass

    @staticmethod
    def no_form_input_content(url, payload):
        try:
            # Extract inputs outside of form or with no method/action in form
            input_list_fin = set()
            form_data = {}
            response_list = []
            soup = BeautifulSoup(ScanConfig.session.get(url, timeout=300).content, 'html.parser')
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
            try:
                potential_paths = re.findall(r'["\']([^"\']*\.php)["\']', ScanConfig.session.get(url).text)
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
                    if any(ignored in str(potential_path) for ignored in ScanConfig.ignored_links):
                        continue
                    if '../' in potential_path:
                        # If app is browsing for the relative resource ../example.php, we need to go back the same about of paths in the current URL as we have ../ in the identified new paths
                        new_url = str(groups[-potential_path.count('../') - 1]) + "/" + potential_path.replace("../", "")
                    else:
                        new_url = url + potential_path
                    if ScanConfig.session.get(new_url).status_code == 200:
                        response_list.append(ScanConfig.session.post(new_url, params=form_data))
                return response_list
            except Exception:
                pass
        except Exception as e:
            Utilities.print_except_message('error', e,
                                      "Something went wrong when extracting inputs outside of forms or with forms with no method.",
                                      url)
            pass

    @staticmethod
    def check_hidden_tag(url, form_data):
        try:
            inputs = Utilities.extract_inputs(url)
            for input in inputs:
                if input['name'] in form_data:
                    if input['type'] == 'hidden':
                        return True
            return False
        except Exception:
            # Ignore if input not found
            pass

    @staticmethod
    def print_except_message(m_type, error=None, custom_message=None, url=None):
        try:
            if m_type == 'warning':
                if error:
                    if custom_message:
                        print(Fore.LIGHTRED_EX + "\n[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- [WARNING] " + custom_message)
                        print(Fore.RESET)
                        print(error)
                    else:
                        print(Fore.LIGHTRED_EX + "\n[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- [WARNING] " + error)
                else:
                    if custom_message:
                        print(Fore.LIGHTRED_EX + "\n[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- [WARNING] " + custom_message)

            if m_type == 'error':
                if error:
                    if custom_message:
                        print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- " + str(
                            custom_message) + "\nPlease check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- URL:" + str(url) + "\nDetails: " + str(
                                custom_message) + "\nError Details: " + str(error), file=ScanConfig.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- " + "\nDetails: " + str(
                                custom_message) + "\nError Details: " + str(error), file=ScanConfig.err_file)
                    else:
                        print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- Please check the Error file for additional details.")
                        if url:
                            print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- URL:" + str(url) + "\nError Details: " + error,
                                  file=ScanConfig.err_file)
                        else:
                            print(Fore.RED + "\n[ERROR]-[" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "] -- " + str(error), file=ScanConfig.err_file)
            print(Fore.RESET)
        except Exception as e:
            print(Fore.RED + "[ERROR] Something went wrong when printing to Error File.", e)
            print(Fore.RESET)
            pass

    @staticmethod
    def extract_xml_tags(url):
        try:
            pattern_tags = r'xmlHttp\.send\("([^"]+)"\);'
            pattern_uri = r'xmlHttp\.open\("POST","([^"]+)"'
            match_tags = re.search(pattern_tags, ScanConfig.session.get(url).text, re.DOTALL)
            match_uri = re.search(pattern_uri, ScanConfig.session.get(url).text, re.DOTALL)

            if match_tags and match_uri:
                extracted_xml = match_tags.group(1)
                extracted_uri = match_uri.group(1)
                return extracted_uri, extracted_xml
            return None, None
        except Exception as e:
            Utilities.print_except_message('error', e, "Something went wrong when extracting XML tags.", url)
            pass

    @staticmethod
    def pretty_sql(sql_type_input):
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
            Utilities.print_except_message('error', e, "Something went wrong when SQL Types.")
            pass

    @staticmethod
    def str_bool(s):
        return s.lower() in ("yes", "true", "t", "1")