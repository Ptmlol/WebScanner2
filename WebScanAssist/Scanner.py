from colorama import Fore
import warnings
from bs4 import MarkupResemblesLocatorWarning
import argparse
from CustomImports import html_report
import re
from Classes.Utilities import Utilities
from Tests import InjectionIframe, InjectionSql, InjectionCodeExec, InjectionPhpExec, InjectionSsi, \
    BrokenAuthRoleDefDir, BrokenAuthRoleDefCookie, InjectionXss, InjectionIdor, MisconfigCors, InjectionSsrf, \
    InjectionXml, InjectionLfi, InfoComments, InjectionHtml, BrokenAuthSession, MisconfigBrowserCache, MisconfigXst, \
    MisconfigHhi, MisconfigHttp, MisconfigHsts, MisconfigRia, MisconfigRobots, InjectionJs

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# DVWA : https://github.com/digininja/DVWA

# Scanner class handles scan jobs
class Scanner(Utilities):
    def __init__(self, url, username=None, password=None, static_scan=None):
        Utilities.__init__(self, url)
        self.static_scan = static_scan
        self.check_scan_build_url(url, username, password, static_scan)
        self.username = username
        self.password = password

    def scan(self):
        try:
            # Scan app
            if self.config_params['TEST']['browser_cache_tests']:
                MisconfigBrowserCache.run(self.url)
            if self.config_params['TEST']['xst_tests']:
                MisconfigXst.run(self.url)
            if self.config_params['TEST']['hhi_tests']:
                MisconfigHhi.run(self.url)
            if self.config_params['TEST']['http_tests']:
                MisconfigHttp.run(self.url)
            if self.config_params['TEST']['hsts_tests']:
                MisconfigHsts.run(self.url)
            if self.config_params['TEST']['ria_tests']:
                MisconfigRia.run(self.url)
            if self.config_params['TEST']['robots_tests']:
                MisconfigRobots.run(self.url, self.static_scan)

            # Scan harvested URLs.
            for url in self.DataStorage.urls:

                print("\nTesting URL: ", url)
                # Injections:
                if Utilities.str_bool(self.config_params['TEST']['sql_tests']):
                    InjectionSql.run(url)
                if Utilities.str_bool(self.config_params['TEST']['iframe_tests']):
                    InjectionIframe.run(url)
                if Utilities.str_bool(self.config_params['TEST']['code_execution_tests']):
                    InjectionCodeExec.run(url)
                if Utilities.str_bool(self.config_params['TEST']['php_execution_tests']):
                    InjectionPhpExec.run(url)
                if Utilities.str_bool(self.config_params['TEST']['ssi_tests']):
                    InjectionSsi.run(url)
                if Utilities.str_bool(self.config_params['TEST']['xss_tests']):
                    InjectionXss.run(url)
                if Utilities.str_bool(self.config_params['TEST']['idor_tests']):
                    InjectionIdor.run(url)
                if Utilities.str_bool(self.config_params['TEST']['ssrf_tests']):
                    InjectionSsrf.run(url)
                if Utilities.str_bool(self.config_params['TEST']['xml_tests']):
                    InjectionXml.run(url)
                if Utilities.str_bool(self.config_params['TEST']['lfi_tests']):
                    InjectionLfi.run(url)
                if Utilities.str_bool(self.config_params['TEST']['js_tests']):
                    InjectionJs.run(url)
                if Utilities.str_bool(self.config_params['TEST']['html_tests']):
                    InjectionHtml.run(url)


                # Broken Authentications:
                if Utilities.str_bool(self.config_params['TEST']['ba_role_def_dir_tests']):
                    BrokenAuthRoleDefDir.run(url)
                if Utilities.str_bool(self.config_params['TEST']['ba_role_def_cookie_tests']):
                    BrokenAuthRoleDefCookie.run(url)
                if Utilities.str_bool(self.config_params['TEST']['ba_session_tests']):
                    BrokenAuthSession.run(url)


                # Security Misconfigurations:
                if Utilities.str_bool(self.config_params['TEST']['cors_tests']):
                    MisconfigCors.run(url)


                #Misc
                if Utilities.str_bool(self.config_params['TEST']['comments_tests']):
                    InfoComments.run(url)

            return
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when attempting to initialize scan function. Quitting..")
            quit()

# Problem URLs:
#  http://192.168.116.11/dvwa/docs/DVWA_v1.3.pdf
#  http://192.168.116.11/dvwa/vulnerabilities/sqli_blind/
#  http://192.168.116.11/dvwa/vulnerabilities/fi/?page=file3.php
#  http://192.168.116.11/dvwa/vulnerabilities/fi/?page=file1.php
#  http://192.168.116.11/dvwa/vulnerabilities/fi/?page=file2.php
#  http://192.168.116.11/dvwa/vulnerabilities/sqli/

# class CreateUserSession(Utilities):  # TODO: Create another py module for the new user.
#     try:
#         def __init__(self, url):
#             self.user = Utilities.__init__(self, url)
#             # self.check_scan_build_url(url, username, password, sec_level=sec_level)
#     except Exception as e:
#         print(Fore.RED + "\n[ERROR] Something went wrong when creating a new user session. Quitting..\n")
#         print(Fore.RESET)
#         print("Error: ", e)


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

        args = parser.parse_args()
        # If username and password is provided, continue with checking if static flag is required or not.
        if args.username and args.password:
            if args.static_scan:
                # Sent the relevant arguments in relation to the required scan type.
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.username, args.password, static_scan=args.static_scan)
                else:
                    Scanner = Scanner('http://' + args.url, args.username, args.password, static_scan=args.static_scan)
            # If static scan not required, continue without flag and perform scan type.
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, args.username, args.password)
                else:
                    Scanner = Scanner('http://' + args.url, args.username, args.password)
        # If no username AND password is provided, determine scan type and try to scan. If username and password are required but not provided, app will throw an error.
        elif not (args.username and args.password):
            if args.static_scan:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url, static_scan=args.static_scan)
                else:
                    Scanner = Scanner('http://' + args.url, static_scan=args.static_scan)
            else:
                if re.match('^http|https?://', args.url):
                    Scanner = Scanner(args.url)
                else:
                    Scanner = Scanner('http://' + args.url)

        Scanner.scan()
        html_report.write_html_report()
    except Exception as e:
        print(Fore.RED + "\n[ERROR] FATAL ERROR OCCURRED. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)
        quit()
