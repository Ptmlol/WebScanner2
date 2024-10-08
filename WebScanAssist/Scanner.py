import math
from datetime import time

from colorama import Fore
import warnings
from bs4 import MarkupResemblesLocatorWarning
import argparse
from Report import html_report
import re
from Core.Utilities import Utilities
from Tests import InjectionIframe, InjectionSql, InjectionCodeExec, InjectionPhpExec, InjectionSsi, \
    BrokenAuthRoleDefDir, BrokenAuthRoleDefCookie, InjectionXss, InjectionIdor, MisconfigCors, InjectionSsrf, \
    InjectionXml, InjectionLfi, InfoComments, InjectionHtml, BrokenAuthSession, MisconfigBrowserCache, MisconfigXst, \
    MisconfigHhi, MisconfigHttp, MisconfigHsts, MisconfigRia, MisconfigRobots, InjectionJs, InfoDirTransversal, \
    InfoVersionFinder
import threading

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
        self.base_url = min(self.DataStorage.urls, key=len)

    def scan(self):
        try:
            # Scan app
            Scanner.app_scan(self.base_url)
            threads_main = []

            # Scan harvested URLs in sub_lists.
            for url_set in list(Scanner.split_list(list(self.DataStorage.urls), math.ceil(len(list(self.DataStorage.urls)) / 3))):
                threads_main.append(threading.Thread(target=Scanner.run_threads, args=(url_set,)))

            for thread in threads_main:
                thread.start()

            for thread in threads_main:
                thread.join()

            return
        except Exception as e:
            self.print_except_message('error', e,
                                      "Something went wrong when attempting to initialize scan function. Quitting..")
            quit()

    @staticmethod
    def app_scan(url):
        # Generic app tests over whole app. 1 base URL.
        if Utilities.str_bool(Scanner.config_params['TEST']['browser_cache_tests']):
            MisconfigBrowserCache.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['xst_tests']):
            MisconfigXst.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['hhi_tests']):
            MisconfigHhi.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['http_tests']):
            MisconfigHttp.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['hsts_tests']):
            MisconfigHsts.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['ria_tests']):
            MisconfigRia.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['robots_tests']):
            MisconfigRobots.run(url, Scanner.static_scan)
        InfoVersionFinder.run(url)

    @staticmethod
    def thread_time_1(url):
        # Injection - balanced time execution
        if Utilities.str_bool(Scanner.config_params['TEST']['php_execution_tests']):
            InjectionPhpExec.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['ssrf_tests']):
            InjectionSsrf.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['xml_tests']):
            InjectionXml.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['lfi_tests']):
            InjectionLfi.run(url)

    @staticmethod
    def thread_time_2(url):
        if Utilities.str_bool(Scanner.config_params['TEST']['idor_tests']):
            InjectionIdor.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['js_tests']):
            InjectionJs.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['html_tests']):
            InjectionHtml.run(url)

    @staticmethod
    def thread_time_3(url):
        if Utilities.str_bool(Scanner.config_params['TEST']['sql_tests']):
            InjectionSql.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['iframe_tests']):
            InjectionIframe.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['ba_role_def_dir_tests']):
            BrokenAuthRoleDefDir.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['cors_tests']):
            MisconfigCors.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['comments_tests']):
            InfoComments.run(url)

    @staticmethod
    def thread_time_4(url):
        if Utilities.str_bool(Scanner.config_params['TEST']['code_execution_tests']):
            InjectionCodeExec.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['ba_role_def_cookie_tests']):
            BrokenAuthRoleDefCookie.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['ba_session_tests']):
            BrokenAuthSession.run(url)

    @staticmethod
    def thread_time_5(url):
        if Utilities.str_bool(Scanner.config_params['TEST']['ssi_tests']):
            InjectionSsi.run(url)
        if Utilities.str_bool(Scanner.config_params['TEST']['xss_tests']):
            InjectionXss.run(url)

    @staticmethod
    def run_threads(lst):
        try:
            harvested = False
            if Utilities.str_bool(Scanner.config_params['TEST']['harvest_url']) and Scanner.static_scan:
                for url in lst:
                    print("Harvesting URL: ", url)
                    harvest_thread = threading.Thread(target=InfoDirTransversal.t_dir_find, args=(url,))
                    harvested = True

            for url in lst:
                print("Testing URL: ", url)
                threads = [threading.Thread(target=Scanner.thread_time_1, args=(url,)),
                           threading.Thread(target=Scanner.thread_time_2, args=(url,)),
                           threading.Thread(target=Scanner.thread_time_3, args=(url,)),
                           threading.Thread(target=Scanner.thread_time_4, args=(url,)),
                           threading.Thread(target=Scanner.thread_time_5, args=(url,))]

                # Start each thread
                for thread in threads:
                    thread.start()

                if harvested:
                    harvest_thread.start()

                # Wait for all threads to complete
                for thread in threads:
                    thread.join()
            if harvested:
                harvest_thread.join()
        except Exception as e:
            print(e)

    @staticmethod
    def split_list(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

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
        print("Finished.")
        print("See report file for findings.")
    except Exception as e:
        print(Fore.RED + "\n[ERROR] FATAL ERROR OCCURRED. Quitting..\n")
        print(Fore.RESET)
        print("Error: ", e)
        quit()
