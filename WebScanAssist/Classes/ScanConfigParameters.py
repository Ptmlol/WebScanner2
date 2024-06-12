import os

import requests
from WebScanAssist.Config import config
from colorama import Fore


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
            # Initialize the ignored links and errors file parameters
            self.ignored_links = None
            self.err_file = None
            # Setup initial requirements and prepare files.
            self.setup()

        except Exception as e:
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