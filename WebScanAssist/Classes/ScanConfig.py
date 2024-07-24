import os

import requests
from colorama import Fore

from Classes.DataStorage import DataStorage
from Config import config


class ScanConfig:
    # Initialize Session for current run
    session = requests.Session()
    # Initialize the ignored links and errors file parameters
    err_file = None
    ignored_links = None
    config_params = config.Config().config_object

    def __init__(self, url):
        try:
            # Initialize Scanner Configuration Parameters.
            self.url = url

            
            # Initialize Data Storage.
            self.DataStorage = DataStorage()
            # Initialize Config File
            # Empty list of links pairs used for hierarchy.
            self.link_pairs = []


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
            ScanConfig.err_file = open('err_file.log', 'a')
            # Check if file is empty before writing.
            if os.stat('err_file.log').st_size == 0:
                ScanConfig.err_file.write("Error File\n")
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong when opening the Error File. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()

        try:  # Import Ignored URLs from Config file.
            ScanConfig.ignored_links = ScanConfig.config_params['URLS']['ignored'].split(",")
        except Exception as e:
            print(Fore.RED + "\n[ERROR] Something went wrong when opening the Ignored Links file. Quitting..\n")
            print(Fore.RESET)
            print("Error: ", e)
            quit()