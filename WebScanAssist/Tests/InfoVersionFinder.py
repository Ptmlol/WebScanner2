import html
import warnings
warnings.simplefilter("ignore", UserWarning)
import requests
from Classes.ScanConfig import ScanConfig
import nvdlib
from Wappalyzer import Wappalyzer, WebPage

from Classes.Utilities import Utilities
from Scanner import Scanner
from colorama import Fore

def get_apps(url):
    response = ScanConfig.session.get(url)
    if response.status_code != 200:
        return

    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_response(response)
    return wappalyzer.analyze_with_versions(webpage)

# https://nvd.nist.gov/developers/vulnerabilities
# https://nvdlib.com/en/latest/v2/CPEv2.html#search-cpe
def get_cpes(app_name, version):
    API_KEY = ScanConfig.config_params['API']['API_KEY']
    try:
        cpe_list = []
        cpes = nvdlib.searchCPE(keywordSearch=app_name, key=API_KEY ,delay=1)
        for cpe in cpes:
            if (':' + str(version) + ':') in str(cpe.cpeName): # PHP 5.2
                cpe_list.append(cpe.cpeName)
        return cpe_list
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when getting CPEs. Passing..")
        pass

def run(url):
    try:
        app_dict = {}
        cpe_list = []
        non_version_app_list = []
        total_apps = get_apps(url)
        print(total_apps)
        for app_name, version in total_apps.items():
            app_dict[app_name] = str(total_apps[app_name]['versions']).replace('[', '').replace(']', '').replace("'", '')
        for app_name, version in app_dict.items():
            if version:
                cpe = get_cpes(app_name.lower(), version)
                if cpe:
                    cpe_list.extend(cpe)
            else:
                non_version_app_list.append(app_name)
        print(cpe_list)
    except Exception as e:
        print(e)