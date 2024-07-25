import html
import warnings
import ast
from CustomImports import html_report

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
        cpe_list = set()
        cpes = nvdlib.searchCPE(keywordSearch=app_name, key=API_KEY ,delay=1)
        for cpe in cpes:
            cpe_array = str(cpe.cpeName).split(':')
            if (':' + str(version) + ':') in str(cpe.cpeName) and (cpe_array[3] == app_name or cpe_array[4] == app_name):
                cpe_list.add(cpe.cpeName)
        return cpe_list
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when getting CPEs. Passing..")
        pass

def get_cve(cpe_name):
    API_KEY = ScanConfig.config_params['API']['API_KEY']
    try:
        cve_dict = {}
        cves = nvdlib.searchCVE(cpeName=cpe_name, limit=5, key=API_KEY, delay=1)
        for cve in cves:
            cve_dict[cpe_name] = [str(cve.id), html.unescape(str(cve.descriptions)), str(cve.url), str(cve.score)]
        return cve_dict
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when getting CVEs. Passing..")
        pass

def run(url):
    try:
        app_dict = {}
        cve_dict = {}
        cpe_list = []
        non_version_app_list = []
        total_apps = get_apps(url)
        for app_name, version in total_apps.items():
            app_dict[app_name] = str(total_apps[app_name]['versions']).replace('[', '').replace(']', '').replace("'", '')
        for app_name, version in app_dict.items():
            if version:
                cpe = get_cpes(app_name.lower(), version)
                if cpe:
                    cpe_list.extend(cpe)
            else:
                non_version_app_list.append(app_name)
        for cpeName in cpe_list: # Remove duplicates
            cve_dict.update(get_cve(cpeName))

        for name, dict_array in cve_dict.items():
            cpe_array = str(name).split(':')
            app_name_supp = cpe_array[3]
            app_name_prod = cpe_array[4]
            cve_id = dict_array[0]
            dict_array[1] = ast.literal_eval(dict_array[1])
            dict_array[1][0] = ast.literal_eval(str(dict_array[1][0]))
            cve_description = str(dict_array[1][0]['value']).replace('\n', '')
            cve_url = dict_array[2]
            dict_array[3] = ast.literal_eval(dict_array[3])
            cve_score = dict_array[3][1]
            cve_severity = dict_array[3][2]

            html_report.add_cve(app_name_supp, app_name_prod, cve_id, cve_description, cve_url, cve_score, cve_severity)
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when getting CPEs. Passing..")
        pass