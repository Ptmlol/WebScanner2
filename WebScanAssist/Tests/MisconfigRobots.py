import re
import urllib.parse

from Core.DataStorage import DataStorage
from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


# https://github.com/danielmiessler/RobotsDisallowed/blob/master/top1000.txt
def run(main_url, scan_type):
    try:
        print("Testing for sensitive data in the Robots.txt file..")
        sensitive_list = set()
        if 'robots' not in main_url and scan_type is None:
            if main_url[-1] == '/':
                url_robots = main_url + 'robots.txt'
            else:
                url_robots = main_url + '/robots.txt'
        else:
            url_robots = main_url
        req_robots = ScanConfig.session.get(url_robots)
        robots_urls = re.findall('Disallow: (.*)', req_robots.text)
        if robots_urls:
            for sensitive in DataStorage.payloads('ROBO'):
                sensitive_list.update(robot for robot in robots_urls if sensitive.strip() in robot)
            if sensitive_list:
                html_report.add_vulnerability('Robots.txt',
                                              'Robots.txt contains the following sensitive values:', comment='Possible Sensitive values identified in robots.txt:' +
                                                                                                             str([str(i).replace("'", "").replace('[', '').replace(']', '').replace('\r', '')
                                                                                                                  for i in sensitive_list]), confidence='Medium')


    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing Robots.txt.", main_url)
        pass
