import re
import urllib.parse

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Create detection of sensitive data in this robots by the above URL
# TODO: Prettify the print of robots contents to report or to HTML report
# https://github.com/danielmiessler/RobotsDisallowed/blob/master/top1000.txt

def run(main_url, scan_type):
    try:
        if 'robots' not in main_url and scan_type is None:
            url_robots = urllib.parse.urljoin(main_url, '/robots.txt')
        else:
            url_robots = main_url
        req_robots = ScanConfig.session.get(url_robots)
        robots_urls = re.findall('Disallow: (.*)', req_robots.text)
        if robots_urls:
            html_report.add_vulnerability('Robots.txt',
                                          'Robots.txt contains the following values: \n{}'.format(
                                              ['<br>' + str(i).replace("'", "").replace('[', '').replace(']', '') for i in robots_urls]),
                                          'Informational')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing Robots.txt.", main_url)
        pass