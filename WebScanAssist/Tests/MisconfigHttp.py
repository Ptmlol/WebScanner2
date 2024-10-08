from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def run(main_url):
    try:
        print("Testing PUT method policy..")
        response = ScanConfig.session.put(str(main_url) + '/test.html', data={"test": 'test'})
        if str(response.status_code).startswith("3") or str(response.status_code).startswith("2"):
            html_report.add_vulnerability('HTTP PUT Method Vulnerability',
                                          'Application accepts custom PUT data on URL: {}'.format(main_url), 'Low', comment="Got Status Code 200 from PUT Method; sent '/test.html' to URL.")
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", main_url)
        pass