from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def run(main_url):
    try:
        response = ScanConfig.session.put(str(main_url) + '/test.html', data={"test": 'test'})
        if str(response.status_code).startswith("3") or str(response.status_code).startswith("2"):
            html_report.add_vulnerability('HTTP PUT Method Vulnerability',
                                          'Application accepts custom PUT data on URL: {}'.format(main_url), 'Low')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", main_url)
        pass