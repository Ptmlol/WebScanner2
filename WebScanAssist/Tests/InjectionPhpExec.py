import re

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_php_exec(url):
    try:
        # URL escaped since it is injected into URL
        php_exec_payload = "%60ping%20-c%203%20127.0.0.1%60"
        # Extract all injectable values, since it is applied for URL, look into URL only
        values_after_equal = re.findall('(?<==)[^&]+', url)
        if values_after_equal:
            for value in values_after_equal:
                # Injection into URL each value
                url = url.replace(value, php_exec_payload)
        else:
            return
        # Get response time, detects both blind and standard PHP injections
        response = ScanConfig.session.get(url)
        if response.elapsed.total_seconds() > 1.5:
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                  url)
        pass


def run(url):
    try:
        if t_i_php_exec(url):
            html_report.add_vulnerability('PHP Code Execution Injection',
                                          'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'High')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                  url)
        pass