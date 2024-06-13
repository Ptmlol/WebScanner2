from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_host_header(url):
    try:
        host = {'Host': 'google.com'}
        host_injection = ScanConfig.session.get(url, headers=host)
        x_host = {'X-Forwarded-Host': 'google.com'}
        x_host_injection = ScanConfig.session.get(url, headers=x_host)
        if host_injection.status_code == 200 and str(host_injection.url) == str(url):
            return True
        elif x_host_injection.status_code == 200 and str(x_host_injection.url) == str(url):
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing Host Header Injection.", url)
        pass


def run(main_url):
    try:
        if t_i_host_header(main_url):
            html_report.add_vulnerability('Host-Header Injection',
                                          'Host-Header Injection vulnerability identified on URL: {}'.format(
                                              main_url), 'Low')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Host Header Injection.", main_url)
        pass