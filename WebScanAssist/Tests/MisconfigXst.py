import requests

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_xst(url):
    try:
        trace_request = requests.Request('TRACE', url)
        prepared_trace = trace_request.prepare()
        if ScanConfig.session.send(prepared_trace).status_code == 200:
            return True
        return False
    except Exception:
        pass


def run(main_url):
    try:
        if t_xst(main_url):
            html_report.add_vulnerability('Cross-Site Tracing (XST)',
                                          'Cross-Site Tracing (XST) vulnerability identified on URL: {}'.format(
                                              main_url), 'Low')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for XST.", main_url)
        pass