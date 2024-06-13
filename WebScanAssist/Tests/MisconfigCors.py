from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report

# TODO: Make CORS work.

def t_cors(url):
    try:
        if ScanConfig.session.get(url).headers['Access-Control-Allow-Origin'] == '*':
            return True
        return
    except Exception: # Blank by design.
        pass


def run(url):
    try:
        if t_cors(url):
            html_report.add_vulnerability('Cross-Origin Resource Sharing',
                                          'Cross-Origin Resource Sharing (CORS) vulnerability identified on URL: {}'.format(
                                              url), 'Low')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for CORS.", url)
        pass