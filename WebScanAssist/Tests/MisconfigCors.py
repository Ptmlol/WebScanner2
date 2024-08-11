from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def t_cors(url):
    try:
        if ScanConfig.session.get(url).headers['Access-Control-Allow-Origin'] == '*':
            return True
        return
    except Exception:
        pass


def run(url):
    try:
        if t_cors(url):
            html_report.add_vulnerability('Cross-Origin Resource Sharing',
                                          'Cross-Origin Resource Sharing (CORS) vulnerability identified on URL: {}'.format(
                                              url), 'Low', comment="Access-Control-Allow-Origin is set to * (Any).")
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for CORS.", url)
        pass
