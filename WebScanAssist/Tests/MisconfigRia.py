from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def run(main_url):
    try:
        content = None
        if 'clientaccesspolicy.xml' in main_url.lower() or 'crossdomain.xml' in main_url.lower():
            content = ScanConfig.session.get(main_url)
        try:
            if '*' in content:
                html_report.add_vulnerability('Overly Permissive Policy File found',
                                              'Review Crossdomain.xml / Clientaccesspolicy.xml files. URL: {}'.format(
                                                  main_url), 'Low')
        except TypeError:
            pass
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing RIA.", main_url)
        pass