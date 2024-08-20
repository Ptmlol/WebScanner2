from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def run(main_url):
    try:
        print("Testing RIA files policy..")
        content = None
        if 'clientaccesspolicy.xml' in main_url.lower() or 'crossdomain.xml' in main_url.lower():
            content = ScanConfig.session.get(main_url)
        try:
            if '*' in content:
                html_report.add_vulnerability('Overly Permissive Policy File found',
                                              'Overly Permissive Policy File found. URL: {}'.format(
                                                  main_url), 'Low', comment="Review Crossdomain.xml / Clientaccesspolicy.xml files.")
        except TypeError:
            pass
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing RIA.", main_url)
        pass