from Core.Utilities import Utilities
from Report import html_report


def run(main_url):
    try:
        print("Testing HTTP Strict Transport Security policy..")
        headers = Utilities.extract_headers(main_url)
        if 'strict' not in str(headers).lower():
            html_report.add_vulnerability('HTTP Strict Transport Security not found',
                                          'Application might be vulnerable to sniffing and certificate invalidation attacks. URL: {}'.format(
                                              main_url), 'Low', comment="'Strict' tag not found in headers.")

        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing Strict Transport on headers.",
                                  main_url)
        pass