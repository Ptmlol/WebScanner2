from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def t_weak_browser_cache(url):
    try:
        response = ScanConfig.session.get(url)
        if "Cache-Control" in str(response.headers):
            if (response.headers["Cache-Control"] != "no-store" and response.headers[
                "Cache-Control"] == "no-cache, must-revalidate") or \
                    (response.headers["Cache-Control"] == "no-store" and
                     response.headers["Cache-Control"] != "no-cache, must-revalidate"):
                return False
        return True
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing browser cache.", url)
        pass


def run(main_url):
    try:
        if t_weak_browser_cache(main_url):
            html_report.add_vulnerability('Cache Weakness',
                                          'Potential Browser Cache Weakness vulnerability identified.'.format(
                                              main_url), 'Low', comment="Cache-Control is not properly configured on this application. ")
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing browser cache.", main_url)
        pass