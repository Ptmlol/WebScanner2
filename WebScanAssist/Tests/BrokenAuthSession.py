from Classes.Utilities import Utilities
from CustomImports import html_report


def t_ba_session(url):
    # Search for session in the cookie.
    try:
        cookie_dict = Utilities.extract_cookies()
        if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(cookie_dict).lower():
            if 'secure' not in str(cookie_dict).lower() or 'httponly' not in str(cookie_dict).lower():
                return True, cookie_dict
        return False, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when checking the session.", url)
        pass


def run(url):
    try:
        session_vuln, curr_session_cookies = t_ba_session(url)
        if session_vuln:
            html_report.add_vulnerability('Insecure Session (HTTP)',
                                          'Insecure Session (HTTP) identified on URL: {}. Session was successfully hijacked!'.format(
                                              url), 'Medium')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when checking the session.", url)
        pass
