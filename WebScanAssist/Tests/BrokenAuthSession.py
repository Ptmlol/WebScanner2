from Classes.Utilities import Utilities
from CustomImports import html_report

# TODO: Find why session wont be chanced ffs and check alternative ways of identification
# TODO : Fix Strong Sessions

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

# def t_ba_strong_session(url, cookies):
#     try:
#         new_user = CreateUserSession(url, self.username, self.password, "2")
#         new_user_cookies = new_user.extract_cookies()
#         for key, value in cookies.items():
#             if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(key).lower():
#                 current_session = value
#         for key, value in new_user_cookies.items():
#             if ("sid" or "sessionid" or "session" or "sessiontoken" or "sessid") in str(
#                     key).lower() and current_session:
#                 new_user.session.cookies[str(key)] = str(current_session)
#                 print(
#                     new_user.session.cookies.get_dict())
#         # new_user_response = new_user.session.get(url)
#         # print("old", cookies)
#         # print(new_user.session.cookies.get_dict())
#         # if 'login' not in new_user_response.url.lower():
#         #     return True
#         return False
#     except Exception as e:
#         Utilities.print_except_message('error', e, "Something went wrong when testing for strong sessions.", url)
#         pass

def run(url):
    try:
        session_vuln, curr_session_cookies = t_ba_session(url)
        if session_vuln:
            # if t_ba_strong_session(url, curr_session_cookies):
            #     html_report.add_vulnerability('Insecure Session (HTTPS)',
            #                                   'Insecure Session (HTTPS) identified on URL: {}. Session was successfully hijacked!'.format(
            #                                       url), 'Medium')
            # else:
                html_report.add_vulnerability('Insecure Session (HTTP)',
                                              'Insecure Session (HTTP) identified on URL: {}. Session was successfully hijacked!'.format(
                                                  url), 'Medium')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when checking the session.", url)
        pass