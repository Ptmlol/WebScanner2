from Classes.Utilities import Utilities
from CustomImports import html_report


def t_ba_role_def_cookies():
    try:
        # Search for specific keywords that define roles in the cookies.
        cookie_dict = Utilities.extract_cookies()
        if "isadmin" in str(cookie_dict).lower():
            if str(cookie_dict.lower()["isAdmin"]).lower() == "true" or \
                    str(cookie_dict.lower()["isAdministrator"]).lower() == "true" or \
                    str(cookie_dict.lower()["admin"]).lower() == "true" or \
                    str(cookie_dict.lower()["administrator"]).lower() == "true":
                return True
        if "role" in str(cookie_dict).lower():
            if str(cookie_dict.lower()["role"]).lower() == "admin" or \
                    str(cookie_dict.lower()["role"]).lower() == "administrator" or \
                    str(cookie_dict.lower()["role"]).lower() == "manager" or \
                    str(cookie_dict.lower()["role"]).lower() == "auditor" or \
                    str(cookie_dict.lower()["role"]).lower() == "mod":
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.")
        pass


def run(url):
    try:
        if t_ba_role_def_cookies():
            html_report.add_vulnerability('Administrator roles defined in Cookie',
                                          'Administrator roles defined in Cookie identified on URL: {}. Session can be hijacked!'.format(
                                              url), 'High')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.",
                                  url)
        pass