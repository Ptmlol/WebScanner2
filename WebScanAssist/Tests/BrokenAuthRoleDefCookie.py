from Classes.Utilities import Utilities
from CustomImports import html_report


def t_ba_role_def_cookies():
    try:
        # Search for specific keywords that define roles in the cookies.
        cookie_dict = Utilities.extract_cookies()
        if "isadmin" in str(cookie_dict).lower():
            if str(cookie_dict.lower()["isAdmin"]).lower() == "true":
                return cookie_dict.lower()["isAdmin"]
            elif str(cookie_dict.lower()["isAdministrator"]).lower() == "true":
                return cookie_dict.lower()["isAdministrator"]
            elif str(cookie_dict.lower()["admin"]).lower() == "true":
                return cookie_dict.lower()["admin"]
            elif str(cookie_dict.lower()["administrator"]).lower() == "true":
                return cookie_dict.lower()["administrator"]
        if "role" in str(cookie_dict).lower():
            if str(cookie_dict.lower()["role"]).lower() == "admin":
                return cookie_dict.lower()["role"]
            elif str(cookie_dict.lower()["role"]).lower() == "administrator":
                return cookie_dict.lower()["role"]
            elif str(cookie_dict.lower()["role"]).lower() == "manager":
                return cookie_dict.lower()["role"]
            elif str(cookie_dict.lower()["role"]).lower() == "auditor":
                return cookie_dict.lower()["role"]
            elif str(cookie_dict.lower()["role"]).lower() == "mod":
                return cookie_dict.lower()["role"]
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.")
        pass


def run(url):
    try:
        def_cookies = t_ba_role_def_cookies()
        if def_cookies:
            html_report.add_vulnerability('Administrator roles defined in Cookie',
                                          'Administrator roles defined in Cookie identified on URL: {}. Session can be hijacked!'.format(
                                              url), 'High', comment="Identified Cookie: {}".format(def_cookies))
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition on cookies.",
                                  url)
        pass