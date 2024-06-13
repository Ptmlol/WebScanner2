from Classes.Utilities import Utilities
from CustomImports import html_report


def t_ba_role_definition_directories(url):
    # Search for specific keywords that define roles in the URLs
    try:
        link = url.lower()
        if "admin" in link or "administrator" in link or "mod" in link or "moderator" in link:
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                  url)
        pass


def run(url):
    try:
        if t_ba_role_definition_directories(url):
            html_report.add_vulnerability('Administrator roles defined in URL',
                                          'Administrator roles defined in URL identified on URL: {}. Session can be hijacked!'.format(
                                              url), 'High')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                  url)
        pass