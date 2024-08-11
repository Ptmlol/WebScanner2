from Core.Utilities import Utilities
from Report import html_report


def t_ba_role_definition_directories(url):
    # Search for specific keywords that define roles in the URLs
    try:
        link = url.lower()
        if "admin" in link or "administrator" in link or "mod" in link or "moderator" in link:
            return link
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                  url)
        pass


def run(url):
    try:
        def_link = t_ba_role_definition_directories(url)
        if def_link:
            html_report.add_vulnerability('Administrator roles defined in URL',
                                          'Administrator roles defined in URL identified on URL: {}. Session can be hijacked!'.format(
                                              url), 'High', comment="Identified URL: {}".format(def_link))
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for role definition directories.",
                                  url)
        pass