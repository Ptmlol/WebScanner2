import re

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Modify IDOR to be generic

def t_idor(url, form_data):
    try:
        if Utilities.check_hidden_tag(url, form_data):
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass


def t_idor_nfi(url):
    try:
        attempts = 0
        sub_string = re.findall('[?](.*)[=]*\d', url)
        if sub_string:
            index_from_url = int(str(re.findall('\d', str(sub_string))))
            response = ScanConfig.session.get(url)
            while attempts < 10:
                try:
                    url.replace(str(index_from_url), index_from_url + 1)
                    response_2 = ScanConfig.session.get(url)
                    if response != response_2 and str(response_2.status_code).startswith("2"):
                        return True
                except Exception:
                    index_from_url += 1
                    attempts += 1
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass

def run(url):
    try:
        if t_idor_nfi(url):
            html_report.add_vulnerability('IDOR',
                                          'Insecure direct object reference (IDOR) vulnerability identified. URL: {}'.format(
                                              url), 'Medium')
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        for index, form in enumerate(form_list):
            if t_idor(url, form_data_list[index]):
                html_report.add_vulnerability('IDOR',
                                              'Possible Insecure direct object reference (IDOR) vulnerability identified on form. URL: {}'.format(
                                                  url), 'Low')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass