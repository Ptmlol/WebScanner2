import re

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Modify IDOR to be generic

def t_idor(url, form_data):
    try:
        input_hidden = Utilities.check_hidden_tag(url, form_data)
        if input_hidden:
            return input_hidden
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass


def get_last_query_string(url):
    # Regular expression to capture everything after the last '?'
    match = re.search(r'[^?]*$', url)
    if match:
        return match.group(0)
    return None

def t_idor_nfi(url):
    try:
        attempts = 0
        #sub_string = re.findall('[?](.*)[=]*\d', url)
        #sub_string_list = re.findall(r'\?(.*)', url)
        sub_string = get_last_query_string(url) # query=test&value=123&other=45   --> query=test&value=
        if not sub_string:
            return
        original_sub_string = sub_string
        int_groups = re.findall(r'=(\d+)', str(sub_string))
        for grp in int_groups:
            index_from_url = int(str(grp)) # 123
            sub_string = sub_string.replace(str(index_from_url), str(index_from_url + 5)) # arbitrary number to reduce FP
            response = ScanConfig.session.get(url)
            while attempts < 10:
                try:
                    url = url.replace(original_sub_string, sub_string)
                    response_2 = ScanConfig.session.get(url)
                    if response.text != response_2.text and str(response_2.status_code).startswith("2"):
                        return response_2.url
                except Exception:
                    index_from_url += 3
                    original_sub_string = sub_string
                    sub_string = sub_string.replace(str(index_from_url), str(index_from_url + 1))
                    attempts += 1
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass

def run(url):
    try:
        response_url = t_idor_nfi(url)
        if response_url:
            html_report.add_vulnerability('IDOR',
                                          'Insecure direct object reference (IDOR) vulnerability identified. URL: {}'.format(
                                              url), 'Medium', comment="Got reply from {}. If the URL is referencing objects, the application is vulnerable to this injection.".format(response_url))
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if not (form_list or form_data_list):
            return
        for index, form in enumerate(form_list):
            input_hidden = t_idor(url, form_data_list[index])
            if input_hidden:
                input_hidden= Utilities.escape_string_html(encoded_single=input_hidden)
                html_report.add_vulnerability('IDOR',
                                              'Possible Insecure direct object reference (IDOR) vulnerability identified on form. URL: {}'.format(
                                                  url), 'Low', reply="\nInput: {}.".format(input_hidden), comment="\nFound hidden tag on form. Check tag for Object Reference.")
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing IDOR.", url)
        pass