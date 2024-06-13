import html

from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_code_exec(url, form, form_data):
    try:
        # Detects blind and standard Code Exec (Ping for 3 seconds)
        code_exec_payload = "|ping -c 7 127.0.0.1"  # 8.8.8.8|cat /etc/passwd
        # Get injection points and inject the payload.
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for injection_key in injection_keys:
            form_data[injection_key] = html.unescape(code_exec_payload)
        response = Utilities.submit_form(url, form, form_data)
        if not response:
            return 0
        # Detect both blind and standard Code Execs.
        if response.elapsed.total_seconds() > 1.5:
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.",
                                  url)
        pass


def t_i_code_exec_nfi(url):
    try:
        # Detects blind and standard Code Exec (Ping for 3 seconds)
        code_exec_payload = "| ping -c 3 127.0.0.1"
        response_injected = Utilities.no_form_input_content(url, code_exec_payload)
        if not response_injected:
            return 0
        # Detect both blind and standard Code Execs.
        for response_inj in response_injected:
            if response_inj.elapsed.total_seconds() > 1.5:
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e,
                                  "Something went wrong when testing for Code Execution Injection in non-form inputs.",
                                  url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if not (form_list or form_data_list):
            return
        for index, form in enumerate(form_list):
            if t_i_code_exec(url, form, form_data_list[index]):
                html_report.add_vulnerability('Code Execution Injection',
                                              'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')

        # Non-form input
        if t_i_code_exec_nfi(url):
            html_report.add_vulnerability('Code Execution Injection',
                                          'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'High')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.",
                                  url)
        pass