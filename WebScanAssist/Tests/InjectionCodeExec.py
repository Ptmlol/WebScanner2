import html

from Classes.Utilities import Utilities
from CustomImports import html_report

# TODO: Get mean time of payload so less FP

def t_i_code_exec(url, form, form_data):
    try:
        # Detects blind and standard Code Exec (Ping for 3 seconds)
        code_exec_payload = "|ping -c 3 127.0.0.1"  # 8.8.8.8|cat /etc/passwd
        # Get injection points and inject the payload.
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for injection_key in injection_keys:
            form_data[injection_key] = html.unescape(code_exec_payload)
        response = Utilities.submit_form(url, form, form_data)
        if not response:
            return None, None
        # Detect both blind and standard Code Execs.
        if response.elapsed.total_seconds() > 1.5:
            forms, form_data = Utilities.extract_from_html_string('form', response.text)
            return code_exec_payload, forms
        return False, False
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
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                payload, form_response_list = t_i_code_exec(url, form, form_data_list[index])

                if payload:
                    payload, form_response_list = Utilities.escape_string_html(form_list, payload)
                    html_report.add_vulnerability('Code Execution Injection',
                                                  'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High', payload=payload, reply="\nInjected Form (Original): {}.".format(form_response_list))

        # Non-form input
        if t_i_code_exec_nfi(url):
            html_report.add_vulnerability('Code Execution Injection',
                                          'Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'High', comment="Used Non-Form input for injection. Non-form inputs are injectable fields outside of forms or URls (standalone input boxes, form options, etc.)")
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Code Execution Injection.",
                                  url)
        pass