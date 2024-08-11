from Core.Utilities import Utilities
from Report import html_report


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
            return None, None
        if 'active internet connections' in str(response.text).lower():
            forms, form_data = Utilities.extract_from_html_string('form', response.text)
            return ssi_payload, forms
        return None, None
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
            return None
        for response_inj in response_injected:
            if 'active internet connections' in str(response_inj.text).lower():
                return ssi_payload
        return None
    except Exception as e:
        Utilities.print_except_message('error', e,
                                  "Something went wrong when testing for SSI (Server-Side Includes) in non-form inputs.",
                                  url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                payload, response_form_list = t_i_ssi(url, form, form_data_list[index])
                if payload:
                    payload, response_form_list = Utilities.escape_string_html(form_list, payload)
                    html_report.add_vulnerability('SSI Code Execution Injection',
                                                  'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High', payload=payload, reply="\nInjected Form (Original): {}.".format(response_form_list))
        # Scan non-form inputs
        payload = t_i_ssi_nfi(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            html_report.add_vulnerability('SSI Code Execution Injection',
                                          'SSI Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'High', payload=payload, comment="Used Non-Form input for injection. Non-form inputs are injectable fields outside of forms or URls (standalone input boxes, form options, etc.)")
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SSI (Server-Side Includes).",
                                  url)
        pass