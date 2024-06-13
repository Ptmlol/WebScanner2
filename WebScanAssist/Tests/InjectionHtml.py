from Classes.DataStorage import DataStorage
from Classes.Utilities import Utilities
from CustomImports import html_report

# TODO: Check why so slow
# TODO: Think of a method for adding confidence dynamically

def t_i_html(url, form, form_data):
    try:
        # Select injection points from form details
        confidence = 0
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for html_payload in DataStorage.payloads("HTML"):
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data[injection_key] = html_payload
            response_injected = Utilities.submit_form(url, form, form_data)
            if not response_injected:
                return 0, 0
            # Check for html_payload (tags included) in response, success execution if available.
            if html_payload in response_injected.text:
                confidence += 1
            if confidence > 0:
                return True, confidence
            elif html_payload == DataStorage.payloads("HTML")[
                -1] and confidence > 0:
                return True, confidence
        return False, 0
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
        pass


def t_i_html_nfi(url):
    try:
        for html_payload in DataStorage.payloads("HTML"):
            # Inject each payload into each injection point
            response_injected = Utilities.no_form_input_content(url, html_payload)
            if not response_injected:
                return 0
            # Check for html_payload (tags included) in response, success execution if available.
            for response_inj in response_injected:
                if html_payload in response_inj.text:
                    return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e,
                                  "Something went wrong when testing HTML Injection with non-form inputs.", url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        for index, form in enumerate(form_list):
            html_vuln, confidence = t_i_html(url, form, form_data_list[index])
            # Print if Vulnerabilities are found.
            if html_vuln:
                if 0 < confidence <= 3:
                    html_report.add_vulnerability('HTML Injection',
                                                  'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'Low')
                else:
                    html_report.add_vulnerability('HTML Injection',
                                                  'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                      url), 'High')
        # Test on non-form inputs
        if t_i_html_nfi(url):
            html_report.add_vulnerability('HTML Injection',
                                          'HTML Injection Vulnerability identified on URL: {}.'.format(
                                              url), 'Medium')
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
        pass