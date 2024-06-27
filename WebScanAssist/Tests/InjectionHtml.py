from Classes.Confidence import Confidence
from Classes.DataStorage import DataStorage
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_html(url, form, form_data):
    try:
        sql_test_confidence = Confidence()
        confidence = 0
        # Select injection points from form details
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for html_payload in DataStorage.payloads("HTML"):
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data[injection_key] = html_payload
            response_injected = Utilities.submit_form(url, form, form_data)
            if not response_injected:
                continue
            # Check for html_payload (tags included) in response, success execution if available.
            if html_payload.lower() in response_injected.text.lower():
                confidence += 1
                sql_test_confidence.add_confidence(severity=0.7, past_occurrences=0.1, exploitability=0.4, impact=0.3)
            if confidence == 4:
                forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                return html_payload, forms, sql_test_confidence.calculate_confidence()
        if confidence > 1:
            forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
            return html_payload, forms, sql_test_confidence.calculate_confidence()
        return False, None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
        pass


def t_i_html_nfi(url):
    try:
        confidence = 0
        sql_test_confidence = Confidence()
        for html_payload in DataStorage.payloads("HTML"):
            # Inject each payload into each injection point
            response_injected = Utilities.no_form_input_content(url, html_payload)
            if not response_injected:
                continue
            # Check for html_payload (tags included) in response, success execution if available.
            for response_inj in response_injected:
                if html_payload in response_inj.text:
                    confidence += 1
                    sql_test_confidence.add_confidence(severity=0.7, past_occurrences=0.1, exploitability=0.4, impact=0.3)
                if confidence == 4:
                    return sql_test_confidence.calculate_confidence()
            if confidence > 1:
                return sql_test_confidence.calculate_confidence()
        return False
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when testing HTML Injection with non-form inputs.", url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                payload, form_response_list, confidence = t_i_html(url, form, form_data_list[index])
                # Print if Vulnerabilities are found.
                if payload:
                    payload, form_response_list = Utilities.escape_string_html(form_list, payload)
                    html_report.add_vulnerability('HTML Injection',
                                                  'HTML Injection Vulnerability identified on URL: {}.'.format(
                                                      url), confidence, payload=payload, reply="\nInjected Form (Original): {}.".format(form_response_list))

        # Test on non-form inputs
        confidence = t_i_html_nfi(url)
        if confidence:
            html_report.add_vulnerability('HTML Injection',
                                          'HTML Injection Vulnerability identified on URL: {}.'.format(
                                              url), confidence,
                                          comment="Used Non-Form input for injection. Non-form inputs are injectable fields outside of forms or URls (standalone input boxes, form options, etc.)")
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing HTML Injection.", url)
        pass
