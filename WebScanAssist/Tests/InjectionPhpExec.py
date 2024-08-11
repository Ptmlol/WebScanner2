import re

from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def t_i_php_exec(url, form=None, form_data=None):
    try:
        php_exec_payload = "%60ping%20-c%203%20127.0.0.1%60"
        if '=' in url:
            # Extract all injectable values, since it is applied for URL, look into URL only
            values_after_equal = re.findall('(?<==)[^&]+', url)
            if values_after_equal:
                for value in values_after_equal:
                    # Injection into URL each value
                    url = url.replace(value, php_exec_payload)

            # Get response time, detects both blind and standard PHP injections
            response = ScanConfig.session.get(url)
            if response.elapsed.total_seconds() > 1.5:
                return php_exec_payload, url
        elif form and form_data:
            injection_keys = Utilities.extract_injection_fields_from_form(form_data)
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data[injection_key] = php_exec_payload
            response_injected = Utilities.submit_form(url, form, form_data)
            if not response_injected:
                return None, None
            if php_exec_payload.lower() in response_injected.text.lower():
                forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                return php_exec_payload, forms
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                       url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                payload, form_response_list_or_url = t_i_php_exec(url, form, form_data_list[index])
                if payload:
                    if type(form_response_list_or_url) == list:
                        payload, form_response_list = Utilities.escape_string_html(form_response_list_or_url, payload)
                        html_report.add_vulnerability('PHP Code Execution Injection',
                                                      'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                          url), 'High', payload=payload, reply="\nInjection Form (Injected): {}.".format(form_response_list),
                                                      comment="Successfully used the above payload to PHP Code Injection.")

                    else:
                        new_url = form_response_list_or_url
                        payload = Utilities.escape_string_html(encoded_single=payload)
                        html_report.add_vulnerability('PHP Code Execution Injection',
                                                      'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                          url), 'High', payload=payload, reply="\nCustom URL: {}.".format(new_url), comment="Successfully injected PHP Code into URL.")
        else:
            payload, new_url = t_i_php_exec(url)
            if payload:
                payload = Utilities.escape_string_html()
                html_report.add_vulnerability('PHP Code Execution Injection',
                                              'PHP Code Execution Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High', payload=payload, reply="\nCustom URL: {}.".format(new_url), comment="Successfully injected PHP Code into URL.")
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for PHP Code Execution Injection.",
                                       url)
        pass
