# Cross Site Scripting
import html

from Classes.DataStorage import DataStorage
from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_xss(url, form, form_data):
    try:
        confidence = 0
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for xss_payload in DataStorage.payloads("XSS"):
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data[injection_key] = xss_payload
            response_injected = Utilities.submit_form(url, form, form_data)
            if not response_injected:
                continue
            if (str(xss_payload).lower() in str(response_injected.text).lower()) or (
                    str(xss_payload).lower() in str(html.unescape(response_injected.text.lower()))):
                confidence += 1
            if confidence > 1:
                forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                return xss_payload, forms
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
        pass


def t_i_xss_nfi(url):
    try:
        for xss_payload in DataStorage.payloads("XSS"):
            response_injected = Utilities.no_form_input_content(url, xss_payload)
            if not response_injected:
                return None
            for response_inj in response_injected:
                if xss_payload.lower() in response_inj.text.lower():
                    return xss_payload
        return None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
        pass


def t_ua_xss(url):
    try:
        for payload in DataStorage.payloads("XSS"):
            # Inject headers with payloads
            headers = Utilities.custom_user_agent(payload)
            try:
                response = ScanConfig.session.get(url, timeout=10, headers=headers)
            except Exception:
                continue
            # Check response type (time or feedback)
            if payload.lower() in response.text.lower():
                return payload, headers
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for User-Agent XSS Injections.",
                                       url)
        pass


def run(url):
    try:
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                payload, response_form_list = t_i_xss(url, form, form_data_list[index])
                if payload:
                    payload, form_response_list = Utilities.escape_string_html(form_list, payload)
                    html_report.add_vulnerability('XSS Injection',
                                                  'XSS Injection vulnerability identified on form. URL: {}'.format(
                                                      url), 'High', payload=payload, reply="\nInjected Form (Original): {}.".format(form_response_list))

        payload = t_i_xss_nfi(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            html_report.add_vulnerability('XSS Injection',
                                          'XSS Injection vulnerability identified on URL: {}'.format(
                                              url), 'High', payload=payload,
                                          comment="Used Non-Form input for injection. Non-form inputs are injectable fields outside of forms or URls (standalone input boxes, form options, etc.)")

        payload, headers = t_ua_xss(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            headers = Utilities.escape_string_html(encoded_single=headers)
            html_report.add_vulnerability('User Agent XSS Injection',
                                          'XSS Injection vulnerability identified using custom User-Agent. URL: {}'.format(
                                              url), 'Critical', payload=payload, comment="\nUsed Custom injected Headers: {}.".format(headers))
        return 0
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong testing XSS in form.", url)
        pass
