import re

from werkzeug.exceptions import InternalServerError

from Core.Confidence import Confidence
from Core.DataStorage import DataStorage
from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def t_i_lfi(url):
    try:
        sql_test_confidence = Confidence()
        confidence = 0
        new_url = None
        forms = None
        # for html_payload in self.DataStorage.payloads("HTML"):
        # https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
        try:
            for lfi_script in DataStorage.payloads("LFI"):
                lfi_script = lfi_script.replace('\n', '')
                if '=' in url:
                    try:
                        new_url = re.sub(r'=(?!.*=).*$', f'={lfi_script}', url)
                        response = ScanConfig.session.get(new_url)
                        if response:
                            if "root:" in response.text.lower():
                                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.7, impact=0.7)
                                confidence += 1
                    except InternalServerError:
                        pass
                form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
                if not (form_list or form_data_list):
                    continue
                for index, form in enumerate(form_list):
                    injection_keys = Utilities.extract_injection_fields_from_form(form_data_list[index])
                    if not injection_keys:
                        continue
                    # Inject each payload into each injection point
                    for injection_key in injection_keys:
                        form_data_list[index][injection_key] = lfi_script
                    response_injected = Utilities.submit_form(url, form, form_data_list[index])
                    if not response_injected:
                        continue
                    if "root:" in response_injected.text.lower():
                        forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                        confidence += 1
                        sql_test_confidence.add_confidence(severity=0.9, past_occurrences=0.1, exploitability=0.2, impact=0.7)
                if confidence == 4:
                    if new_url:
                        return lfi_script, new_url, sql_test_confidence.calculate_confidence()
                    if forms:
                        return lfi_script, forms, sql_test_confidence.calculate_confidence()
        except UnicodeDecodeError:
            pass
        if confidence >= 1:
            if new_url:
                return lfi_script, new_url, sql_test_confidence.calculate_confidence()
            if forms:
                return lfi_script, forms, sql_test_confidence.calculate_confidence()
        return None, None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
        pass


def run(url):
    try:
        lfi_script, form_response_list_or_url, confidence = t_i_lfi(url)
        if lfi_script:
            if type(form_response_list_or_url) == list:
                lfi_script, form_response_list = Utilities.escape_string_html(form_response_list_or_url, lfi_script)

                html_report.add_vulnerability('Local File Inclusion (LFI)',
                                              'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(url),
                                              confidence, payload=lfi_script, reply="\nInjection Form (Injected): {}.".format(form_response_list),
                                              comment="Successfully used the above payload to perform Local File Inclusion (LFI).")
            else:
                new_url = form_response_list_or_url
                html_report.add_vulnerability('Local File Inclusion (LFI)',
                                              'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(
                                                  url),
                                              confidence, payload=lfi_script,
                                              reply="\nURL: {}.".format(new_url),
                                              comment="Successfully used the above payload to perform Local File Inclusion (LFI) in the URL.")

        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI) (RUN).", url)
        pass
