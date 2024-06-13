from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Add more payloads

def t_i_js(url):
    try:
        js_payload = '/?javascript:alert(testedforjavascriptcodeexecutionrn3284)'
        if url[-1] != '/':
            new_url = url + js_payload
            return js_payload in str(ScanConfig.session.get(new_url).text).lower()
        else:
            new_url = url + js_payload[1:]
            return js_payload[1:] in str(ScanConfig.session.get(new_url).text).lower()
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
        pass


def run(url):
    try:
        if t_i_js(url):
            html_report.add_vulnerability('Javascript Code Injection',
                                          'Javascript Code Injection vulnerability identified on URL: {}'.format(url),
                                          'High')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
        pass