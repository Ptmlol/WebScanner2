from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def t_i_js(url):
    try:
        js_payload = '/?javascript:alert(testedforjavascriptcodeexecutionrn3284)'
        if url[-1] != '/':
            new_url = url + js_payload
            response = ScanConfig.session.get(new_url)
            if not response.text:
                return None, None
            if js_payload in str(response.text).lower():
                return js_payload, new_url
        else:
            new_url = url + js_payload[1:]
            response = ScanConfig.session.get(new_url)
            if not response.text:
                return None, None
            if js_payload[1:] in str(response.text).lower():
                return js_payload[1:], new_url
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
        pass


def run(url):
    try:
        js_payload, new_url = t_i_js(url)
        if js_payload:
            html_report.add_vulnerability('Javascript Code Injection',
                                          'Javascript Code Injection vulnerability identified on URL: {}'.format(url),
                                          'High', reply="Successfully injected Javascript Code: {} into Custom URL: {}".format(js_payload, new_url),
                                          comment="If the application is not designed to accept JS code on this URL, this is a vulnerability.")
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
        pass
