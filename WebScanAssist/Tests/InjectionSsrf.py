from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Add more payloads and make work with URLs = as in LFI

def t_i_ssrf(url):
    try:
        if '=' in url:
            ssrf_payload = "=https://www.google.com/"
            url = url.replace('=', ssrf_payload)
            response = ScanConfig.session.get(url)
            if ssrf_payload in url and response.status_code == 200:
                return ssrf_payload, url
            ssrf_payload = '=file:///etc/passwd'
            url = url.replace('=', ssrf_payload)
            if ssrf_payload in url and "root:" in response.text.lower():
                return ssrf_payload, url
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when testing for Server Side Request-Forgery (SSRF).", url)
        pass


def run(url):
    try:
        payload, new_url = t_i_ssrf(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            html_report.add_vulnerability('Server Side Request Forgery',
                                          'Server Side Request Forgery (SSRF) vulnerability identified on URL: {}'.format(
                                              url), 'Low', payload=payload, reply="Successfully injected payload into URL: {}".format(url))
        return
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when testing for Server Side Request-Forgery (SSRF).", url)
        pass
