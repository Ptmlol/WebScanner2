from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


# TODO: Might need to add other payloads

def run(url):
    try:
        payload = 'file:///etc/passwd'
        # Get the custom values of the page and try to inject them if possible.
        custom_url, custom_payload = Utilities.prepare_xml_inj(url, payload)
        if custom_url and custom_payload:
            response = ScanConfig.session.post(custom_url, data=custom_payload, headers={'Content-Type': 'application/xml'})
            if 'root' in response.text.lower():
                html_report.add_vulnerability('XXE Injection',
                                              'XXE Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'Critical')
        # If specific injection cannot be performed, try generic approach.
        elif custom_url is None and custom_payload:
            if 'error' in str(
                    ScanConfig.session.post(url, data=payload, headers={'Content-Type': 'application/xml'}).content):
                html_report.add_vulnerability('XXE Injection',
                                              'XXE Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'High')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Generic XML Injection.", url)
        pass