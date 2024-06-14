import requests
from bs4 import BeautifulSoup

from Classes.Utilities import Utilities
from Classes.ScanConfig import ScanConfig
from CustomImports import html_report


def extract_iframes(url):
    try:
        # Extract iFrames the same way forms are extracted
        response = ScanConfig.session.get(url, timeout=300)
        response.raise_for_status()
        parsed_html = BeautifulSoup(response.content, "html.parser")  # , from_encoding="iso-8859-1")
        return parsed_html.findAll("iframe")
    except requests.HTTPError as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when extracting iframes from links. A HTTP error occurred",
                                       url)
        pass
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when extracting iframes from links.", url)
        pass

def build_iframe_url(url, iframe, payload):
    try:  # Get the src value of the iframe to get the destination of the payload.
        if iframe['src'] in url:
            url = url.replace(iframe['src'], payload)
            return url
        return None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when building iframe URL.", url)
        pass

def t_i_iframe(url, iframe):
    try:
        # iFrame payload is another page.
        iframe_payload = 'https://www.google.com'
        iframe_url = build_iframe_url(url, iframe, iframe_payload)
        # If iFrame loads the new page it means it is vulnerable.
        if iframe_url:
            if iframe_payload in ScanConfig.session.get(iframe_url).text.lower():
                return iframe_url
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for iFrame Injection.", url)
        pass


def run(url):
    try:
        # Perform tests for each iFrame
        iframes = extract_iframes(url)
        if not iframes:
            return
        for iframe in iframes:
            iframe_url = t_i_iframe(url, iframe)
            if iframe_url:
                html_report.add_vulnerability('iFrame Injection',
                                              'iFrame Injection Vulnerability identified on URL: {}.'.format(
                                                  url), 'Low', reply="Iframe: {}".format(Utilities.escape_string_html(encoded_single=iframe)), comment="\nSuccessfully injected google.com Iframe over existing iFrame using Custom URL: {}.".format(iframe_url))
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for iFrame Injection.", url)
        pass