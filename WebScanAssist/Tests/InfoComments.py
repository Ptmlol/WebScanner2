import re

from Core.ScanConfig import ScanConfig
from Core.Utilities import Utilities
from Report import html_report


def run(url):
    try:
        # Get comments from the DOM on each URL.
        comm_dict = {}
        comments = re.findall('(?<=<!--)(.*)(?=-->)', str(ScanConfig.session.get(url).text))
        comm_dict.update({url: comments})
        # Print comments to report
        html_report.add_comments(comm_dict)
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for Javascript Execution.", url)
        pass