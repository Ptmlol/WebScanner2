import os
import sys

from jinja2 import Environment, FileSystemLoader


vulnerabilities = []

try:
    def add_vulnerability(v_type, details, confidence='Critical'):
        temp_dict = {'type': v_type, 'details': details, 'severity': confidence}
        vulnerabilities.append(temp_dict)


    def write_html_report():
        # Load the template
        env = Environment(loader=FileSystemLoader('CustomImports/templates'))
        template = env.get_template('report.html')

        # Render the template with the data
        output = template.render(vulnerabilities=vulnerabilities)

        # Save the output to a file
        with open('vulnerability_report.html', 'w') as f:
            f.write(output)

        f.close()
except Exception as e:
    print(e)