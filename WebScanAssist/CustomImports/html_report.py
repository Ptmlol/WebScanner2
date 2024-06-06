import os
import sys

from jinja2 import Environment, FileSystemLoader
from CustomImports import generate_tree

vulnerabilities = []
tree_json = {}
external_links = set()
non_accessible_links = set()
try:
    def add_vulnerability(v_type, details, confidence='Critical'):
        temp_dict = {'type': v_type, 'details': details, 'severity': confidence}
        vulnerabilities.append(temp_dict)
        return


    def create_tree(tree_list):
        try:
            global tree_json
            tree_json = generate_tree.generate_tree(tree_list)
            return
        except Exception as e:
            print(e)


    def add_external_link(external):
        global external_links
        external_links.add(external)
        return


    def add_non_accessible_link(external):
        global non_accessible_links
        non_accessible_links.add(external)
        return


    def write_html_report():
        # Load the template
        env = Environment(loader=FileSystemLoader('CustomImports/templates'))
        template = env.get_template('report.html')

        # Render the template with the data
        output = template.render(vulnerabilities=vulnerabilities, tree_json=tree_json, external_links=external_links,
                                 non_accessible_links=non_accessible_links)

        # Save the output to a file
        with open('vulnerability_report.html', 'w') as f:
            f.write(output)

        f.close()
        return

except Exception as e:
    print(e)
