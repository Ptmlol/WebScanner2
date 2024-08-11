from datetime import datetime

from jinja2 import Environment, FileSystemLoader
from Report import generate_tree

vulnerabilities = []
tree_json = {}
external_links = set()
non_accessible_links = set()
comments_dict = {}
hidden_paths = []
cve_dict = []

try:
    def add_vulnerability(v_type, details, confidence='Critical', payload=None, reply=None, comment=None):
        vulnerabilities.append({'type': v_type, 'details': details, 'severity': confidence, 'dropdown_details': {'payload': payload, 'reply': reply, 'comment': comment}})
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

    def add_comments(external):
        global comments_dict
        comments_dict.update(external)
        return

    def add_hidden_path(path, status_code):
        global hidden_paths
        hidden_paths.append({'path': path, 'status_code': status_code})
        return

    def add_cve(app_name_supp, app_name_prod, cve_id, cve_description, cve_url,cve_score, cve_severity):
        global cve_dict
        cve_dict.append({
            'app_name_supp': app_name_supp,
            'app_name_prod': app_name_prod,
            'cve_id': cve_id,
            'cve_description': cve_description,
            'cve_url': cve_url,
            'cve_score': cve_score,
            'cve_severity': cve_severity
        })
        return

    def write_html_report():
        try:
            # Load the template
            env = Environment(loader=FileSystemLoader('Report/templates'))
            template = env.get_template('report.html')
            # Render the template with the data
            output = template.render(vulnerabilities=vulnerabilities, tree_json=tree_json, external_links=external_links, non_accessible_links=non_accessible_links,
                                     comments_dict=comments_dict, hidden_paths=hidden_paths, cve_dict=cve_dict, timestamp=datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S"))
            # Save the output to a file
            # with open('Vulnerability_Report_' + datetime.now().strftime('%Y-%m-%d_%H-%M') + '.html', 'w', encoding='utf-8') as f:
            with open('report.html', 'w', encoding='utf-8') as f:  # temp until on prod.
                f.write(output)

            f.close()
            return
        except Exception as e:
            print(e)

except Exception as e:
    print(e)
