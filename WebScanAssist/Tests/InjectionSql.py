from Classes.DataStorage import DataStorage
from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_sql(url, form, form_data):
    try:
        # Initialize default Confidence for forms/URLs and SQL types list
        confidence = 0
        sql_type_list = set()
        time_based = False
        # Get Initial ~ normal response time with no Payload
        response_wo_1 = Utilities.submit_form(url, form, "")
        if not response_wo_1:
            return 0, 0, 0
        response_time_wo_1 = response_wo_1.elapsed.total_seconds()
        response_time_wo_2 = Utilities.submit_form(url, form, "").elapsed.total_seconds()
        response_time_wo_3 = Utilities.submit_form(url, form, "").elapsed.total_seconds()

        if not response_time_wo_1 or not response_time_wo_2 or not response_time_wo_3:
            return 0, 0, 0

        # Create average response time
        avg_response_time = (response_time_wo_1 + response_time_wo_2 + response_time_wo_3) / 3

        # Find the injection points for the SQL Payload
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        for sql_payload in DataStorage.payloads("SQL"):
            # Populate injection keys with payloads.
            for injection_key in injection_keys:
                form_data[injection_key] = sql_payload
            # Check time based only once, heavy load on time of execution.
            if (time_based and confidence > 2) and DataStorage.inject_type(sql_payload) == 'time_based_sql':
                continue
            response_injected = Utilities.submit_form(url, form, form_data)
            if not response_injected:
                continue
            payload_response_time = response_injected.elapsed.total_seconds()
            # Get time of response and check.
            if payload_response_time > avg_response_time and payload_response_time > 2:  # and (time_based is False or confidence < 2):
                # Vulnerable to Time based SQL type X, increase confidence
                confidence += 1
                sql_type_list.add(DataStorage.inject_type(sql_payload))
                time_based = True

            if "error" in response_injected.text.lower():  # TODO: Fix generic FP rate for 'error' alone in response.
                confidence += 1
                sql_type_list.add(DataStorage.inject_type(sql_payload))

            if confidence > 1:
                return True, sql_type_list, confidence
            elif sql_payload == DataStorage.payloads("SQL")[
                -1] and confidence > 0:
                return True, sql_type_list, confidence
        return False, [], 0
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
        pass


def t_i_sql_nfi(url):
    try:
        for sql_payload in DataStorage.payloads("SQL"):
            if not DataStorage.inject_type(sql_payload) == 'time_based_sql':
                continue
            response_injected = Utilities.no_form_input_content(url, sql_payload)
            if not response_injected:
                continue
            for response_inj in response_injected:
                if response_inj.elapsed.total_seconds() > 4.5:
                    return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e,
                                  "Something went wrong when testing for SQL Injection with no form inputs.", url)
        pass


def t_i_ua_sql(url):
    try:
        # Get Initial ~ normal response time with no Payload
        response_time_wo = ScanConfig.session.get(url, timeout=300).elapsed.total_seconds()
        # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
        for sql_payload in DataStorage.payloads("SQL"):
            # Inject headers with payloads
            headers = Utilities.custom_user_agent(sql_payload)
            try:
                response = ScanConfig.session.get(url, timeout=300, headers=headers)
            except Exception:
                continue
            # Check response type (time or feedback)
            if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                return True
            if "error" in response.text.lower(): # TODO: Other methods of detection
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for User-Agent SQL Injection.",
                                  url)
        pass


def t_i_xml_sql(url):
    try:
        # Get Initial ~ normal response time with no Payload
        response_time_wo = ScanConfig.session.get(url, timeout=300).elapsed.total_seconds()
        # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
        for sql_payload in DataStorage.payloads("SQL"):
            # Inject XML with custom payloads
            prepared_url, custom_payload = Utilities.prepare_xml_inj(url, sql_payload)
            if prepared_url and custom_payload:
                try:
                    response = ScanConfig.session.post(prepared_url, data=custom_payload,
                                                 headers={'Content-Type': 'application/xml'})
                except Exception:
                    continue
            else:
                break
            # Check response type (time or feedback)
            if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                return True
            if "error" in response.text.lower():
                return True
        return False
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection in XML tags.",
                                  url)
        pass


def run(url):
    try:
        # Scan inputs in form
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        for index, form in enumerate(form_list):
            # Test SQL Injections and print results
            sql_vuln, sql_type, sql_conf = t_i_sql(url, form, form_data_list[index])
            if sql_vuln:
                if 0 < sql_conf <= 3:
                    html_report.add_vulnerability('SQL Injection',
                                                  'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}.'.format(
                                                      url, Utilities.pretty_sql(str(sql_type))), 'Medium')
                else:
                    html_report.add_vulnerability('SQL Injection',
                                                  'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}'.format(
                                                      url, Utilities.pretty_sql(str(sql_type))), 'Critical')
        # Bulk up User-Agent SQL Injection detection in the same function
        if t_i_ua_sql(url):
            html_report.add_vulnerability('SQL Injection - User Agent',
                                          'SQL Injection vulnerability identified on URL: {} using custom User-Agent.'.format(
                                              url), 'Critical')

        # Scan inputs outside forms/with no actionable form
        if t_i_sql_nfi(url):
            html_report.add_vulnerability('SQL Injection',
                                          'Time based (Blind) SQL Injection vulnerability identified on URL: {}.'.format(
                                              url), 'Medium')

        if t_i_xml_sql(url):
            html_report.add_vulnerability('SQL Injection in XML tag',
                                          'SQL Injection in XML tag vulnerability identified on URL: {} using custom XML tags.'.format(
                                              url), 'Critical')
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
        pass