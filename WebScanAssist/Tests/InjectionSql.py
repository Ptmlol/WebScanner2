from Classes.Confidence import Confidence
from Classes.DataStorage import DataStorage
from Classes.ScanConfig import ScanConfig
from Classes.Utilities import Utilities
from CustomImports import html_report


def t_i_sql(url, form, form_data):
    try:
        # Initialize default Confidence for forms/URLs and SQL types list
        sql_test_confidence = Confidence()
        confidence = 0
        sql_type_list = set()
        time_based = False
        # Create average response time
        avg_response_time = Utilities.get_average(url, form)
        if not avg_response_time:
            return None, None, None, None
        # Find the injection points for the SQL Payload
        injection_keys = Utilities.extract_injection_fields_from_form(form_data)
        if not injection_keys:
            return None, None, None, None
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
            if payload_response_time > avg_response_time and payload_response_time > 2:
                # Vulnerable to Time based SQL type X, increase confidence
                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.4, impact=0.4)
                confidence += 1
                sql_type_list.add(DataStorage.inject_type(sql_payload))
                time_based = True

            if ("error" in response_injected.text.lower() and 'error' not in ScanConfig.session.get(url)) or (
                    'error' in ScanConfig.session.get(url) and sql_payload in response_injected.text.lower()):
                confidence += 1
                sql_test_confidence.add_confidence(past_occurrences=0.6, exploitability=0.5, impact=0.3)
                sql_type_list.add(DataStorage.inject_type(sql_payload))

            if confidence == 4:
                forms, form_data = Utilities.extract_from_html_string('form', response_injected.text)
                return sql_payload, sql_type_list, forms, sql_test_confidence.calculate_confidence()

        if confidence >= 1:
            return sql_payload, sql_type_list, form, sql_test_confidence.calculate_confidence()
        return None, None, None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
        pass


def t_i_sql_nfi(url):
    try:
        sql_test_confidence = Confidence()
        for sql_payload in DataStorage.payloads("SQL"):
            if not DataStorage.inject_type(sql_payload) == 'time_based_sql':
                continue
            response_injected = Utilities.no_form_input_content(url, sql_payload)
            if not response_injected:
                continue
            for response_inj in response_injected:
                if response_inj.elapsed.total_seconds() > 4.5:
                    sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.5, impact=0.7)
                    return sql_payload, sql_test_confidence.calculate_confidence()
        return None, None
    except Exception as e:
        Utilities.print_except_message('error', e,
                                       "Something went wrong when testing for SQL Injection with no form inputs.", url)
        pass


def t_i_ua_sql(url):
    try:
        sql_test_confidence = Confidence()
        # Get Initial ~ normal response time with no Payload
        response_time_wo = ScanConfig.session.get(url, timeout=30).elapsed.total_seconds()
        # Check only one time injection as it keeps the app loading for a long time if all time payloads are injected
        for sql_payload in DataStorage.payloads("SQL"):
            # Inject headers with payloads
            headers = Utilities.custom_user_agent(sql_payload)
            try:
                response = ScanConfig.session.get(url, timeout=30, headers=headers)
            except Exception:
                continue
            # Check response type (time or feedback)
            if not response:
                continue
            if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.5, impact=0.7)
                return sql_payload, headers, sql_test_confidence.calculate_confidence()
            if ("error" in response.text.lower() and 'error' not in ScanConfig.session.get(url)) or (
                    'error' in ScanConfig.session.get(url) and sql_payload in response.text.lower()):
                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.5, impact=0.7)
                return sql_payload, headers, sql_test_confidence.calculate_confidence()
        return None, None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for User-Agent SQL Injection.",
                                       url)
        pass


def t_i_xml_sql(url):
    try:
        sql_test_confidence = Confidence()
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
                continue
            if not response:
                continue
            # Check response type (time or feedback)
            if response.elapsed.total_seconds() > response_time_wo and response.elapsed.total_seconds() > 2:
                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.5, impact=0.7)
                return custom_payload, prepared_url, sql_test_confidence.calculate_confidence()
            if "error" in response.text.lower():
                sql_test_confidence.add_confidence(severity=0.8, past_occurrences=0.1, exploitability=0.5, impact=0.7)
                return custom_payload, prepared_url, sql_test_confidence.calculate_confidence()
        return None, None, None
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection in XML tags.",
                                       url)
        pass


def run(url):
    try:
        # Scan inputs in form
        form_list, form_data_list = Utilities.extract_forms_and_form_data(url)
        if form_list and form_data_list:
            for index, form in enumerate(form_list):
                # Test SQL Injections and print results
                payload, sql_type, response_form_list, confidence = t_i_sql(url, form, form_data_list[index])
                if payload:
                    payload, form_response_list = Utilities.escape_string_html(form_list, payload)
                    html_report.add_vulnerability('SQL Injection',
                                                  'SQL Injection vulnerability identified on form. URL: {}. Vulnerability Type: {}.'.format(
                                                      url, Utilities.pretty_sql(str(sql_type))), confidence, payload=payload,
                                                  reply="\nInjected Form (Original): {}.".format(form_response_list))

        # Bulk up User-Agent SQL Injection detection in the same function
        payload, headers, confidence = t_i_ua_sql(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            headers = Utilities.escape_string_html(encoded_single=headers)
            html_report.add_vulnerability('SQL Injection - User Agent',
                                          'SQL Injection vulnerability identified on URL: {} using custom User-Agent.'.format(
                                              url), confidence, payload=payload, comment="\nUsed Custom injected Headers: {}.".format(headers))

        # Scan inputs outside forms/with no actionable form
        payload, confidence = t_i_sql_nfi(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            html_report.add_vulnerability('SQL Injection',
                                          'Time based (Blind) SQL Injection vulnerability identified on URL: {}.'.format(
                                              url), confidence, payload=payload,
                                          comment="Used Non-Form input for injection. Non-form inputs are injectable fields outside of forms or URls (standalone input boxes, form options, etc.)")

        payload, xml_url, confidence = t_i_xml_sql(url)
        if payload:
            payload = Utilities.escape_string_html(encoded_single=payload)
            html_report.add_vulnerability('SQL Injection in XML tag',
                                          'SQL Injection in XML tag vulnerability identified on URL: {} using custom XML tags.'.format(
                                              url), confidence, payload=payload, comment="Used custom URL for XML SQL Injection URL: {}.".format(xml_url))
        return
    except Exception as e:
        Utilities.print_except_message('error', e, "Something went wrong when testing for SQL Injection.", url)
        pass
