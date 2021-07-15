"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_OT_Asset_Search' block
    Format_OT_Asset_Search(container=container)

    return

def Check_for_OT_Asset_Info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_for_OT_Asset_Info() called')

    # collect data for 'Check_for_OT_Asset_Info' call
    formatted_data_1 = phantom.get_format_data(name='Format_OT_Asset_Search')

    parameters = []
    
    # build parameters list for 'Check_for_OT_Asset_Info' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "asset,asset_id,asset_model,asset_status,asset_system,asset_tag,asset_type,asset_vendor,asset_version,bunit,category,city,classification,country,description,dns,exposure,ip,is_expected,key,lat,location,long,mac,nt_host,owner,pci_domain,priority,requires_av,should_timesync,should_update,site_id,vlan,zone",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=Check_for_OT_Asset_Info_callback, name="Check_for_OT_Asset_Info")

    return

def Check_for_OT_Asset_Info_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Check_for_OT_Asset_Info_callback() called')
    
    decision_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_Authentication_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_Network_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_Endpoint_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="OT Sec : MITRE ICS T0818 : Engineering Workstation Compromise")
    Pin_Case_Escalated(container=container)

    return

def join_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_promote_to_case_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Prompt_Escalate_Case', 'Check_for_OT_Asset_Info']):
        
        # call connected block "promote_to_case_1"
        promote_to_case_1(container=container, handle=handle)
    
    return

def Format_OT_Asset_Search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_OT_Asset_Search() called')
    
    template = """| `reverse_asset_lookup(\"{0}\")`"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_OT_Asset_Search")

    Check_for_OT_Asset_Info(container=container)

    return

def Format_Priv_Auth_Search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Priv_Auth_Search() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.user_category) as user_category,dc(Authentication.dest) as dc(dest) from datamodel=Authentication.Authentication where Authentication.user_category=default  Authentication.dest=\"{0}\"  earliest=-1d latest=now by  Authentication.dest Authentication.user
| `drop_dm_object_name(\"Authentication\")` 
| sort 100 - _time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Priv_Auth_Search")

    Check_Priv_Auth_Activity(container=container)

    return

def Check_Priv_Auth_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Priv_Auth_Activity() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Priv_Auth_Activity' call
    formatted_data_1 = phantom.get_format_data(name='Format_Priv_Auth_Search')

    parameters = []
    
    # build parameters list for 'Check_Priv_Auth_Activity' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "_time,dest,user,user_category,count",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_3, name="Check_Priv_Auth_Activity")

    return

def Format_Login_Failures_Successes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Login_Failures_Successes() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.action) as action,values(Authentication.app) as app,count from datamodel=Authentication.Authentication where * (Authentication.action=\"failure\") Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.src,Authentication.src_user,Authentication.dest,Authentication.user 
| `drop_dm_object_name(\"Authentication\")` 
| eval src_user=if(src_user==\"unknown\",null(),src_user) 
| fields _time,src,dest,src_user,user,action,app,count
| sort - count"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Login_Failures_Successes")

    Check_Login_Failures_Successes(container=container)

    return

def Format_Excessive_Login_Fails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Excessive_Login_Fails() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.action) as action,values(Authentication.app) as app,count from datamodel=Authentication.Authentication where * (Authentication.action=\"failure\") Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.src,Authentication.src_user,Authentication.dest,Authentication.user 
| `drop_dm_object_name(\"Authentication\")` 
| eval src_user=if(src_user==\"unknown\",null(),src_user) 
| fields _time,src,dest,src_user,user,action,app,count
| sort - count
| search count>2"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Excessive_Login_Fails")

    Check_Excessive_Login_Fails(container=container)

    return

def Format_Unique_Login_Attempts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Unique_Login_Attempts() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.action) as action,values(Authentication.app) as app,count from datamodel=Authentication.Authentication where * (Authentication.action=\"failure\") Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.src,Authentication.dest 
| `drop_dm_object_name(\"Authentication\")` 
| eval src_user=if(src_user==\"unknown\",null(),src_user) 
| fields _time,src,dest,action,app,count
| sort - count
| search count<2"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Unique_Login_Attempts")

    Check_Unique_Login_Attempts(container=container)

    return

def Check_Login_Failures_Successes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Login_Failures_Successes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Login_Failures_Successes' call
    formatted_data_1 = phantom.get_format_data(name='Format_Login_Failures_Successes')

    parameters = []
    
    # build parameters list for 'Check_Login_Failures_Successes' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "_time,src,dest,src_user,user,action,app,count,status_cnt",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_4, name="Check_Login_Failures_Successes")

    return

def Check_Excessive_Login_Fails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Excessive_Login_Fails() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Excessive_Login_Fails' call
    formatted_data_1 = phantom.get_format_data(name='Format_Excessive_Login_Fails')

    parameters = []
    
    # build parameters list for 'Check_Excessive_Login_Fails' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_5, name="Check_Excessive_Login_Fails")

    return

def Check_Unique_Login_Attempts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Unique_Login_Attempts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Unique_Login_Attempts' call
    formatted_data_1 = phantom.get_format_data(name='Format_Unique_Login_Attempts')

    parameters = []
    
    # build parameters list for 'Check_Unique_Login_Attempts' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_6, name="Check_Unique_Login_Attempts")

    return

def Filter_Authentication_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Authentication_Activity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", ""],
        ],
        name="Filter_Authentication_Activity:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Priv_Auth_Search(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Login_Failures_Successes(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Excessive_Login_Fails(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Unique_Login_Attempts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Logins_Unusual_Place(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Multiple_IP_Short_Time(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Irregular_Access_Hr(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Priv_Auth_Activity:action_result.summary.total_events", ">", 0],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Priv_Auth_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Priv_Auth_Activity:action_result.summary.total_events", "==", 0],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Pin_Check_Priv_Auth_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Priv_Auth_Activity() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Priv_Auth_Activity')

    phantom.pin(container=container, data=formatted_data_1, message="Priv Auth Activities Detected", name="Priv Auth Activities Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Login_Failures_Successes:action_result.summary.total_events", ">", 0],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Login_Failures_Success(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Login_Failures_Successes:action_result.summary.total_events", "==", 0],
        ],
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Pin_Check_Login_Failures_Successes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Login_Failures_Successes() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Login_Failures_Success')

    phantom.pin(container=container, data=formatted_data_1, message="Login Failures Successes Detected", name=None)
    join_Prompt_Escalate_Case(container=container)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Excessive_Login_Fails:action_result.summary.total_events", ">", 0],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Excessive_Login_Fails(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_OT_Asset_Info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_OT_Asset_Info() called')
    
    template = """{0} | Type - {2} | Site - {1} | Vendor - {3} | Model - {4} | Zone - {5}"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.nt_host",
        "Check_for_OT_Asset_Info:action_result.data.*.site_id",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_type",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_vendor",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_model",
        "Check_for_OT_Asset_Info:action_result.data.*.zone",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_OT_Asset_Info")

    Pin_OT_Asset_Info(container=container)

    return

def Pin_OT_Asset_Info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_OT_Asset_Info() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_OT_Asset_Info')

    phantom.pin(container=container, data=formatted_data_1, message="OT Asset Information", pin_type="card", pin_style="red", name="OT Asset Information")
    Format_Pin_Zone_Level(container=container)

    return

def Pin_Check_Excessive_Login_Fails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Excessive_Login_Fails() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Excessive_Login_Fails')

    phantom.pin(container=container, data=formatted_data_1, message="Excessive Login Fails Detected", name="Excessive Login Fails Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Unique_Login_Attempts:action_result.summary.total_events", ">", 0],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Unique_Login_Attempts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Pin_Check_Unique_Login_Attempts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Unique_Login_Attempts() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Unique_Login_Attempts')

    phantom.pin(container=container, data=formatted_data_1, message="Unique Login Attempts Detected", name="Unique Login Attempts Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Format_Pin_Check_Priv_Auth_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Priv_Auth_Activity() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Priv_Auth_Activity:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Priv_Auth_Activity")

    Pin_Check_Priv_Auth_Activity(container=container)

    return

def Format_Pin_Login_Failures_Success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Login_Failures_Success() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Login_Failures_Successes:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Login_Failures_Success")

    Pin_Check_Login_Failures_Successes(container=container)

    return

def Format_Pin_Check_Excessive_Login_Fails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Excessive_Login_Fails() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Excessive_Login_Fails:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Excessive_Login_Fails")

    Pin_Check_Excessive_Login_Fails(container=container)

    return

def Format_Pin_Check_Unique_Login_Attempts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Unique_Login_Attempts() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Unique_Login_Attempts:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Unique_Login_Attempts")

    Pin_Check_Unique_Login_Attempts(container=container)

    return

def Prompt_Escalate_Case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_Escalate_Case() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """If you have verified the found IOCs,
Do you want to escalate as a case?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="Prompt_Escalate_Case", response_types=response_types, callback=decision_9)

    return

def join_Prompt_Escalate_Case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Prompt_Escalate_Case() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Check_Priv_Auth_Activity', 'Check_Login_Failures_Successes', 'Check_Excessive_Login_Fails', 'Check_Unique_Login_Attempts', 'Check_Logins_Unusual_Place', 'Check_Multiple_IP_Short_Time', 'Check_Irregular_Access_Hr', 'Check_Network_Intrusions', 'Check_Endpoint_Activity', 'Check_Outbound_Traffic', 'Check_ES_Notables']):
        
        # call connected block "Prompt_Escalate_Case"
        Prompt_Escalate_Case(container=container, handle=handle)
    
    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_Escalate_Case:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_promote_to_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Pin_Case_Escalated(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Case_Escalated() called')

    phantom.pin(container=container, data="", message="Analyst escalated to a case", pin_type="card", pin_style="blue", name="Analyst escalated to a case")
    import_container_1(container=container)

    return

def Format_Logins_Unusual_Place(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Logins_Unusual_Place() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.user_category) as user_category,count(_time) as count from datamodel=Authentication.Authentication where Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(\"Authentication\")` 
| sort 100 - _time
| table _time,src, dest,user,user_category,count
| iplocation allfields=true src
| search Country=* NOT Country=\"United States\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Logins_Unusual_Place")

    Check_Logins_Unusual_Place(container=container)

    return

def Format_Multiple_IP_Short_Time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Multiple_IP_Short_Time() called')
    
    template = """| tstats `summariesonly` max(_time) as _time, values(Authentication.src) as src, dc(Authentication.src) as src_dc, values(Authentication.user_category) as user_category,count(_time) as count from datamodel=Authentication.Authentication where Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.dest
| `drop_dm_object_name(\"Authentication\")` 
| sort 100 - _time
| table _time,dest,src,src_dc,count
| search src_dc>5"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Multiple_IP_Short_Time")

    Check_Multiple_IP_Short_Time(container=container)

    return

def Format_Irregular_Access_Hr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Irregular_Access_Hr() called')
    
    template = """| tstats `summariesonly` max(_time) as _time, values(Authentication.src) as src, dc(Authentication.src) as src_dc, values(Authentication.user_category) as user_category,count(_time) as count from datamodel=Authentication.Authentication where Authentication.dest=\"{0}\" earliest=-1d latest=now by Authentication.dest
| `drop_dm_object_name(\"Authentication\")` 
| sort 100 - _time
| table _time,dest,src,src_dc,count
| eval HTIME=_time
| convert ctime(HTIME)
| rex field=HTIME \"\\S+\\s+(?<date_hr>\\d+):\"
| search date_hr<10 date_hr>16"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Irregular_Access_Hr")

    Check_Irregular_Access_Hr(container=container)

    return

def Filter_Network_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Network_Activity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", ""],
        ],
        name="Filter_Network_Activity:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Network_Intrusions(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Outbound_Traffic(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Check_Logins_Unusual_Place(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Logins_Unusual_Place() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Logins_Unusual_Place' call
    formatted_data_1 = phantom.get_format_data(name='Format_Logins_Unusual_Place')

    parameters = []
    
    # build parameters list for 'Check_Logins_Unusual_Place' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_8, name="Check_Logins_Unusual_Place")

    return

def Check_Multiple_IP_Short_Time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Multiple_IP_Short_Time() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Multiple_IP_Short_Time' call
    formatted_data_1 = phantom.get_format_data(name='Format_Multiple_IP_Short_Time')

    parameters = []
    
    # build parameters list for 'Check_Multiple_IP_Short_Time' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_9, name="Check_Multiple_IP_Short_Time")

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Logins_Unusual_Place:action_result.summary.total_events", ">", 0],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Logins_Unusual_Place(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_9() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Multiple_IP_Short_Time:action_result.summary.total_events", ">", 0],
        ],
        name="filter_9:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Multiple_IP_Short_Time(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_10() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Irregular_Access_Hr:action_result.summary.total_events", ">", 0],
        ],
        name="filter_10:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Irregular_Access_Hr(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_Check_Logins_Unusual_Place(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Logins_Unusual_Place() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Logins_Unusual_Place:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Logins_Unusual_Place")

    Pin_Check_Logins_Unusual_Place(container=container)

    return

def Format_Pin_Check_Multiple_IP_Short_Time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Multiple_IP_Short_Time() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Multiple_IP_Short_Time:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Multiple_IP_Short_Time")

    Pin_Check_Multiple_IP_Short_Time(container=container)

    return

def Format_Pin_Check_Irregular_Access_Hr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Irregular_Access_Hr() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Irregular_Access_Hr:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Irregular_Access_Hr")

    Pin_Check_Irregular_Access_Hr(container=container)

    return

def Pin_Check_Logins_Unusual_Place(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Logins_Unusual_Place() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Logins_Unusual_Place')

    phantom.pin(container=container, data=formatted_data_1, message="Logins Unusual Place Detected", name="Logins Unusual Place Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Pin_Check_Multiple_IP_Short_Time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Multiple_IP_Short_Time() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Multiple_IP_Short_Time')

    phantom.pin(container=container, data=formatted_data_1, message="Multiple IP Short Time Detected", name="Multiple IP Short Time Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Pin_Check_Irregular_Access_Hr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Irregular_Access_Hr() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Irregular_Access_Hr')

    phantom.pin(container=container, data=formatted_data_1, message="Irregular Access Hr Detected", pin_type="card", pin_style="", name="Irregular Access Hr Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Check_Irregular_Access_Hr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Irregular_Access_Hr() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Irregular_Access_Hr' call
    formatted_data_1 = phantom.get_format_data(name='Format_Irregular_Access_Hr')

    parameters = []
    
    # build parameters list for 'Check_Irregular_Access_Hr' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_10, name="Check_Irregular_Access_Hr")

    return

def Check_Network_Intrusions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Network_Intrusions() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Network_Intrusions' call
    formatted_data_1 = phantom.get_format_data(name='Format_Network_Intrusions')

    parameters = []
    
    # build parameters list for 'Check_Network_Intrusions' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_11, name="Check_Network_Intrusions")

    return

def Format_Network_Intrusions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Network_Intrusions() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(IDS_Attacks.severity) as severity,count from datamodel=Intrusion_Detection.IDS_Attacks where IDS_Attacks.dest=\"{0}\"  earliest=-2d latest=now (IDS_Attacks.category=\"*\") by IDS_Attacks.category,IDS_Attacks.signature,IDS_Attacks.src,IDS_Attacks.dest 
| `drop_dm_object_name(\"IDS_Attacks\")` 
| sort - count 
| fields _time,src,dest,severity,category,signature,count"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Network_Intrusions")

    Check_Network_Intrusions(container=container)

    return

def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_11() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Network_Intrusions:action_result.summary.total_events", ">", 0],
        ],
        name="filter_11:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Network_Intrusions(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_Check_Network_Intrusions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Network_Intrusions() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Network_Intrusions:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Network_Intrusions")

    Pin_Check_Network_Intrusions(container=container)

    return

def Filter_Endpoint_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Endpoint_Activity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", ""],
        ],
        name="Filter_Endpoint_Activity:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Endpoint_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Endpoint_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Endpoint_Activity() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Malware_Attacks.action) as action,values(Malware_Attacks.file_name) as file_name,latest(Malware_Attacks.user) as user,count from datamodel=Malware.Malware_Attacks where Malware_Attacks.dest=\"{0}\" earliest=-5d latest=now by Malware_Attacks.signature,Malware_Attacks.dest 
| `drop_dm_object_name(\"Malware_Attacks\")` 
| sort - count 
| fields _time,dest, action,signature,file_name,user,count"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Endpoint_Activity")

    Check_Endpoint_Activity(container=container)

    return

def Check_Endpoint_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Endpoint_Activity() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Endpoint_Activity' call
    formatted_data_1 = phantom.get_format_data(name='Format_Endpoint_Activity')

    parameters = []
    
    # build parameters list for 'Check_Endpoint_Activity' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_13, name="Check_Endpoint_Activity")

    return

def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_13() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Endpoint_Activity:action_result.summary.total_events", ">", 0],
        ],
        name="filter_13:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Endpoint_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_Check_Endpoint_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Endpoint_Activity() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Endpoint_Activity:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Endpoint_Activity")

    Pin_Check_Endpoint_Activity(container=container)

    return

def Pin_Check_Endpoint_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Endpoint_Activity() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Endpoint_Activity')

    phantom.pin(container=container, data=formatted_data_1, message="Endpoint Activity Detected", name="Endpoint Activity Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Pin_Check_Network_Intrusions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Network_Intrusions() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Network_Intrusions')

    phantom.pin(container=container, data=formatted_data_1, message="Network Intrusions Detected", pin_type="card", pin_style="", name="Network Intrusions Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Format_Outbound_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Outbound_Traffic() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(All_Traffic.action) as action,values(All_Traffic.src_port) as src_port,count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src=\"{0}\" earliest=-1d latest=now by All_Traffic.src,All_Traffic.dest,All_Traffic.transport,All_Traffic.dest_port 
| `drop_dm_object_name(\"All_Traffic\")` 
| sort - count 
| fields _time,src,src_port,dest_port,dest,action,transport,count
| search NOT ( dest=10.* OR dest=192.* OR dest=172.168.* )"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Outbound_Traffic")

    Check_Outbound_Traffic(container=container)

    return

def Check_Outbound_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Outbound_Traffic() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Outbound_Traffic' call
    formatted_data_1 = phantom.get_format_data(name='Format_Outbound_Traffic')

    parameters = []
    
    # build parameters list for 'Check_Outbound_Traffic' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_14, name="Check_Outbound_Traffic")

    return

def filter_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_14() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Outbound_Traffic:action_result.summary.total_events", ">", 0],
        ],
        name="filter_14:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Outbound_Traffic(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_Outbound_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Outbound_Traffic() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Outbound_Traffic:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Outbound_Traffic")

    Pin_Outbound_Traffic(container=container)

    return

def Pin_Outbound_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Outbound_Traffic() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Outbound_Traffic')

    phantom.pin(container=container, data=formatted_data_1, message="Outbound Traffic Detected", name="Outbound Traffic Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def filter_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_15() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", ""],
        ],
        name="filter_15:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_OT_Asset_Info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_ES_notables(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_ES_notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_ES_notables() called')
    
    template = """index=notable earliest=-1d latest=now src={0}
| stats count by src search_name"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_ES_notables")

    Check_ES_Notables(container=container)

    return

def Check_ES_Notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_ES_Notables() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_ES_Notables' call
    formatted_data_1 = phantom.get_format_data(name='Format_ES_notables')

    parameters = []
    
    # build parameters list for 'Check_ES_Notables' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_16, name="Check_ES_Notables")

    return

def filter_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_16() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_ES_Notables:action_result.summary.total_events", ">", 0],
        ],
        name="filter_16:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_ES_Notables(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Pin_ES_Notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_ES_Notables() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "Check_ES_Notables:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_ES_Notables")

    Pin_ES_Notables_Detected(container=container)

    return

def Pin_ES_Notables_Detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_ES_Notables_Detected() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_ES_Notables')

    phantom.pin(container=container, data=formatted_data_1, message="ES Notables Detected", name="ES Notables Detected")
    join_Prompt_Escalate_Case(container=container)

    return

def Format_Pin_Zone_Level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Zone_Level() called')
    
    template = """Asset identified in Zone {1} and Purdue Level {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.zone",
        "Check_for_OT_Asset_Info:action_result.data.*.level",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Zone_Level")

    Pin_Zone_Level(container=container)

    return

def Pin_Zone_Level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Zone_Level() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Zone_Level')

    phantom.pin(container=container, data=formatted_data_1, message="Verify Asset Zone and Level", name="Asset Zone and Level")
    join_promote_to_case_1(container=container)

    return

def import_container_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('phantom.add_workbook start')
    ot_sec_workbook_id = 9
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    success, message = phantom.add_tags(workbook_id=ot_sec_workbook_id)
    success, message = phantom.add_workbook(workbook_id=ot_sec_workbook_id)
    # collect data for 'import_container_1' call
    
    if success:
        phantom.debug('phantom.add_workbook succeeded. API message: {}'.format(message))
        # Call on_success callback
    else:
        phantom.debug('phantom.add_workbook failed. API message: {}'.format(message))
        # Call on_fail callball
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return