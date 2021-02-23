"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_priv_auth_search' block
    format_priv_auth_search(container=container)

    return

def format_priv_auth_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_priv_auth_search() called')
    
    template = """| tstats `summariesonly` max(_time) as _time,values(Authentication.user_category) as user_category,dc(Authentication.dest) as dc(dest) from datamodel=Authentication.Authentication where Authentication.user_category=default  Authentication.dest=\"{0}\"  earliest=-1d latest=now by  Authentication.dest Authentication.user
| `drop_dm_object_name(\"Authentication\")` 
| sort 100 - _time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_priv_auth_search")

    check_priv_auth_activity(container=container)

    return

"""
Search for Access priv logins to the asset
"""
def check_priv_auth_activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_priv_auth_activity() called')

    # collect data for 'check_priv_auth_activity' call
    formatted_data_1 = phantom.get_format_data(name='format_priv_auth_search')

    parameters = []
    
    # build parameters list for 'check_priv_auth_activity' call
    parameters.append({
        'command': "",
        'query': formatted_data_1,
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_1, name="check_priv_auth_activity")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["check_priv_auth_activity:action_result.summary.total_events", ">", 0],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Check_Priv_Auth_Activity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["check_priv_auth_activity:action_result.summary.total_events", "==", 0],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Check_Priv_Auth_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Check_Priv_Auth_Activity() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:check_priv_auth_activity:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Check_Priv_Auth_Activity")

    Pin_Check_Priv_Auth_Activity(container=container)

    return

def Pin_Check_Priv_Auth_Activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Priv_Auth_Activity() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Check_Priv_Auth_Activity')

    phantom.pin(container=container, data=formatted_data_1, message="Priv Auth Activities Detected", name="Priv Auth Activities Detected")

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