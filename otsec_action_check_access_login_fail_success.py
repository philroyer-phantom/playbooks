"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_Login_Failures_Successes' block
    Format_Login_Failures_Successes(container=container)

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

"""
Search for Access priv logins to the asset
"""
def Check_Login_Failures_Successes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Login_Failures_Successes() called')

    # collect data for 'Check_Login_Failures_Successes' call
    formatted_data_1 = phantom.get_format_data(name='Format_Login_Failures_Successes')

    parameters = []
    
    # build parameters list for 'Check_Login_Failures_Successes' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=Filter_Login_Result, name="Check_Login_Failures_Successes")

    return

def Filter_Login_Result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Login_Result() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Login_Failures_Successes:action_result.summary.total_events", ">", 0],
        ],
        name="Filter_Login_Result:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Login_Failures_Success(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Add_Note_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Login_Failures_Successes:action_result.summary.total_events", "==", 0],
        ],
        name="Filter_Login_Result:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Login_Failures_Success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Login_Failures_Success() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_Login_Result:condition_1:Check_Login_Failures_Successes:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Login_Failures_Success")

    Pin_Check_Login_Failures_Successes(container=container)

    return

def Pin_Check_Login_Failures_Successes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Login_Failures_Successes() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Login_Failures_Success')

    phantom.pin(container=container, data=formatted_data_1, message="Check authentication activities through access control system", name="Login Failures Successes Detected")

    return

def Add_Note_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_Format() called')
    
    template = """**GUIDE** : Validate authentication activities found for this asset({1}) through access control system :

|Apps|Source|Destination|User|Count|Action|
|----|----|----|----|----|----|
%%
|{0}|{1}|{2}|{3}|{4}|{5}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Login_Failures_Successes:action_result.data.*.app",
        "Check_Login_Failures_Successes:action_result.data.*.src",
        "Check_Login_Failures_Successes:action_result.data.*.dest",
        "Check_Login_Failures_Successes:action_result.data.*.user",
        "Check_Login_Failures_Successes:action_result.data.*.count",
        "Check_Login_Failures_Successes:action_result.data.*.action",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Add_Note_Format")

    Add_Notes(container=container)

    return

def Add_Notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Notes() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Check_Login_Failures_Successes:action_result.data.*._raw'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='Add_Note_Format')
    formatted_data_2 = phantom.get_format_data(name='Add_Note_Format__as_list')

    results_item_1_0 = [item[0] for item in results_data_1]

    note_title = "Enforce access management through centralized access control system"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.comment(container=container, comment=formatted_data_2)

    phantom.add_tags(container=container, tags="MITRE T0818")

    phantom.add_list("Login_List", results_item_1_0)

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