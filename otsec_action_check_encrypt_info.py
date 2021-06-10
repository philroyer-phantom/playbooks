"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_Encrypt_Info_Config' block
    Format_Encrypt_Info_Config(container=container)

    return

def Format_Encrypt_Info_Config(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Encrypt_Info_Config() called')
    
    template = """| inputlookup ot_asset_host_config
| search nt_host=\"{0}\"
| table nt_host ip ip_last encryption applied_patch asset_last_updated"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Encrypt_Info_Config")

    Check_Encrypt_Info_Config(container=container)

    return

def Check_Encrypt_Info_Config(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Encrypt_Info_Config() called')

    # collect data for 'Check_Encrypt_Info_Config' call
    formatted_data_1 = phantom.get_format_data(name='Format_Encrypt_Info_Config')

    parameters = []
    
    # build parameters list for 'Check_Encrypt_Info_Config' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_1, name="Check_Encrypt_Info_Config")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Encrypt_Info_Config:action_result.summary.total_events", ">", 0],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Encrypt_Info_Config(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Add_Note_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Encrypt_Info_Config:action_result.summary.total_events", "==", 0],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Encrypt_Info_Config(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Encrypt_Info_Config() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:Check_Encrypt_Info_Config:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Encrypt_Info_Config")

    Pin_Check_Encrypt_Info_Config(container=container)

    return

def Pin_Check_Encrypt_Info_Config(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Encrypt_Info_Config() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Encrypt_Info_Config')

    phantom.pin(container=container, data=formatted_data_1, message="Check Encrypt Info Config", name="Check Audit Endpoint Process")

    return

def Add_Note_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_Format() called')
    
    template = """**GUIDE** : Check Encryption configuration status at the endpoint.  \"Encryption\" must be \"yes\" and there should be recommended patches.

|nt_host|ip|ip_last|encryption|applied_patch|asset_last_updated|
|--|--|--|--|--|--|
%%
|{0}|{1}|{2}|{3}|{4}|{5}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Encrypt_Info_Config:action_result.data.*.nt_host",
        "Check_Encrypt_Info_Config:action_result.data.*.ip",
        "Check_Encrypt_Info_Config:action_result.data.*.ip_last",
        "Check_Encrypt_Info_Config:action_result.data.*.encryption",
        "Check_Encrypt_Info_Config:action_result.data.*.applied_patch",
        "Check_Encrypt_Info_Config:action_result.data.*.asset_last_updated",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Add_Note_Format")

    add_note_3(container=container)

    return

def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='Add_Note_Format')

    note_title = "Enforce managing sensitive information by encryption from the operational assets."
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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