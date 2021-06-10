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
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_15, name="Check_for_OT_Asset_Info")

    return

def Format_OT_Asset_Search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_OT_Asset_Search() called')
    
    template = """| `reverse_asset_lookup(\"{0}\")`
| strcat asset_vendor \" : \" asset_model asset_vendor_model
| rex field=zone \"level[_]*(?<zone_no>\\d+)\"
| mvexpand zone_no
| table nt_host ip exposure zone_no dns location"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_OT_Asset_Search")

    Check_for_OT_Asset_Info(container=container)

    return

def Format_Pin_OT_Asset_Info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_OT_Asset_Info() called')
    
    template = """HOST : {0} | IP : {1} | {2} | Zone {3}"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.nt_host",
        "Check_for_OT_Asset_Info:action_result.data.*.ip",
        "Check_for_OT_Asset_Info:action_result.data.*.exposure",
        "Check_for_OT_Asset_Info:action_result.data.*.zone_no",
        "Check_for_OT_Asset_Info:action_result.data.*.dns",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_OT_Asset_Info")

    Pin_OT_Asset_Info(container=container)

    return

def Pin_OT_Asset_Info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_OT_Asset_Info() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_OT_Asset_Info')

    phantom.pin(container=container, data=formatted_data_1, message="Check Network Config", pin_type="card", pin_style="red", name="Check Network Config")

    return

def filter_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_15() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "!=", 0],
        ],
        name="filter_15:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_OT_Asset_Info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Add_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "==", 0],
        ],
        name="filter_15:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Add_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Add_Note() called')
    
    template = """**GUIDE** : Check Network configuration on this asset.  Be aware of Exposure and Zone of the asset.

|nt_host|ip|exposure|zone_no|dns|location|
|--|--|--|--|--|--|
|{0}|{1}|{2}|{3}|{4}|{5}|"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.nt_host",
        "Check_for_OT_Asset_Info:action_result.data.*.ip",
        "Check_for_OT_Asset_Info:action_result.data.*.exposure",
        "Check_for_OT_Asset_Info:action_result.data.*.zone_no",
        "Check_for_OT_Asset_Info:action_result.data.*.dns",
        "Check_for_OT_Asset_Info:action_result.data.*.location",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Add_Note")

    add_note_22(container=container)

    return

def add_note_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_22() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Add_Note')

    note_title = "\"Enforcement of network segmentation control on the host, limiting the host to minimal connectivity"
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