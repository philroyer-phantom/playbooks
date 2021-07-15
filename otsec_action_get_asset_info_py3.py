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
| table asset asset_id asset_vendor_model asset_model asset_status asset_system asset_tag asset_type asset_vendor asset_version bunit category city classification country description dns exposure ip location mac nt_host owner pci_domain priority requires_av should_timesync should_update site_id vlan zone zone_no"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_OT_Asset_Search")

    Check_for_OT_Asset_Info(container=container)

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
        "Check_for_OT_Asset_Info:action_result.data.*.zone_no",
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
        Format_Add_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_for_OT_Asset_Info:action_result.data.*.asset_type", "==", ""],
        ],
        name="filter_15:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Zone_Level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Zone_Level() called')
    
    template = """Asset identified in Perdue Level \"{0}\" and Location at \"{1}\", production line 
\"{2}\""""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.zone_no",
        "Check_for_OT_Asset_Info:action_result.data.*.location",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_system",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Zone_Level")

    Pin_Zone_Level(container=container)

    return

def Pin_Zone_Level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Zone_Level() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Zone_Level')

    phantom.pin(container=container, data=formatted_data_1, message="Verify Asset Zone, Level, Location", name="Asset Zone and Level")

    return

def Format_Add_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Add_Note() called')
    
    template = """**GUIDE** : Please verify that this is an OT asset as well as determine the potential risk and impact for the function and role of the asset in the operation.

|Hostname|IP|Type|Vendor|Model|Version|Status|Priority|Perdue Zone|Zone Info|Exposure|
|--|--|--|--|--|--|--|--|--|
|{1}|{20}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|

|ID|Biz Unit|System|Site ID|Location|City|Country|Latitude|Longitude|
|--|--|--|--|--|--|--|--|--|--|
|{11}|{12}|{13}|{14}|{15}|{16}|{17}|{18}|{19}|"""

    # parameter list for template variable replacement
    parameters = [
        "Check_for_OT_Asset_Info:action_result.data.*.asset",
        "Check_for_OT_Asset_Info:action_result.data.*.nt_host",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_type",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_vendor",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_model",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_version",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_status",
        "Check_for_OT_Asset_Info:action_result.data.*.priority",
        "Check_for_OT_Asset_Info:action_result.data.*.zone_no",
        "Check_for_OT_Asset_Info:action_result.data.*.zone",
        "Check_for_OT_Asset_Info:action_result.data.*.exposure",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_id",
        "Check_for_OT_Asset_Info:action_result.data.*.bunit",
        "Check_for_OT_Asset_Info:action_result.data.*.asset_system",
        "Check_for_OT_Asset_Info:action_result.data.*.site_id",
        "Check_for_OT_Asset_Info:action_result.data.*.location",
        "Check_for_OT_Asset_Info:action_result.data.*.city",
        "Check_for_OT_Asset_Info:action_result.data.*.country",
        "Check_for_OT_Asset_Info:action_result.data.*.lat",
        "Check_for_OT_Asset_Info:action_result.data.*.long",
        "Check_for_OT_Asset_Info:action_result.data.*.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Add_Note")

    add_note_22(container=container)

    return

def add_note_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_22() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Add_Note')

    note_title = "OT Asset Information Details"
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