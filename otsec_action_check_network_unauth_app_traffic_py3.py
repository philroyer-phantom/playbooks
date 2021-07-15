"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_Asset_Lookup' block
    Format_Asset_Lookup(container=container)

    return

def Format_Network_Unauth_App_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Network_Unauth_App_Traffic() called')
    
    template = """| tstats `summariesonly` values(All_Traffic.action) as action,values(All_Traffic.src) as src,values(All_Traffic.src_port) as src_port,values(All_Traffic.dest) as dest,count from datamodel=Network_Traffic.All_Traffic where earliest=-24h latest=now ( All_Traffic.dest=\"{0}\" ) NOT (All_Traffic.dest_port=\"136\" OR All_Traffic.dest_port=\"23\" OR All_Traffic.dest_port=\"25\" OR All_Traffic.dest_port=\"80\" OR All_Traffic.dest_port=\"22\" OR All_Traffic.dest_port=\"135\" OR All_Traffic.dest_port=\"514\" OR All_Traffic.dest_port=\"443\" OR All_Traffic.dest_port=\"20\" OR All_Traffic.dest_port=\"123\" OR All_Traffic.dest_port=\"502\") by All_Traffic.dest_port
| `drop_dm_object_name(\"All_Traffic\")`
| rex field=dest \"(?P<src_net>\\d+\\.\\d+)\"
| eval condition=src_net+\".%\"
| where NOT (src LIKE condition)
| table dest_port dest src src_port   action   count
| sort - count"""

    # parameter list for template variable replacement
    parameters = [
        "Search_OT_Asset:action_result.data.*.ip",
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Network_Unauth_App_Traffic")

    Check_Network_Unauth_App_Traffic(container=container)

    return

"""
Search for Access priv logins to the asset
"""
def Check_Network_Unauth_App_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Network_Unauth_App_Traffic() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Network_Unauth_App_Traffic' call
    formatted_data_1 = phantom.get_format_data(name='Format_Network_Unauth_App_Traffic')

    parameters = []
    
    # build parameters list for 'Check_Network_Unauth_App_Traffic' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_1, name="Check_Network_Unauth_App_Traffic")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Network_Unauth_App_Traffic:action_result.summary.total_events", ">", 0],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Network_Unauth_App_Traffic(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Add_Note_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Network_Unauth_App_Traffic:action_result.summary.total_events", "==", 0],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Network_Unauth_App_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Network_Unauth_App_Traffic() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:Check_Network_Unauth_App_Traffic:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Network_Unauth_App_Traffic")

    Pin_Check_Network_Unauth_App_Traffic(container=container)

    return

def Pin_Check_Network_Unauth_App_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Network_Unauth_App_Traffic() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Network_Unauth_App_Traffic')

    phantom.pin(container=container, data=formatted_data_1, message="Check Network Unauthorized App Traffic", name="Check Network Unauthorized App Traffic")

    return

def Add_Note_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_Format() called')
    
    template = """|dest_port|dest|src|src_port|action|count|
|--|--|--|--|--|--|
%%
|{0}|{1}|{2}|{3}|{4}|{5}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Network_Unauth_App_Traffic:action_result.data.*.dest_port",
        "Check_Network_Unauth_App_Traffic:action_result.data.*.dest",
        "Check_Network_Unauth_App_Traffic:action_result.data.*.src",
        "Check_Network_Unauth_App_Traffic:action_result.data.*.src_port.data.*.src_port",
        "Check_Network_Unauth_App_Traffic:action_result.data.*.dest_port.data.*.action",
        "Check_Network_Unauth_App_Traffic:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Add_Note_Format")

    add_note_3(container=container)

    return

def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='Add_Note_Format')

    note_title = "Check Network Unauthorized App Traffic"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Format_Asset_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Asset_Lookup() called')
    
    template = """| `reverse_asset_lookup(\"{0}\")`
| strcat asset_vendor \" : \" asset_model asset_vendor_model
| rex field=zone \"level[_]*(?<zone_no>\\d+)\"
| mvexpand zone_no
| table asset asset_id asset_vendor_model asset_model asset_status asset_system asset_tag asset_type asset_vendor asset_version bunit category city classification country description dns exposure ip location mac nt_host owner pci_domain priority requires_av should_timesync should_update site_id vlan zone zone_no
| rex field=ip \"^(?P<net_local>\\d+\\.\\d+)\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Asset_Lookup")

    Search_OT_Asset(container=container)

    return

def Search_OT_Asset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Search_OT_Asset() called')

    # collect data for 'Search_OT_Asset' call
    formatted_data_1 = phantom.get_format_data(name='Format_Asset_Lookup')

    parameters = []
    
    # build parameters list for 'Search_OT_Asset' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=Format_Network_Unauth_App_Traffic, name="Search_OT_Asset")

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