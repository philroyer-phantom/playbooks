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

def Format_Network_Behavior_Change(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Network_Behavior_Change() called')
    
    template = """index=evt_sum_ot_asset_traffic sum_type=evt_sum_ot_asset_traffic_snap_1d earliest=-1d@d latest=-0d@d dvc=\"{0}\" 
| table dvc tot_bytes tot_session avg_port_com_num tot_duration dvc_asset_type, dvc_asset_status, dvc_asset_system 
| append 
    [ search index=evt_sum_ot_asset_traffic sum_type=evt_sum_ot_asset_traffic_snap_1d earliest=-2d@d latest=-1d@d dvc=\"{0}\"
    | table dvc tot_bytes tot_session avg_port_com_num tot_duration ] 
| stats avg(tot_bytes) as tot_bytes_avg, range(tot_bytes) as tot_bytes_range, avg(tot_session) as tot_session_avg, range(tot_session) as tot_session_range, avg(tot_duration) as tot_duration_avg, range(tot_duration) as tot_duration_range, last(dvc_asset_type) as dvc_asset_type, last(dvc_asset_status) as dvc_asset_status, last(dvc_asset_system) as dvc_asset_system by dvc
| eval tot_bytes_change_pct=round(((tot_bytes_avg+tot_bytes_range)*100/tot_bytes_avg)-100), tot_session_change_pct=round(((tot_session_avg+tot_session_range)*100/tot_session_avg)-100), tot_duration_change_pct=round(((tot_duration_avg+tot_duration_range)*100/tot_duration_avg)-100)
| eval tot_mb_avg=tot_bytes_avg/1024/1024
| lookup asset_lookup_by_str dns as dvc OUTPUTNEW asset_type as dns_asset_type, asset_system, asset_status, site_id
| lookup asset_lookup_by_str nt_host as dvc OUTPUTNEW asset_type as host_asset_type, asset_system, asset_status, site_id
| lookup asset_lookup_by_str ip as dvc OUTPUTNEW asset_type as ip_asset_type, asset_system, asset_status, site_id
| fillnull dvc_site_id, dvc_bunit, site_id  value=\"\" 
| search dvc_asset_type=* site_id=\"*\" dvc_bunit=\"*\" asset_system=\"*\"
| table dvc, dvc_asset_type, tot_mb_avg, tot_bytes_avg, tot_bytes_change_pct, tot_session_avg, tot_session_change_pct, tot_duration_avg, tot_duration_change_pct,  dvc_asset_status, dvc_asset_system, site_id
| sort - tot_bytes_change_pct
| table dvc, dvc_asset_type, tot_bytes_change_pct, tot_session_change_pct, tot_duration_change_pct,  dvc_asset_system, site_id"""

    # parameter list for template variable replacement
    parameters = [
        "Search_OT_Asset:action_result.data.*.ip",
        "Search_OT_Asset:action_result.data.*.net_local",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Network_Behavior_Change")

    Check_Network_Behavior_Change(container=container)

    return

"""
Search for Access priv logins to the asset
"""
def Check_Network_Behavior_Change(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Network_Behavior_Change() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Check_Network_Behavior_Change' call
    formatted_data_1 = phantom.get_format_data(name='Format_Network_Behavior_Change')

    parameters = []
    
    # build parameters list for 'Check_Network_Behavior_Change' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=filter_1, name="Check_Network_Behavior_Change")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Network_Behavior_Change:action_result.summary.total_events", ">", 0],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_Format_Network_Behavior_Chang(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Add_Note_Format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Network_Behavior_Change:action_result.summary.total_events", "==", 0],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def Format_Pin_Format_Network_Behavior_Chang(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Pin_Format_Network_Behavior_Chang() called')
    
    template = """Total {0} Records Detected for Review"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:Check_Network_Behavior_Change:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Pin_Format_Network_Behavior_Chang")

    Pin_Check_Network_Behavior_Change(container=container)

    return

def Pin_Check_Network_Behavior_Change(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Pin_Check_Network_Behavior_Change() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Pin_Format_Network_Behavior_Chang')

    phantom.pin(container=container, data=formatted_data_1, message="Check for network behavior changes of asset", name="Check for network behavior changes of asset")

    return

def Add_Note_Format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_Format() called')
    
    template = """Enforce filtering network traffic : Ensure only authorized data flows are allowed to the asset, especially across network boundaries.

Verify the network communication behavior changes of the asset.  Larger the change % higher the risk. 

|dvc|dvc_asset_type|tot_bytes_change_pct|tot_session_change_pct|tot_duration_change_pct|dvc_asset_system|site_id|
|--|--|--|--|--|--|--|
%%
|{0}|{1}|{2}%|{3}%|{4}%|{5}|{6}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_Network_Behavior_Change:action_result.data.*.src",
        "Check_Network_Behavior_Change:action_result.data.*.dest",
        "Check_Network_Behavior_Change:action_result.data.*.count",
        "Check_Network_Behavior_Change:action_result.data.*.action",
        "Check_Network_Behavior_Change:action_result.data.*.src_port",
        "Check_Network_Behavior_Change:action_result.data.*.dest_port",
        "Check_Network_Behavior_Change:action_result.data.*.transport",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Add_Note_Format")

    add_note_3(container=container)

    return

def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='Add_Note_Format')

    note_title = "Check for network behavior changes of asset"
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

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=Format_Network_Behavior_Change, name="Search_OT_Asset")

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