"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_ES_notables' block
    Format_ES_notables(container=container)

    return

def Format_ES_notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_ES_notables() called')
    
    template = """index=notable earliest=-1d latest=now \"{0}\"
| rex field=dvc_asset_tag \"perdue:level(?<perdue_level>\\d+)\"
| search dvc=*
| eval time=strftime(_time,\"%Y-%m-%d %H:%M:%S\")
| table time, dvc, asset_type, perdue_level, asset_criticality, search_name"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvc",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_ES_notables")

    Check_ES_Notables(container=container)

    return

def Check_ES_Notables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_ES_Notables() called')

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

    phantom.act(action="run query", parameters=parameters, assets=['splunk es - ot sec'], callback=Filter_ES_Notable_Count, name="Check_ES_Notables")

    return

def Filter_ES_Notable_Count(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_ES_Notable_Count() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_ES_Notables:action_result.summary.total_events", ">", 0],
        ],
        name="Filter_ES_Notable_Count:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Pin_ES_Notables(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_Add_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_ES_Notables:action_result.summary.total_events", "==", 0],
        ],
        name="Filter_ES_Notable_Count:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

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

    phantom.pin(container=container, data=formatted_data_1, message="Check all detected ES notables", name="Check all detected ES notables")

    return

def Format_Add_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Add_Note() called')
    
    template = """**GUIDE** : Verify all ES notables related to the asset and depending on the combination of notables, additional investigation may be necessary.

|time|dvc|asset_type|perdue_level|asset_criticality|search_name|
|--|--|--|--|--|--|
%%
|{0}|{1}|{2}|{3}|{4}|{5}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_ES_Notables:action_result.data.*.time",
        "Check_ES_Notables:action_result.data.*.dvc",
        "Check_ES_Notables:action_result.data.*.asset_type",
        "Check_ES_Notables:action_result.data.*.perdue_level",
        "Check_ES_Notables:action_result.data.*.asset_criticality",
        "Check_ES_Notables:action_result.data.*.search_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Add_Note")

    add_note_22(container=container)

    return

def add_note_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_22() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Add_Note')

    note_title = "Check all detected ES notables"
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