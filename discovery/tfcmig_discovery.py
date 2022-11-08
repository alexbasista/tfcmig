import os
import sys
import logging
import argparse
import pytfc
#import pandas as pd
from tabulate import tabulate
import time
import tarfile
import io
import requests


# Environment Variables
SRC_TFE_HOSTNAME = os.getenv('SRC_TFE_HOSTNAME')
SRC_TFE_TOKEN = os.getenv('SRC_TFE_TOKEN')
SRC_TFE_ORG = os.getenv('SRC_TFE_ORG')
SRC_TFE_VERIFY = os.getenv('SRC_TFE_VERIFY', False)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Constants
MAX_PAGE_SIZE=100

def _get_oc_name(client, ot_id):
    """
    Helper method used by registry_modules_report()
    
    Returns OAuth Client (Display) Name based on
    OAuth Token ID.
    """
    ot = client.oauth_tokens.show(ot_id)
    oc_id = ot.json()['data']['relationships']['oauth-client']['data']['id']
    oc = client.oauth_clients.show(oc_id)
    oc_name = oc.json()['data']['attributes']['name']
    
    return oc_name

def get_ws_team_access(client):
    """
    Function to generate report of Team Access
    (RBAC) settings on Workspaces.
    """

def get_ws_notifications(client):
    """
    Function to generate report of Notification
    settings that exist on Workspaces.
    """

def get_ws_run_triggers(client):
    """
    Function to generate report of Run Triggers
    configured for Workspaces.
    """

def get_mod_src_in_ws(client):
    """
    Function to generate report of Workspaces
    that have Terraform Resources in them that
    were created from a Registry Module.

    This function leverages Sentinel Mock data
    (tfconfig-v2 import) to analyze any module
    calls and specifically filter out Registry
    Modules.
    """
    _log.info("Generating 'Module Sources in Workspaces' report...")
    
    results = []
    ws_results = []

    ws_list = client.workspaces.list_all()['data']
    for ws in ws_list:
        ws_results = {}
        mods_found = []
        mods_found_unique = []
        plan_export_id = None
        ws_id = ws['id']
        ws_name = ws['attributes']['name']
        _log.debug(f"Starting Workspace `{ws_name}`.") 
               
        _log.debug(f"Finding Plan ID from latest Run in Workspace `{ws_name}`.")
        try:
            latest_run = client.runs.list(ws_id=ws_id).json()['data'][0]
            latest_plan_id = latest_run['relationships']['plan']['data']['id']
            _log.debug(f"Detected latest Run ID is `{latest_run['id']}`.")
        except IndexError:
            _log.debug(f"Did not detect a Run in Workspace. Skipping `{ws_name}`.")
            continue
        
        try:
            plan_export_id = client.plans.show(plan_id=latest_plan_id).json()\
                ['data']['relationships']['exports']['data'][0]['id']
            _log.debug(f"Found existing Plan Export ID `{plan_export_id}`.")
        except IndexError:
            _log.debug(f"Did not detect Plan Export on Plan `{latest_plan_id}`.")
            plan_export_id = None
        
        if plan_export_id is None:
            _log.debug(f"Creating new Plan Export for Plan `{latest_plan_id}`.")
            try:
                plan_export_id = client.plan_exports.create(
                    plan_id=latest_plan_id).json()['data']['id']
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 422:
                    _log.error(f"A Plan Export is already pending. Skipping `{ws_name}`.")
                    continue
                else:
                    _log.error(f"An unexpected error occured. Skipping `{ws_name}`.")
                    continue

        pe_status = client.plan_exports.show(pe_id=plan_export_id).json()\
            ['data']['attributes']['status']
        # error handling here for the No-Code Workspaces that do not support mocks
        if pe_status == 'errored':
            _log.error(f"Detected Plan Export `{plan_export_id}`"\
                f" is in an errored status. Skipping `{ws_name}`.")
            continue

        pe_dl_url = client.plan_exports._get_download_url(pe_id=plan_export_id)
        
        pe_bytes_data = requests.get(url=pe_dl_url, stream=True).content
        retry_count = 0
        while len(pe_bytes_data) == 0:
            _log.debug("Detected Plan Export download was empty. Retrying...")
            time.sleep(2)
            pe_bytes_data = requests.get(url=pe_dl_url, stream=True).content
            retry_count += 1
            if retry_count == 60:
                _log.error(f"Exceeded max download retries. Skipping `{ws_name}`.")
                continue

        _log.debug(f"Successfully downloaded Plan Export with data from `{latest_plan_id}`.")
        pe_file_obj = io.BytesIO(pe_bytes_data)
        pe_tarball = tarfile.open(fileobj=pe_file_obj)
        member = pe_tarball.getmember(name='mock-tfconfig-v2.sentinel')
        tfconfig_data = pe_tarball.extractfile(member).read()
        tfconfig_str = tfconfig_data.decode('utf-8')
        
        for line in tfconfig_str.splitlines():
            if '"source":' in line:
                line.split('"')[3]
                mods_found.append(line.split('"')[3])

        mods_found_unique = list(dict.fromkeys(mods_found))

        ws_results['Workspace'] = ws_name
        ws_results['Registry Modules Used'] = mods_found_unique
        results.append(ws_results)
    
    print("***********************************************************************************************************************")
    print("*                                             Module Sources in Workspaces                                            *")
    print("***********************************************************************************************************************")
    #mod_src_in_ws_df = pd.DataFrame(mod_src_in_ws_report)
    #print(tabulate(mod_src_in_ws_df, headers='keys', tablefmt='simple'))
    print(tabulate(results, headers='keys', tablefmt='simple'))
    print('\n')
    return results

def get_mod_calls_in_ws(client):
    """
    Function to generate report of Workspaces
    that have Terraform Resources in them that
    were created with a module call (generic).
    """
    _log.info("Generating 'Module Calls in Workspaces' report...")
    results = []
    
    ws_list = client.workspaces.list_all()['data']
    for ws in ws_list:
        ws_results = {}
        wsr_results = []
        ws_id = ws['id']
        ws_name = ws['attributes']['name']
        _log.debug(f"Starting Workspace `{ws_name}`.") 
        
        ws_resources = client.workspace_resources.list_all(ws_id=ws_id)['data']
        for r in ws_resources:
            mod = r['attributes']['module']
            wsr_results.append(mod)

        wsr_results = list( dict.fromkeys(wsr_results) )
        if 'root' in wsr_results: 
            wsr_results.remove('root')
        
        ws_results['Workspace'] = ws_name
        
        if wsr_results == []:
            ws_results['Modules'] = 'N/A'
        else:
            ws_results['Modules'] = wsr_results
        
        results.append(ws_results)

    print("***********************************************************************************************************************")
    print("*                                            Module Calls in Workspaces                                               *")
    print("***********************************************************************************************************************")
    #mod_calls_in_ws_df = pd.DataFrame(mod_calls_in_ws_report)
    #print(tabulate(modules_in_workspaces_df, headers='keys', tablefmt='simple'))
    print(tabulate(results, headers='keys', tablefmt='simple'))
    print('\n')
    return results

def registry_modules_report(client):
    """
    Function to generate report of Registry Modules.
    """
    _log.info("Generating 'Registry Modules in Organizations' report...")
    results = []
    
    modules_list = client.registry_modules.list(page_size=MAX_PAGE_SIZE)
    for mod in modules_list.json()['data']:
        mod_result = {}
        mod_result['Org'] = mod['attributes']['namespace']
        mod_result['Name'] = mod['attributes']['name']
        mod_result['Provider'] = mod['attributes']['provider']

        try:
            mod_result['VCS'] = mod['attributes']['vcs-repo']['service-provider']
            mod_result['Repo'] = mod['attributes']['vcs-repo']['identifier']
            ot_id = mod['attributes']['vcs-repo']['oauth-token-id']
            mod_result['OAuth Token ID'] = ot_id
            oc_name = _get_oc_name(client=client, ot_id=ot_id)
            mod_result['OAuth Client Name'] = oc_name
        except KeyError:
            _log.debug('Detected module created without VCS.')
            mod_result['VCS'] = 'N/A'
            mod_result['Repo'] = 'N/A'
            mod_result['OAuth Token ID'] = 'N/A'
            mod_result['OAuth Client Name'] = 'N/A'

        results.append(mod_result)
    
    print("***********************************************************************************************************************")
    print("*                                       Registry Modules in Organizations Report                                      *")
    print("***********************************************************************************************************************")
    # reg_mod_df = pd.DataFrame(reg_mod_report)
    # print(tabulate(reg_mod_df, headers='keys', tablefmt='simple'))
    print(tabulate(results, headers='keys', tablefmt='simple'))
    print('\n')
    
    return results

def parse_args():
    parser = argparse.ArgumentParser(description='TFC/E arguments for script.')
    parser.add_argument('--orgs', dest='orgs', nargs='*',
        help='List of source TFE Organizations to query.')
    parser.add_argument('--all-reports', dest='all_reports',
        help='Generate report with all source TFE components.',
        action='store_true')
    parser.add_argument('--registry-modules', dest='registry_modules',
        help='Generate report of Registry Modules and their VCS info.',
        action='store_true')
    parser.add_argument('--module-calls-in-workspaces', dest='module_calls_in_workspaces',
        help='Generate report of module calls made in Workspaces.',
        action='store_true')
    parser.add_argument('--module-sources-in-workspaces', dest='module_sources_in_workspaces',
        help='Generate report of module sources used in Workspaces.',
        action='store_true')
    args = parser.parse_args()
    return args

def main():
    tfe_client = None
    reg_mod_report = []
    mod_calls_in_ws_report = []
    mod_src_in_ws_report = []

    for org in orgs:
        _log.info(f"Instantiating API client for source TFE Org `{org}`.")
        tfe_client = pytfc.Client(hostname=SRC_TFE_HOSTNAME,
            token=SRC_TFE_TOKEN, org=org)
        
        if not args.all_reports:
            if args.registry_modules:
                reg_mod_results = registry_modules_report(client=tfe_client)
                reg_mod_report.extend(reg_mod_results)

            if args.module_calls_in_workspaces:
                mod_calls_in_ws_results = get_mod_calls_in_ws(client=tfe_client)
                mod_calls_in_ws_report.extend(mod_calls_in_ws_results)
            
            if args.module_sources_in_workspaces:
                mod_src_in_ws_results = get_mod_src_in_ws(client=tfe_client)
                mod_src_in_ws_report.extend(mod_src_in_ws_results)
        else:
            # run everything
            reg_mod_results = registry_modules_report(client=tfe_client)
            reg_mod_report.extend(reg_mod_results)
            
            mod_calls_in_ws_results = get_mod_calls_in_ws(client=tfe_client)
            mod_calls_in_ws_report.extend(mod_calls_in_ws_results)

            mod_src_in_ws_results = get_mod_src_in_ws(client=tfe_client)
            mod_src_in_ws_report.extend(mod_src_in_ws_results)

if __name__ == "__main__":
    # setup logging
    _log = logging.getLogger(__name__)
    _log_level = getattr(logging, LOG_LEVEL.upper())
    _log.setLevel(_log_level)
    _console_handler = logging.StreamHandler()
    _console_handler.setLevel(_log_level)
    _formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    _console_handler.setFormatter(_formatter)
    _log.addHandler(_console_handler)

    # parse and validate args
    args = parse_args()
    
    orgs = args.orgs
    if not isinstance(orgs, list):
        _log.error(\
            "Must provide a list of Organizations with `--orgs` argument.")
        sys.exit(1)

    if not args.all_reports:
        if not args.registry_modules\
            and not args.module_calls_in_workspaces\
            and not args.module_sources_in_workspaces:
                _log.error(\
                    "Must provide a migration component argument(s)."\
                    " See `Usage` section of README.")
                sys.exit(1)
    
    main()
    
    _log.debug("Finished reports!")
    sys.exit(0)