import os
import sys
import logging
import argparse
import pytfc
import pandas as pd
from tabulate import tabulate


# Environment Variables
SRC_TFE_HOSTNAME = os.getenv('SRC_TFE_HOSTNAME')
SRC_TFE_TOKEN = os.getenv('SRC_TFE_TOKEN')
SRC_TFE_ORG = os.getenv('SRC_TFE_ORG')
SRC_TFE_VERIFY = os.getenv('SRC_TFE_VERIFY', False)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

#Constants
PAGE_SIZE=100

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

def workspace_rbac_report(client):
    """
    Function to generate report of Team Access
    settings on Workspaces (RBAC).
    """

def workspace_notifications_report(client):
    """
    Function to generate report of Notification
    settings that exist on Workspaces.
    """

def modules_in_workspaces_report(client):
    """
    Function to generate report of Workspaces
    that have Terraform Resources in them that
    were created from a Registry Module.
    """
    results = []
    ws_results = []
    
    ws_list = client.workspaces.list(page_size=PAGE_SIZE)
    for ws in ws_list.json()['data']:
        ws_results = {}
        ws_id = ws['id']
        ws_name = ws['attributes']['name']
        ws_resources = client.workspace_resources.list(
            ws_id=ws_id, page_size=PAGE_SIZE)

        wsr_results = []
        for r in ws_resources.json()['data']:
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

    return results

def registry_modules_report(client):
    """
    Function to generate report of Registry Modules.
    """
    results = []
    
    modules_list = client.registry_modules.list()
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
            log.debug('Detected module created without VCS.')
            mod_result['VCS'] = 'N/A'
            mod_result['Repo'] = 'N/A'
            mod_result['OAuth Token ID'] = 'N/A'
            mod_result['OAuth Client Name'] = 'N/A'

        results.append(mod_result)
    
    return results

def parse_args():
    parser = argparse.ArgumentParser(description='TFC/E arguments for script.')
    parser.add_argument('--orgs', dest='orgs', nargs='*',
        help='List of source TFE Organizations to query.')
    parser.add_argument('--all', dest='all',
        help='Generate report with all source TFE components.',
        action='store_true')
    parser.add_argument('--registry-modules', dest='registry_modules',
        help='Generate report of Registry Modules and their VCS info.',
        action='store_true')
    parser.add_argument('--modules-in-workspaces', dest='modules_in_workspaces',
        help='Generate report of Modules used in Workspaces.',
        action='store_true')
    args = parser.parse_args()
    return args

def main():
    tfe_client = None
    reg_mod_report = []
    mods_in_ws_report = []

    for org in orgs:
        log.info(f"Instantiating API client for source TFE Org `{org}`.")
        tfe_client = pytfc.Client(hostname=SRC_TFE_HOSTNAME, token=SRC_TFE_TOKEN, org=org)
        
        if not args.all:
            if args.registry_modules:
                reg_mod_results = registry_modules_report(client=tfe_client)
                reg_mod_report.extend(reg_mod_results)
            if args.modules_in_workspaces:
                mods_in_ws_results = modules_in_workspaces_report(client=tfe_client)
                mods_in_ws_report.extend(mods_in_ws_results)
        else:
            # run everything
            reg_mod_results = registry_modules_report(client=tfe_client)
            reg_mod_report.extend(reg_mod_results)
            
            mods_in_ws_results = modules_in_workspaces_report(client=tfe_client)
            mods_in_ws_report.extend(mods_in_ws_results)

    
    # display the report results
    reg_mod_df = pd.DataFrame(reg_mod_report)
    print(tabulate(reg_mod_df, headers='keys', tablefmt='simple'))

    print('\n')

    mods_in_ws_df = pd.DataFrame(mods_in_ws_report)
    print(tabulate(mods_in_ws_df, headers='keys', tablefmt='simple'))

if __name__ == "__main__":
    # setup logging
    log = logging.getLogger(__name__)
    log_level = getattr(logging, LOG_LEVEL.upper())
    log.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)

    # parse and validate args
    args = parse_args()
    
    orgs = args.orgs
    if not isinstance(orgs, list):
        log.error(\
            "Must provide a list of Organizations with `--orgs` argument.")
        sys.exit(1)

    if not args.all:
        if not args.registry_modules\
            and not args.modules_in_workspaces:
                log.error(\
                    "Must provide a migration component argument(s). See `Usage` section of README.")
                sys.exit(1)
    
    main()
    
    log.debug("Finished report!")
    sys.exit(0)