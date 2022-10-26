import os
import sys
import logging
import argparse
import pytfc
import pandas as pd


# Environment Variables
SRC_TFE_HOSTNAME = os.getenv('SRC_TFE_HOSTNAME')
SRC_TFE_TOKEN = os.getenv('SRC_TFE_TOKEN')
SRC_TFE_ORG = os.getenv('SRC_TFE_ORG')
SRC_TFE_VERIFY = os.getenv('SRC_TFE_VERIFY', False)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')


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
        help='Generate report of Registry Modules.',
        action='store_true')
    
    args = parser.parse_args()
    return args

def main():
    tfe_client = None
    report = []

    for org in orgs:
        log.info(f"Instantiating API client for source TFE Org `{org}`.")
        tfe_client = pytfc.Client(hostname=SRC_TFE_HOSTNAME, token=SRC_TFE_TOKEN, org=org)
        
        if not args.all:
            registry_results = registry_modules_report(client=tfe_client)
            report.extend(registry_results)
        else:
            # run everything
            registry_results = registry_modules_report(client=tfe_client)
            report.extend(registry_results)
    
    # display the report results
    df = pd.DataFrame(report)
    print(df)

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
        if not args.registry_modules:
            log.error(\
                "Must provide a migration component argument(s). See `Usage` section of README.")
            sys.exit(1)
    
    main()
    
    log.debug("Finished report!")
    sys.exit(0)