import os
import sys
import logging
import argparse
import pytfc
import json
import ssl
import hashlib
import base64
from requests.exceptions import HTTPError


# Environment Variables
SRC_TFE_HOSTNAME = os.getenv('SRC_TFE_HOSTNAME')
SRC_TFE_TOKEN = os.getenv('SRC_TFE_TOKEN')
SRC_TFE_ORG = os.getenv('SRC_TFE_ORG')
SRC_TFE_VERIFY = os.getenv('SRC_TFE_VERIFY', False)

DST_TFC_HOSTNAME = os.getenv('DST_TFC_HOSTNAME', 'app.terraform.io')
DST_TFC_TOKEN = os.getenv('DST_TFC_TOKEN')
DST_TFC_ORG = os.getenv('DST_TFC_ORG')

# Constants
LOGGER = 'tfcmig'
ADD_USER_AGENT_HEADERS = True
USER_AGENT_HEADERS = {'User-Agent': 'Mozilla/5.0'}
PAGE_SIZE = 100


def migrate_all_states(src_client, dst_client, workspaces):
    logger = logging.getLogger(LOGGER)
    logger.info("Preparing to migrate all State Versions of Workspaces...")

    context = ssl.create_default_context()
    if SRC_TFE_VERIFY is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    ws_objects = _get_workspaces(client=src_client, workspaces=workspaces)
    total_ws = len(ws_objects)
    logger.info(f"Total Workspaces gathered: {total_ws}")

    for ws in ws_objects:
        src_state_versions = None
        dst_state_versions = None

        ws_name = ws['attributes']['name']
        logger.info(f"({ws_objects.index(ws) + 1}/{total_ws}) Migrating all State Versions for Workspace `{ws_name}`.")
        
        try:
            src_client.set_ws(name=ws_name)
        except Exception as e:
            logger.error(f"Unable to set Workspace `{ws_name}` on source API client.")
            logger.error(e)
            continue

        try:
            dst_client.set_ws(name=ws_name)
        except Exception as e:
            logger.error(f"Unable to set Workspace `{ws_name}` on destination API client.")
            logger.error(e)
            continue

        src_state_versions = src_client.state_versions.list_all()['data']
        logger.info(f"Total source State Versions found for `{ws_name}`: {len(src_state_versions)}")
        if len(src_state_versions) == 0:
            logger.info(f"Skipping `{ws_name}` as no states were found to migrate.")
            continue
        else:
            try:
                logger.info(f"Locking destination Workspace `{ws_name}` before state migration.")
                dst_client.workspaces.lock(reason='Locked by tfcmig for migration.')
            except HTTPError as e:
                if e.response.status_code == 409:
                    logger.warning(f"Detected destination Workspace `{ws_name}` already locked. Skipping out of precaution.")
                    continue

        dst_state_versions = dst_client.state_versions.list_all()['data']
        dst_sv_serials = [dst_sv['attributes']['serial'] for dst_sv in dst_state_versions]

        for src_sv in reversed(src_state_versions):
            src_state_url = src_sv['attributes']['hosted-state-download-url']
            
            if ADD_USER_AGENT_HEADERS:
                src_state_obj = src_client.state_versions.download(
                    url=src_state_url, context=context, headers=USER_AGENT_HEADERS)
            else:
                src_state_obj = src_client.state_versions.download(
                    url=src_state_url, context=context)
            
            src_state_json = json.loads(src_state_obj)
            src_state_serial = src_state_json['serial']
            src_state_lineage = src_state_json['lineage']

            if dst_sv_serials and src_state_serial <= dst_sv_serials[0]:
                logger.info(\
                    f"Skipping State Version `{src_state_serial}` in `{ws_name}` as it already exists or is older than the current.")
                continue

            src_state_hash = hashlib.md5()
            src_state_hash.update(src_state_obj)
            src_state_md5 = src_state_hash.hexdigest()
            src_state_b64 = base64.b64encode(src_state_obj).decode('utf-8')

            logger.info(f"Creating new State Version `{src_state_serial}` on Workspace `{ws_name}`.")
            dst_client.state_versions.create(serial=src_state_serial,
                lineage=src_state_lineage, md5=src_state_md5, state=src_state_b64)

        logger.info(f"Unlocking destination Workspace `{ws_name}` after state migration.")
        dst_client.workspaces.unlock()
        logger.info(f"Migration of State Versions for Workspace `{ws_name}` completed.")
    
    logger.info(f"Migration of all State Versions of Workspaces completed.")


def migrate_current_state(src_client, dst_client, workspaces):
    logger = logging.getLogger(LOGGER)
    logger.info("Preparing to migrate current State Version of Workspaces...")

    context = ssl.create_default_context()
    if SRC_TFE_VERIFY is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    ws_objects = _get_workspaces(client=src_client, workspaces=workspaces)
    total_ws = len(ws_objects)
    logger.info(f"Total Workspaces gathered: {total_ws}")

    for ws in ws_objects:
        src_sv = None
        
        ws_name = ws['attributes']['name']
        logger.info(f"({ws_objects.index(ws) + 1}/{total_ws}) Migrating current State Version for Workspace `{ws_name}`.")
        
        try:
            src_client.set_ws(name=ws_name)
        except Exception as e:
            logger.error(f"Unable to set source Workspace `{ws_name}`.")
            logger.error(e)
            continue
        
        try:
            dst_client.set_ws(name=ws_name)
        except Exception as e:
            logger.error(f"Unable to set destination Workspace `{ws_name}`.")
            logger.error(e)
            continue

        try:
            logger.debug(f"Getting current State Version from source `{ws_name}`.")
            src_sv = src_client.state_versions.get_current().json()
        except HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"No State Version found in source `{ws_name}`. Skipping.")
                continue

        src_sv_serial = src_sv['data']['attributes']['serial']

        dst_sv_list = dst_client.state_versions.list_all()['data']
        dst_sv_serials = [dst_sv['attributes']['serial'] for dst_sv in dst_sv_list]
        
        if dst_sv_serials and src_sv_serial <= dst_sv_serials[0]:
            logger.info(f"Skipping `{ws_name}` as source State Version is older than or equal to destination.")
            continue
        else:
            try:
                logger.info(f"Locking destination Workspace `{ws_name}` before state migration.")
                dst_client.workspaces.lock(reason='Locked by tfcmig for migration.')
            except HTTPError as e:
                if e.response.status_code == 409:
                    logger.warning(f"Detected destination Workspace `{ws_name}` already locked. Skipping out of precaution.")
                    continue

        src_state_url = src_sv['data']['attributes']['hosted-state-download-url']
        
        if ADD_USER_AGENT_HEADERS:
            src_state_obj = src_client.state_versions.download(
                url=src_state_url, context=context, headers=USER_AGENT_HEADERS)
        else:
            src_state_obj = src_client.state_versions.download(
                url=src_state_url, context=context)

        src_state_json = json.loads(src_state_obj)
        src_state_serial = src_state_json['serial']
        src_state_lineage = src_state_json['lineage']

        src_state_hash = hashlib.md5()
        src_state_hash.update(src_state_obj)
        src_state_md5 = src_state_hash.hexdigest()
        src_state_b64 = base64.b64encode(src_state_obj).decode('utf-8')

        logger.info(f"Creating new State Version `{src_state_serial}` on Workspace `{ws_name}`.")
        dst_client.state_versions.create(serial=src_state_serial,
            lineage=src_state_lineage, md5=src_state_md5, state=src_state_b64)

        logger.info(f"Unlocking destination Workspace `{ws_name}` after state migration.")
        dst_client.workspaces.unlock()
        
    logger.info(f"Migration of current State Versions completed.")

def _get_workspaces(client, workspaces):
    logger = logging.getLogger(LOGGER)
    ws_objects = []

    if workspaces != 'all':
        logger.info(f"Gathering specified Workspaces in `{client.org}` Org.")
        if not isinstance(workspaces, list):
            logger.error("Must provide a list of Workspaces when using `--workspaces` arg.")
        for ws in workspaces:
            try:
                ws_obj = client.workspaces.show(name=ws).json()['data']
                ws_objects.append(ws_obj)
            except Exception as e:
                logger.error(f"Error retrieving info for Workspace `{ws}`. Please verify name and existence.")
                logger.error(e)
                continue
    elif workspaces == 'all':
        logger.info(f"Gathering all Workspaces in `{client.org}` Org.")
        ws_objects = client.workspaces.list_all()['data']
    else:
        logger.error("A Workspaces argument was not specified.")

    return ws_objects


def parse_args():
    parser = argparse.ArgumentParser(description='TFC/E arguments for script.')
    parser.add_argument('--log-level', dest='log_level', default='INFO',
        help='Log level for script output.')
    parser.add_argument('--workspaces', dest='workspaces', nargs='*',
        help='List of source TFE Workspace names to migrate.')
    parser.add_argument('--all-workspaces', dest='all_workspaces',
        help='Migrate all source TFE Workspaces in the Organzation.',
        action='store_true')
    parser.add_argument('--migrate-current-state', dest='migrate_current_state',
        help='Migrate current state of Workspaces in the Organzation.',
        action='store_true')
    parser.add_argument('--migrate-all-states', dest='migrate_all_states',
        help='Migrate all states of Workspaces in the Organzation.',
        action='store_true')
    
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    # set up logging
    logger = logging.getLogger(LOGGER)
    log_level = getattr(logging, args.log_level.upper())
    logger.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # validate Workspace args
    if args.migrate_current_state or args.migrate_all_states:
        if not args.workspaces and not args.all_workspaces:
            logger.error("Either `--workspaces` or `--all-workspaces` argument is required.")
            sys.exit(1)
        elif args.workspaces:
            workspaces = args.workspaces
        elif args.all_workspaces:
            workspaces = 'all'
        else:
            logger.error("Unexpected error occured parsing Workspace arguments.")
            sys.exit(1)
    else:
        logger.error("Either `--migrate-current-state` or `--migrate-all-states` argument is required.")
        sys.exit(1)

    # instantiate API clients
    logger.info("Instantiating API client for source TFE.")
    src_client = pytfc.Client(hostname=SRC_TFE_HOSTNAME, token=SRC_TFE_TOKEN, org=SRC_TFE_ORG, log_level="DEBUG")
    logger.info("Instantiating API client for destination TFC.")
    dst_client = pytfc.Client(hostname=DST_TFC_HOSTNAME, token=DST_TFC_TOKEN, org=DST_TFC_ORG)

    # route to functions to do migration work
    if args.migrate_current_state:
        migrate_current_state(src_client, dst_client, workspaces)
    elif args.migrate_all_states:
        migrate_all_states(src_client, dst_client, workspaces)
    else:
        logger.error("Either `--migrate-current-state` or `--migrate-all-states` argument is required.")
        sys.exit(2)

    logger.info("Finished!")
    sys.exit(0)


if __name__ == "__main__":
    main()
    