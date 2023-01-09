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


def migrate_workspaces(src_client, dst_client, workspaces, config=None):
    logger = logging.getLogger(LOGGER)
    logger.info("Preparing to migrate Workspaces...")

    src_workspaces = _get_workspaces(client=src_client, workspaces=workspaces)
    total_ws = len(src_workspaces)
    logger.info(f"Total Workspaces gathered: {total_ws}")

    src_latest_tf_version = src_client.admin_terraform_versions.list().json()\
        ['data'][0]['attributes']['version']
    
    for src_ws in src_workspaces:
        src_ws_id = src_ws['id']
        src_ws_name = src_ws['attributes']['name']
        logger.info(f"({src_workspaces.index(src_ws) + 1}/{total_ws})"
                    f" Migrating Workspace `{src_ws_name}`.")

        dst_name = src_ws_name
        
        # --- handle VCS integration --- #
        if src_ws['attributes']['vcs-repo'] is None\
            and src_ws['attributes']['vcs-repo-identifier'] is None:
            dst_vcs_identifier = None
            dst_vcs_oauth_token_id = None
            dst_vcs_branch = None
            dst_vcs_ingress_submodules = None
            dst_vcs_tags_regex = None
        else:
            try:
                config['vcs_oauth_token_ids']
            except KeyError:
                logger.error("Detected VCS repo on src Workspace but no config mapping was provided.")
                logger.error(f"Skipping `{src_ws_name}`.")
                break
            dst_vcs_oauth_token_id = None
            for i in config['vcs_oauth_token_ids']:
                if dst_vcs_oauth_token_id is not None:
                    break
                for k, v in i.items():
                    if src_ws['attributes']['vcs-repo']['oauth-token-id'] == k:
                        dst_vcs_oauth_token_id = v
                        break
                    else:
                        dst_vcs_oauth_token_id = None

            if dst_vcs_oauth_token_id == "None":
                dst_vcs_identifier = None
                dst_vcs_oauth_token_id = None
                dst_vcs_branch = None
                dst_vcs_ingress_submodules = None
                dst_vcs_tags_regex = None
            else:
                dst_vcs_identifier = src_ws['attributes']['vcs-repo']['identifier']
                dst_vcs_branch = src_ws['attributes']['vcs-repo']['branch']
                dst_vcs_ingress_submodules = src_ws['attributes']['vcs-repo']['ingress-submodules']
                dst_vcs_tags_regex = src_ws['attributes']['vcs-repo']['tags-regex']

        # --- handle Agent Pool ID --- #
        dst_agent_pool_id = None
        try:
            src_agent_pool_id = src_ws['relationships']['agent-pool']['data']['id']
        except TypeError:
            src_agent_pool_id = None

        if src_agent_pool_id is None:
            dst_agent_pool_id = None
        else:
            try:
                config['agent_pool_ids']
            except KeyError:
                logger.error("Detected Agent Pool on src Workspace but no config"
                            f" mapping was provided. Skipping `{src_ws_name}`.")
                break
            for i in config['agent_pool_ids']:
                if dst_agent_pool_id is not None:
                    break
                for k, v in i.items():
                    if src_ws['relationships']['agent-pool']['data']['id'] == k:
                        dst_agent_pool_id = v
                        break
                    else:
                        dst_agent_pool_id = None
        
        # --- handle Terraform Version --- #
        dst_terraform_version = src_ws['attributes']['terraform-version']
        if dst_terraform_version == 'latest':
            logger.debug("Found src Workspace Terraform version was set to `latest`.")
            logger.debug("Setting to latest available version from src TFE"
                         f" `{src_latest_tf_version}` in dst.")
            dst_terraform_version = src_latest_tf_version

        # --- handle regular attributes --- #
        dst_allow_destroy_plan = src_ws['attributes']['allow-destroy-plan']
        dst_auto_apply = src_ws['attributes']['auto-apply']
        dst_description = src_ws['attributes']['description']
        dst_execution_mode = src_ws['attributes']['execution-mode']
        dst_file_triggers_enabled = src_ws['attributes']['file-triggers-enabled']
        dst_global_remote_state = src_ws['attributes']['global-remote-state']
        dst_queue_all_runs = False # hard-coded for now

        try:
            dst_source_name = src_ws['attributes']['source-name']
        except KeyError:
            dst_source_name = None
        try:
            dst_source_url = src_ws['attributes']['source-url']
        except KeyError:
            dst_source_url = None
        
        dst_speculative_enabled = src_ws['attributes']['speculative-enabled']
        dst_trigger_prefixes = src_ws['attributes']['trigger-prefixes']
        dst_trigger_patterns = src_ws['attributes']['trigger-patterns']
        dst_working_directory = src_ws['attributes']['working-directory']

        try:
            dst_assessments_enabled = src_ws['attributes']['assessments-enabled']
        except KeyError:
            dst_assessments_enabled = False

        # --- check if dst Workspace exists --- #
        try:
            dst_ws = dst_client.workspaces.show(name=dst_name)
            dst_ws_exists = True
            logger.info(f"Detected dst Workspace `{dst_name}` already exists.")
        except HTTPError as e:
            if e.response.status_code == 404:
                dst_ws_exists = False
                logger.info(f"Detected dst Workspace `{dst_name}` does not yet exist.")
            else:
                logger.error("An unexpected error has occured.")
                logger.error(e)

        # --- create/update dst Workspace --- #
        if dst_ws_exists == False:
            dst_ws = dst_client.workspaces.create(
                name = dst_name,
                agent_pool_id = dst_agent_pool_id,
                allow_destroy_plan = dst_allow_destroy_plan,
                auto_apply = dst_auto_apply,
                description = dst_description,
                execution_mode = dst_execution_mode,
                file_triggers_enabled = dst_file_triggers_enabled,
                global_remote_state = dst_global_remote_state,
                queue_all_runs = dst_queue_all_runs, 
                source_name = dst_source_name, # beta
                source_url = dst_source_url, # beta
                speculative_enabled = dst_speculative_enabled,
                terraform_version = dst_terraform_version,
                trigger_prefixes = dst_trigger_prefixes,
                trigger_patterns = dst_trigger_patterns,
                identifier = dst_vcs_identifier, # vcs
                oauth_token_id = dst_vcs_oauth_token_id, # vcs
                branch = dst_vcs_branch, # vcs
                ingress_submodules = dst_vcs_ingress_submodules, # vcs
                tags_regex = dst_vcs_tags_regex, # vcs
                working_directory = dst_working_directory,
                assessments_enabled = dst_assessments_enabled
            )
        elif dst_ws_exists == True:
            dst_client.workspaces.update(
                name = dst_name,
                agent_pool_id = dst_agent_pool_id,
                allow_destroy_plan = dst_allow_destroy_plan,
                auto_apply = dst_auto_apply,
                description = dst_description,
                execution_mode = dst_execution_mode,
                file_triggers_enabled = dst_file_triggers_enabled,
                global_remote_state = dst_global_remote_state,
                queue_all_runs = dst_queue_all_runs, 
                source_name = dst_source_name, # beta
                source_url = dst_source_url, # beta
                speculative_enabled = dst_speculative_enabled,
                terraform_version = dst_terraform_version,
                trigger_prefixes = dst_trigger_prefixes,
                trigger_patterns = dst_trigger_patterns,
                identifier = dst_vcs_identifier, # vcs
                oauth_token_id = dst_vcs_oauth_token_id, # vcs
                branch = dst_vcs_branch, # vcs
                ingress_submodules = dst_vcs_ingress_submodules, # vcs
                tags_regex = dst_vcs_tags_regex, # vcs
                working_directory = dst_working_directory,
                assessments_enabled = dst_assessments_enabled
            )

        dst_ws_id = dst_ws.json()['data']['id']
        dst_ws_name = dst_name
        
        # --- handle Workspace Variables --- #
        src_ws_vars = src_client.workspace_variables.list(ws_id=src_ws_id).json()['data']
        dst_ws_vars = dst_client.workspace_variables.list(ws_id=dst_ws_id).json()['data']

        logger.info(f"Copying Workspace Variables for `{src_ws_name}`.")
        for src_var in src_ws_vars:
            dst_var_key = src_var['attributes']['key']
            dst_var_value = src_var['attributes']['value']
            dst_var_description = src_var['attributes']['description']
            dst_var_category = src_var['attributes']['category']
            dst_var_hcl = src_var['attributes']['hcl']
            dst_var_sensitive = src_var['attributes']['sensitive']
        
            if any(dst_var_key in i['attributes']['key'] for i in dst_ws_vars):
                logger.info(f"Detected variable `{dst_var_key}` already exists in dst Workspace. Skipping.")
                continue

            logger.info(f"Copying variable `{dst_var_key}`.")
            if dst_var_value is None:
                logger.warning(f"Detected variable `{dst_var_key}` has a sensitive or null value.")
            
            dst_client.workspace_variables.create(
                key = dst_var_key,
                value = dst_var_value,
                description = dst_var_description,
                category = dst_var_category,
                hcl = dst_var_hcl,
                sensitive = dst_var_sensitive,
                ws_id = dst_ws_id
            )

        # --- handle SSH Key assignment --- #
        try:
            src_ws_ssh_key_id = src_ws['relationships']['ssh-key']['data']['id']
        except KeyError:
            src_ws_ssh_key_id = None

        if src_ws_ssh_key_id is not None:
            logger.info(f"Assigning equivalent SSH Key for `{dst_ws_name}`.")
            try:
                config['ssh_key_ids']
            except KeyError:
                logger.error("Detected SSH Key assigned to src Workspace but" 
                             " no config mapping was provided. Skipping.")
                break
            dst_ws_ssh_key_id = None
            for i in config['ssh_key_ids']:
                if dst_ws_ssh_key_id is not None:
                    break
                for k, v in i.items():
                    if src_ws_ssh_key_id == k:
                        dst_ws_ssh_key_id = v
                        logger.info(f"Assigning `{dst_ws_ssh_key_id}` to `{dst_ws_name}`.")
                        dst_client.workspaces.assign_ssh_key(ssh_key_id=dst_ws_ssh_key_id,
                                                             name=dst_ws_name)
                        break
                    # else:
                    #     dst_ws_ssh_key_id = None
        
        # --- handle Notifications --- #
        # src_ws_nc_list = src_client.notification_configurations.list(ws_id=src_ws_id).json()['data']
        # dst_ws_nc_list = dst_client.notification_configurations.list(ws_id=dst_ws_id).json()['data']
        
        # if src_ws_nc_list != []:
        #     for src_nc in src_ws_nc_list:
        #         dst_nc_name = src_nc['attributes']['name']
        #         if any(dst_nc_name in i['attributes']['name'] for i in dst_ws_nc_list):
        #             logger.warning(f"Skipping {dst_nc_name} already exists.")
        #         else:
        #             dst_nc_destination_type = src_nc['attributes']['destination-type']
        #             dst_nc_enabled = src_nc['attributes']['enabled']
        #             dst_nc_triggers = src_nc['attributes']['triggers']
                    
        #             try:
        #                 dst_nc_token = src_nc['attributes']['token']
        #             except KeyError:
        #                 dst_nc_token = None

        #             try:
        #                 dst_nc_url = src_nc['attributes']['url']
        #             except KeyError:
        #                 dst_nc_url = None

        #             try:
        #                 dst_nc_users = src_nc['relationships']['users']['data']
        #             except KeyError:
        #                 dst_nc_users = None

        #             dst_nc_users_list = []
        #             if dst_nc_users != [] or dst_nc_users != None:
        #                 for u in dst_nc_users:
        #                     dst_nc_users_list.append(u['id'])
        #             else:
        #                 dst_nc_users_list = None

        #             dst_client.notification_configurations.create(
        #                 name = dst_nc_name,
        #                 destination_type = dst_nc_destination_type,
        #                 enabled = dst_nc_enabled,
        #                 token = dst_nc_token,
        #                 triggers = dst_nc_triggers,
        #                 url = dst_nc_url,
        #                 users = dst_nc_users_list, # config mapping of User IDs required
        #                 ws_id = dst_ws_id
        #             )

        # --- Team Access --- #


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
        logger.info(f"Gathering specified src Workspaces in `{client.org}` Org.")
        if not isinstance(workspaces, list):
            logger.error("Must provide a list of src Workspaces when using `--workspaces` arg.")
        for ws in workspaces:
            try:
                ws_obj = client.workspaces.show(name=ws).json()['data']
                ws_objects.append(ws_obj)
            except Exception as e:
                logger.error(f"Error finding src Workspace `{ws}`. Please verify name and existence.")
                logger.error(e)
                continue
    elif workspaces == 'all':
        logger.info(f"Gathering all src Workspaces in `{client.org}` Org.")
        ws_objects = client.workspaces.list_all()['data']
    else:
        logger.error("A Workspaces scope argument was not specified. Either"
                     " `--workspaces <list>` or `--all-workspaces` is required.")

    return ws_objects

def parse_args():
    parser = argparse.ArgumentParser(description='TFC/E arguments for script.')
    parser.add_argument('--migrate-current-state', dest='migrate_current_state',
        help='Migrate current state of Workspaces specified.',
        action='store_true')
    parser.add_argument('--migrate-all-states', dest='migrate_all_states',
        help='Migrate all states of Workspaces specified.',
        action='store_true')
    parser.add_argument('--migrate-workspaces', dest='migrate_workspaces',
        help='Migrate Workspaces specified.',
        action='store_true')
    parser.add_argument('--workspaces', dest='workspaces', nargs='*',
        help='Scope a list of source Workspace names within the Org into the migrate action.')
    parser.add_argument('--all-workspaces', dest='all_workspaces',
        help='Scope all source Workspaces within the Org into the migrate action.',
        action='store_true')
    parser.add_argument('--config-file', dest='config_file',
        help='Path to config file with ID mappings.')
    parser.add_argument('--log-level', dest='log_level', default='INFO',
        help='Log level for script output.')
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
    #formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s')
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # validate Workspace args
    if args.migrate_current_state or args.migrate_all_states or args.migrate_workspaces:
        if not args.workspaces and not args.all_workspaces:
            logger.error("Either `--workspaces` or `--all-workspaces` argument"
                         " is required for Workspaces scope.")
            sys.exit(1)
        elif args.workspaces:
            workspaces = args.workspaces
        elif args.all_workspaces:
            workspaces = 'all'
        else:
            logger.error("Unexpected error occured parsing Workspace arguments.")
            sys.exit(1)
    else:
        logger.error("Either `--migrate-current-state`, `--migrate-all-states`,"
                     " or `--migrate-workspaces` argument is required.")
        sys.exit(1)

    # instantiate API clients
    logger.info("Instantiating API client for source TFE.")
    src_client = pytfc.Client(hostname=SRC_TFE_HOSTNAME, token=SRC_TFE_TOKEN, org=SRC_TFE_ORG)
    logger.info("Instantiating API client for destination TFC.")
    dst_client = pytfc.Client(hostname=DST_TFC_HOSTNAME, token=DST_TFC_TOKEN, org=DST_TFC_ORG, log_level='DEBUG')

    # import config file
    config = None
    if args.config_file:
        try:
            f = open(args.config_file)
            config = json.load(f)
        except Exception as e:
            logger.error("Unable to import config file.")
            logger.error(e)

    # route to functions to do migration work
    if args.migrate_current_state:
        migrate_current_state(src_client, dst_client, workspaces)
    elif args.migrate_all_states:
        migrate_all_states(src_client, dst_client, workspaces)
    elif args.migrate_workspaces:
        migrate_workspaces(src_client, dst_client, workspaces, config)
    else:
        logger.error("One action argument is required: "
                     " `--migrate-current-state`, `--migrate-all-states`, `--migrate-workspaces`.")
        sys.exit(2)

    logger.info("Finished!")
    sys.exit(0)


if __name__ == "__main__":
    main()
    