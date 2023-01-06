# tfcmig
Tooling to migrate config from TFE to TFC.

## Setup
```shell
pip3 install pytfc

export SRC_TFE_HOSTNAME='<my-TFE-hostname>'
export SRC_TFE_TOKEN='<my-TFE-token>'
export SRC_TFE_ORG='<my-TFE-org>'

export DST_TFC_HOSTNAME='app.terraform.io'
export DST_TFC_TOKEN='<my-TFC-token>'
export DST_TFC_ORG='<my-TFC-org>'
```

## Usage
There are two arguments categories required to run the script:
1) **Action** - What component do you want to migrate?
2) **Scope** - Which Workspaces or _all_ Workspaces in an Org?

**Actions arguments**
- `--migrate-workspaces` - migrate Workspaces and their config (without the State files)
- `--migrate-all-states` - migrate all State files
- `--migrate-current-state` - migrate the current (latest) State file only

**Scope arguments**
- `--workspaces` - list of Workspace names separate by spaces (not commas)
- `--all-workspaces` - all Workspaces in the Organization

### Config File
Some components of Workspaces require a mapping of names or IDs from source
to destination in order to be properly migrated, such as:
- Agent Pool ID
- VCS OAuth Token ID
- SSH Key ID

Use the `--config-file` argument with a path to the JSON file.
See the [example template](./examples/tfcmig.json) for proper formatting and syntax.

## Examples

### Migrate Workspaces
```
> tfcmig.py --migrate-workspaces --workspaces ws1 ws2 ws3
```

### Migrate All State Files
```
> tfcmig.py --migrate-all-states --workspaces ws1 ws2 ws3
```

### Migrate Current State File
```
> tfcmig.py --migrate-current-states --workspaces ws1 ws2 ws3
```

### Using a Config File
```
> tfcmig.py --migrate-workspaces --workspaces ws1 ws2 ws3 --config-file 'tfcmig.json'
```
