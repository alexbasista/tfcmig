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
2) **Scope** - Which Workspaces do you want to migrate (within an Org)?

**Actions arguments**
- `--migrate-workspaces` - migrate Workspaces and their config (without the State files)
- `--migrate-all-states` - migrate all State files
- `--migrate-current-state` - migrate the current (latest) State file only

**Scope arguments**
- `--workspaces` - list of Workspace names separate by spaces (not commas)
- `--all-workspaces` - all Workspaces in the Organization

**Config File (optional)**
Some components of Workspaces require a mapping of names or IDs from source
to destination in order to be properly migrated, such as:
- VCS OAuth Token ID
- Agent Pool ID
- SSH Key ID

Use the `--config-file` argument with a path to the JSON file containing the mappings.
See the [example template](./examples/tfcmig.json) for proper formatting and syntax.

### Order of Ops

#### 1) Migrate Workspaces
```
> tfcmig.py --migrate-workspaces --workspaces ws1 ws2 ws3
```

or with the optional config file:

```
> tfcmig.py --migrate-workspaces --workspaces ws1 ws2 ws3 --config-file 'tfcmig.json'
```

#### 2) Migrate All State Files
```
> tfcmig.py --migrate-all-states --workspaces ws1 ws2 ws3
```


## What's Not Supported
- **Workspace Team Access** - _work in progress_
- **Variable Sets** - _planned_
- **Run Triggers** - _planned_
- **Run Tasks** - _unplanned_
