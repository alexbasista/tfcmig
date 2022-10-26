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

### Migrate All States

#### All Workspaces
```
> tfcmig.py --migrate-all-states --all-workspaces
```

#### Select Workspaces
```
> tfcmig.py --migrate-all-states --workspaces ws1 ws2 ws3
```

### Migrate Current State

#### All Workspaces
```
> tfcmig.py --migrate-current-state --all-workspaces
```

#### Select Workspaces
```
> tfcmig.py --migrate-current-state --workspaces ws1 ws2 ws3
```

## Troubleshooting
- If you have more than 100 Workspaces in your Org and you are using the `--all-workspaces` arg, modify the value of `PAGE_SIZE` contstant at the top of the script to the total number of Workspaces in your Org.