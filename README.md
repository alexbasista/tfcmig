# tfcmig
Tooling to migrate config from TFE to TFC.

## Usage

### Migrate All States

#### All Workspaces
```
> tfcmig.py --migrate-all-states --all-workspaces
```

#### Select Workspaces
```
> tfcmig.py --migrate-all-states --workspaces ws1, ws2, ws3
```

### Migrate Current State

#### All Workspaces
```
> tfcmig.py --migrate-current-state --all-workspaces
```

#### Select Workspaces
```
> tfcmig.py --migrate-current-state --workspaces ws1, ws2, ws3
```