# Discovery Script
`tfcmig_discovery.py` queries the source TFE instance and generates a report
that will assist in migration planning and execution.

## Setup
```shell
pip3 install pytfc, tabulate

export SRC_TFE_HOSTNAME='<my-TFE-hostname>'
export SRC_TFE_TOKEN='<my-TFE-token>'
```

## Usage
Specify a flag for at least one report to generate, as well as one or
more Organizations to query via the `--orgs` argument. For example:

```shell
> tfcmig_discovery.py --registry-modules --orgs myorg1 myorg2 myorg3
```

You can also pass the `--all` flag to run all of the available reports:

```shell
> tfcmig_discovery.py --all --orgs myorg1 myorg2 myorg3
```

## Available Reports
Below are the reports that can be generated either alone or in tandem with others.

### Registry Modules in Organization(s)
```shell
> tfcmig_discovery.py --registry-modules --orgs myorg1 myorg2 myorg3
```

### Module Sources in Workspaces
```shell
> tfcmig_discovery.py --module-sources-in-workspaces --orgs myorg1 myorg2 myorg3
```

### Module Calls in Workspaces
```shell
> tfcmig_discovery.py --module-calls-in-workspaces --orgs myorg1 myorg2 myorg3
```