# Discovery Script
`tfcmig_discovery.py` queries the source TFE instance and generates a report
that will assist in migration planning and execution.

## Setup
```shell
pip3 install pytfc

export SRC_TFE_HOSTNAME='<my-TFE-hostname>'
export SRC_TFE_TOKEN='<my-TFE-token>'
```

## Usage
- A list of Organizations via the `--orgs` argument is required.
- At least one additional flag is required to tell the script which TFE
  components to report on (see subsections below)
- For a full report, pass the `--all` flag instead of individual components:
  
  ```shell
  > tfcmig_discovery.py --orgs org1 org2 org3 --all
  ```

### Registry Modules
```python
> tfcmig_discovery.py --orgs org1 org2 org3 --registry-modules
```