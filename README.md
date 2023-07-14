# cf-asg-extractor

Extract ASG details from a running CF install via the v3 API.

## Usage

You must export the API endpoint as `CF_ENDPOINT`.

User credentials can either be passed in via `` and `` environmental variables or the can be entered interactively.

A file called output.json will be created in the script directory.

```
$  python3 cf_asg_extractor.py 
Enter username: admin
Password: 
Collected organisation apping
Collected space mapping
Collected ASG: default_security_group
Collected ASG: sg1
Written file: ./cf-asg-munger/output.json
```