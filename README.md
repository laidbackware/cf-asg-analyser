# cf-asg-extractor

Extract ASG details from a running CF install via the v3 API.

## How to run

  - **Interpreter:** Requires Python 3.6. Install all dependencies with `pip install cloudfoundry-client`.
  - **Binary:** Download from the [releases page](https://github.com/laidbackware/cf-asg-extractor/releases/latest)

## Usage

You must export the API endpoint as `CF_ENDPOINT`.

User credentials can either be passed in via `CF_USER` and `CF_PASS` environmental variables or the can be entered interactively.


```
$  python3 cf_asg_extractor.py 
Enter username: admin
Password: 
Collected organisation mapping
Collected space mapping
Collected ASG: default_security_group
Collected ASG: sg1
Written file: /home/user/cf-asg-munger/output.json
```

A file called output.json will be created in the script directory.