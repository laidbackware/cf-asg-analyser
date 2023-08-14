# cf-asg-analyser

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

Run the analyser against the output file;

```
------------Source data-------------
Source number of ASGs: 7
Source number of rules 19
Source number of unbound ASGs: 1
Source number of rules in unbound ASGs: 2
Source number of ASGs with more than 100 rules: 0
Source number of rules in the largest asg: 4
Number rules covered by the default ASG: 1
------------------------------------
----------Large ASGs----------------
------------------------------------
----------Per Org ASG---------------
Number of rules that could be covered by common org ASG: 4
Number of common ASGs to be created: 1
Number of common rules within common ASGs to be created: 2
------------------------------------
----------Destination lists---------
Number of rules to be saved be destination lists: 1
------------------------------------
----------Final rule count----------
Target number of ASGs: 7
Target number of rules: 11
Target number of ASGs with more than 100 rules: 0
Target number of rules in the largest asg: 2
------------------------------------
```

## Development

### Testing
Requires `pytest`, installed via `pip install pytest`.

Run `pytest` from the root of the repo.

### Build
The extractor can be built to a single executable. Requires `pyinstaller`. Instructions cover Linux, but `pyinstaller` is multiplatform.

Run with `pyinstaller cf_asg_extracter.spec`

### Build with older Python version
Export Docker hub tag for python version `export PYTHON_VERSION=3.7.3-stretch`.

```
docker run -v .:/work python:3.7.3-stretch sh -c \
  'pip install urllib3==1.26.16 cloudfoundry-client pyinstaller &&
  cd /work &&
  pyinstaller cf_asg_extractor.spec'
```
