'''Pull and anonymise asg data from CF'''
import getpass, json, os, sys
from hashlib import md5
from cloudfoundry_client.client import CloudFoundryClient
import requests

# v2 features
# extract org list
# extract default asg under dedicated section

try:
  from urllib3.exceptions import InsecureRequestWarning

  # Suppress the warnings from urllib3
  requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
except Exception as e:
  pass

if os.environ.get('CF_ENDPOINT') is None:
  print("You must export the CF API endpoint as CF_ENDPOINT", file=sys.stderr)
  sys.exit(1)

TARGET_ENDPOINT = os.environ.get('CF_ENDPOINT')
proxy = {'http': os.environ.get('HTTP_PROXY', ''), 'https': os.environ.get('HTTPS_PROXY', '')}
client = CloudFoundryClient(TARGET_ENDPOINT, proxy=proxy, verify=False)

if os.environ.get('CF_USER') is not None and os.environ.get('CF_PASS') is not None:
  client.init_with_user_credentials(
    os.environ.get('CF_USER'), os.environ.get('CF_PASS')
  )
else:
  client.init_with_user_credentials(input("Enter username: "), getpass.getpass())

org_name_lookup = {}
orgs = client.v3.organizations.list()
for org in orgs:
  org_name_lookup[org['guid']] = org['name']
print("Collected organisation mapping")

space_name_lookup = {}
spaces = client.v3.spaces.list()
for space in spaces:
  space_name_lookup[space['guid']] = \
    f"{org_name_lookup[space['relationships']['organization']['data']['guid']]}_{space['name']}"
print("Collected space mapping")

asgs = client.v3.security_groups.list()
asg_list = []

def return_content(lookup_dict, lookup_string):
  '''Return value or empty'''
  if not lookup_string in lookup_dict:
    return ""
  return lookup_dict[lookup_string]

for asg in asgs:

  # Map relationships to org and space
  asg_relationships = set()
  for relationship in asg['relationships']['running_spaces']['data']:
    asg_relationships.add(space_name_lookup[relationship['guid']])
  for relationship in asg['relationships']['staging_spaces']['data']:
    asg_relationships.add(space_name_lookup[relationship['guid']])

  rule_list = []
  # Anomise IP addresses
  for rule in asg['rules']:
    rule_list.append(
      {
        "description": return_content(rule, 'description'),
        "ports": return_content(rule, 'ports'),
        "protocol": rule['protocol'],
        "destination": md5(rule['destination'].encode('utf-8')).hexdigest(),
      }
    )

  asg_list.append(
    {
      "asg_name": asg['name'],
      "spaces": list(sorted(asg_relationships)),
      "rules": rule_list
    }
  )

  print(f"Collected ASG: {asg['name']}")

# output_string = json.loads(asg_list)
if getattr(sys, 'frozen', False):
  script_dir = os.path.dirname(sys.executable)
else:
  script_dir = os.path.dirname(os.path.realpath(__file__))
output_file_path = os.path.join(script_dir, "output.json")
with open(output_file_path,'w', encoding='UTF-8') as open_file:
  json.dump(asg_list, open_file, indent=2)
print(f"Written file: {output_file_path}")
