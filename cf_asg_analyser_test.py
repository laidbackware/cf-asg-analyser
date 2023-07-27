'''Test cf_asg_optimiser'''
import os
import json

import cf_asg_analyser as cfa

base_dir = os.path.dirname(os.path.realpath(__file__))

DUMMY_FILE = os.path.join(base_dir, "test", "dummy.json")

asg = {
    "spaces": [
      "o1_s1",
      "o1_s2",
      "o1_s3",
      "o2_s4",
    ]
  }

# org_data = {
#    "o1": {

#    }
# }

with open(DUMMY_FILE, encoding="utf-8") as open_file:
  asg_data = json.load(open_file)
  print(asg_data)

def test_parse_args():
  '''Ensure runs e2e without error'''
  covered_by_defaults, _ = cfa.parse_asgs(asg_data)

  assert len(covered_by_defaults) == 1, "Detected too many rules covered by default"

def test_extract_org_space_numbers():
  resp = cfa.extract_org_space_numbers(asg_data)

  assert "o1" in resp

# def test_extract_org_space_dict():
#    resp = cfa.extract_org_space_dict(asg_data[5])
#    assert len(resp) == 2
#    assert type(resp["o3"]) == list and len(resp["o3"]) == 3
#    assert resp["o4"] == ["s4"]

def test_assign_rule_org_mapping():
  rule_string = "destination_protocol_ports"
  org_data = {
    "o3": {"rules": {}},
    "o4": {"rules": {}}
  }
  cfa.assign_rule_org_mapping(org_data, asg_data[5], f"{rule_string}_1")
  cfa.assign_rule_org_mapping(org_data, asg_data[5], f"{rule_string}_2")

  assert len(org_data["o3"]["rules"]) == 2

def test_look_for_common_org_rules():
  _, org_data = cfa.parse_asgs(asg_data)
  org_common_saving = cfa.look_for_common_org_rules(org_data)
  assert org_common_saving == 8
