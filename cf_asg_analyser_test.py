'''Test cf_asg_optimiser'''
import os
import json

import cf_asg_analyser as cfa

base_dir = os.path.dirname(os.path.realpath(__file__))

DUMMY_FILE = os.path.join(base_dir, "test", "dummy.json")
DUMMY_FILE = os.path.join(base_dir, "ignored", "nwg-dev01.json")

asg = {
    "spaces": [
      "o1_s1",
      "o1_s2",
      "o1_s3",
      "o2_s4",
    ]
  }


with open(DUMMY_FILE, encoding="utf-8") as open_file:
  asg_data = json.load(open_file)
  # print(asg_data)

def test_e2e():
  cfa.main(DUMMY_FILE)

def test_combine_rules_per_org():
  '''Ensure runs e2e without error'''
  org_common_saving, mod_org_data, mod_asg_data = cfa.combine_rules_per_org(asg_data)

  assert org_common_saving == 4
  assert len(mod_asg_data[1]["rules"]) == 1

  assert len(mod_asg_data) == 8

def test_check_default_coverage():
  covered_by_defaults, mod_asg_data = cfa.check_default_coverage(asg_data)

  assert len(covered_by_defaults) == 1, "Detected too many rules covered by default"
  assert len(mod_asg_data[3]["rules"]) == 3

def test_remove_unbound_asgs():
  unbound_asgs, unbound_asg_rules, mod_asg_data, unbound_asg_list = cfa.remove_unbound_asgs(asg_data)

  assert unbound_asgs == 1, "Detected too many rules covered by default"
  assert unbound_asg_rules == 3, "Detected too many rules covered by default"
  assert len(mod_asg_data) == 6
  assert len(unbound_asg_list) == 1 and unbound_asg_list[0] == "sg_-unbound"

def test_find_large_asgs():
  large_asgs, largest_asg, org_common_asgs = cfa.find_large_asgs(asg_data)
  assert large_asgs == 0 and largest_asg == 4

def test_extract_org_data():
  org_data = cfa.extract_org_data(asg_data)

  assert "o1" in org_data
  assert org_data["o1"]["asgs"] == 3

def test_assign_rule_org_mapping():
  rule_string = "destination_protocol_ports"
  org_data = {
    "o3": {"rules": {}, "asgs": 0},
    "o4": {"rules": {}, "asgs": 0}
  }
  cfa.assign_rule_org_mapping(org_data, asg_data[5], f"{rule_string}_1", 0, 0)
  cfa.assign_rule_org_mapping(org_data, asg_data[5], f"{rule_string}_2", 1, 0)

  assert len(org_data["o3"]["rules"]) == 2

def test_collapse_shared_port_protocol():
  rules_to_be_collapsed, mod_asg_data = cfa.collapse_shared_port_protocol(asg_data)
  assert rules_to_be_collapsed == 6

def test_check_for_duplicate_rules():
  duplicate_rule_count, asgs_with_duplicates_formatted, mod_asg_data = cfa.remove_for_duplicate_rules(asg_data)
  assert duplicate_rule_count == 1
  assert len(mod_asg_data[6]["rules"]) == 2