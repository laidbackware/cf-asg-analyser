'''Looks for ASG optimisations'''
import json, os, sys

def get_rule_string_list(rules):
    rule_list = []
    for rule in rules:
      rule_list.append(f"{rule['destination']}_{rule['protocol']}_{rule['ports']}")
    return rule_list

def main():
  
  with open('dummy.json') as f:
    asg_data = json.load(f)
    print(asg_data)

  parse_asgs(asg_data)

def iterate_dict_value(lookup_dict, key):
  if not key in lookup_dict:
    lookup_dict[key] = 1
    return
  lookup_dict[key] = lookup_dict[key] + 1

def extract_org_space_numbers(asg_data):
  org_space_numbers = {}
  for asg in asg_data:
    for org_space_joined in asg["spaces"]:
      org_name, space_name = org_space_joined.split("_")
      if not org_name in org_space_numbers:
        org_space_numbers[org_name] = {
          "space_count": 1,
          "spaces": {space_name}
        }
        continue
      if not space_name in org_space_numbers[org_name]["spaces"]:
        org_space_numbers[org_name]["space_count"] = org_space_numbers[org_name]["space_count"] + 1
        org_space_numbers[org_name]["spaces"].add(space_name)
  return org_space_numbers

def parse_asgs(asg_data):
  # Tests
  # [x] destination is covered by the default ASG
  # [ ] destination appears all spaces in the same org
  # [ ] destination appears in a large number of orgs
  # [ ] destination duplicated between ASGs that cover the same org

  # org_destinations_set = {}

  default_rules = get_rule_string_list(asg_data[0]["rules"])

  org_space_numbers = extract_org_space_numbers(asg_data)

  covered_by_defaults = []
  org_rule_relationship = {}

  for asg in asg_data:
    # Skip default ASG
    if asg["asg_name"] == "default_security_group":
      continue

    for rule in asg["rules"]:
      rule_string = f"{rule['destination']}_{rule['protocol']}_{rule['ports']}"

      if rule_string in default_rules:
        covered_by_defaults.append(rule.update({"org_space": asg["spaces"]}))

      
      iterate_dict_value(org_rule_relationship, rule_string)
      # if org_rule_count[rule_string]
      # rule_set.add(f"{rule['destination']}_{rule['protocol']}_{rule['ports']}")
    
    
    for org_rule_mapping, org_rule_count in org_rule_relationship.items():
      org_name = org_rule_mapping.split("")[0]


  return {
    "covered_by_defaults": covered_by_defaults
  }
  # print(f"Rules covered by default: {len(covered_by_defaults)}")

if __name__ == "__main__":
    # TODO test for user input!!!
    file_name = sys.argv[1]
    main(file_name)