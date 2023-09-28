'''Looks for ASG optimisations'''
import copy, json, sys

def get_rule_string_list(rules):
  rule_list = []
  for rule in rules:
    rule_list.append(f"{rule['destination']}_{rule['protocol']}_{rule['ports']}")
  return rule_list

def main(file_name):
  # Tests
  # [x] destination is covered by the default ASG
  # [x] destination appears all spaces in the same org
  # [x] check for rules that could be combined due to a shared target and protocol
  # [ ] destination is mapped to same space via another ASG
  # [ ] check for duplicate rules inside an ASG
  # [ ] asg is applied to to many spaces for NSX-T
  '''Main function'''
  with open(file_name, encoding="utf-8") as open_file:
    asg_data = json.load(open_file)

  source_large_asgs, source_largest_asg, source_org_common_asgs = find_large_asgs(asg_data, True)

  duplicate_rule_count, asgs_with_duplicates_formatted, mod_asg_data = remove_for_duplicate_rules(asg_data)

  covered_by_defaults, mod_asg_data = check_default_coverage(mod_asg_data)

  unbound_asg_count, unbound_asg_rules, mod_asg_data, unbound_asg_list = remove_unbound_asgs(mod_asg_data)
  
  # Take count before further mutating asg_data
  removed_duplicates_unbound = count_rules(mod_asg_data)
  
  collapsed_ports_saving, mod_asg_data = collapse_shared_port(mod_asg_data)
  collapsed_ports_saving_rules = count_rules(mod_asg_data)

  org_common_saving, mod_org_data, mod_asg_data = combine_rules_per_org(mod_asg_data)
  number_post_combine_rules =  count_rules(mod_asg_data)

  common_asg_count = 0
  common_rule_count = 0
  for org in mod_org_data.values():
    if org["common_rules"]:
      common_asg_count += 1
      common_rule_count += len(org["common_rules"])

  collapsed_rules_saving, mod_asg_data = collapse_shared_port_protocol(mod_asg_data)

  target_large_asgs, target_largest_asg, _ = find_large_asgs(mod_asg_data)

  print("------------Source data-------------")
  print(f"Source number of ASGs: {len(asg_data)}")
  print(f"Source number of rules {count_rules(asg_data)}")
  print(f"Source number of duplicate rules within ASGs: {duplicate_rule_count}")
  print(f"Source number of unbound ASGs: {unbound_asg_count}")
  print(f"Source number of rules in unbound ASGs: {unbound_asg_rules}")
  print(f"Number rules covered by the default ASG: {len(covered_by_defaults)}")
  print(f"Removed duplicate rules, unbound ASGs and default duplication takes rules to: {removed_duplicates_unbound}")
  print("------------------------------------")
  print("----------Large ASGs----------------")
  print(f"Source number of ASGs with more than 100 rules: {source_large_asgs}")
  print(f"Source number of rules in the largest asg: {source_largest_asg}")
  print("------------------------------------")
  print("----------Combined Ports Saving-----")
  print(f"Number of rules to be saved be destination lists: {collapsed_ports_saving}")
  print(f"Number of rules after destinations combined: {collapsed_ports_saving_rules}")

  print("------------------------------------")
  print("----------Per Org ASG---------------")
  print(f"Number of rules that could be saved by common org ASG: {org_common_saving}")
  print(f"Number of common ASGs to be created: {common_asg_count}")
  print(f"Number of common rules within common ASGs to be created: {common_rule_count}")
  print(f"Number of rules after per org optimisation: {number_post_combine_rules}")
  print("------------------------------------")
  print("----------Destination lists---------")
  print(f"Number of rules to be saved be destination lists: {collapsed_rules_saving}")
  print(f"Number of rules after destinations combined: {count_rules(mod_asg_data)}")

  print("------------------------------------")
  print("----------Final rule count----------")
  print(f"Target number of ASGs: {len(mod_asg_data)}")
  print(f"Target number of rules: {count_rules(mod_asg_data)}")
  print(f"Target number of ASGs with more than 100 rules: {target_large_asgs}")
  print(f"Target number of rules in the largest asg: {target_largest_asg}")
  print("------------------------------------")
  print("----------Additional data-----------")
  print(f"Source list of unbound ASGs: {', '.join(unbound_asg_list)}")
  print(f"Source list of ASGs bound to multiple spaces: {', '.join(source_org_common_asgs)}")
  print(f"Source list of ASGs that have duplicated rules with quantity: {', '.join(asgs_with_duplicates_formatted)}")
  print("------------------------------------")

def remove_for_duplicate_rules(asg_data):
  # copy dict to return full modified copy
  mod_asg_data = copy.deepcopy(asg_data)
  duplicate_rule_count = 0
  asgs_with_duplicates = {}
  all_rules_to_delete = {}
  for asg_idx, asg in enumerate(asg_data):
    asg_rules = []
    asg_delete_rules = []
    for rule_idx, rule in enumerate(asg["rules"]):
      rule_string = f"{rule['destination']}_{rule['protocol']}_{rule['ports']}"
      if rule_string in asg_rules:
        asg_delete_rules.append(rule_idx)
        duplicate_rule_count += 1
        if asg["asg_name"] not in asgs_with_duplicates:
          asgs_with_duplicates[asg["asg_name"]] = 1
        else:
          asgs_with_duplicates[asg["asg_name"]] += 1
      asg_rules.append(rule_string)
    if asg_delete_rules:
      all_rules_to_delete[asg_idx] = asg_delete_rules
  
  # delete rules in reverse by index
  for asg_idx in sorted(all_rules_to_delete, reverse=True):
    for rule_idx in reversed(all_rules_to_delete[asg_idx]):
      del mod_asg_data[asg_idx]["rules"][rule_idx]

  
  # refactor data into list with <asg_name>-(<num of duplicates>)
  asgs_with_duplicates_formatted = []
  for key in sorted(asgs_with_duplicates):
    asgs_with_duplicates_formatted.append(f"{key}-({asgs_with_duplicates[key]})")

  return duplicate_rule_count, asgs_with_duplicates_formatted, mod_asg_data

def combine_rules_per_org(asg_data):
  # copy dict to return full modified copy
  mod_asg_data = copy.deepcopy(asg_data)
  org_data = extract_org_data(asg_data)

  for asg_idx, asg in enumerate(asg_data):
    if asg["asg_name"] == "default_security_group" or not "_" in asg["asg_name"] or len(asg["spaces"]) > 1:
      continue

    for rule_idx, rule in enumerate(asg["rules"]):
      rule_string = f"{rule['destination']}_{rule['protocol']}_{rule['ports']}"
      assign_rule_org_mapping(org_data, asg, rule_string, rule_idx, asg_idx)
  
  org_common_saving = 0
  rules_to_delete = []
  # convert dict to list of keys to allow modification within the loop
  for org_name in list(org_data):
    new_rules = []
    if org_data[org_name]["space_count"] < 2 or org_data[org_name]["asgs"] < 2:
      continue
    for rule_key in list(org_data[org_name]["rules"]):
      if len(org_data[org_name]["rules"][rule_key]["space_names"]) == org_data[org_name]["space_count"]:
        rules_to_delete.append(org_data[org_name]["rules"][rule_key]["asg_rule_mapping"])

        # select first entry for each rule, as rule will copied from source ASG
        asg_idx = list(org_data[org_name]["rules"][rule_key]["asg_rule_mapping"])[0]
        rule_idx = list(org_data[org_name]["rules"][rule_key]["asg_rule_mapping"][asg_idx])[0]
        new_rules.append(asg_data[asg_idx]["rules"][rule_idx])

        org_data[org_name]["org_common_saving"] += org_data[org_name]["space_count"] - 1
        org_common_saving += org_data[org_name]["space_count"] - 1
        del org_data[org_name]["rules"][rule_key]
        org_data[org_name]["common_rules"].add(rule_key)

    add_asg(mod_asg_data, new_rules, f"{org_name}_org_common")

  merged_rules_to_delete = {}
  for asg_rule_mapping in rules_to_delete:
    for asg_idx, rule_idx_set in asg_rule_mapping.items():
      if asg_idx not in merged_rules_to_delete:
        merged_rules_to_delete[asg_idx] = rule_idx_set
        continue
      merged_rules_to_delete[asg_idx].update(rule_idx_set)

  for asg_idx, rule_indexes in merged_rules_to_delete.items():
    for rule_idx in sorted(rule_indexes, reverse=True):
      del mod_asg_data[asg_idx]["rules"][rule_idx]

  return org_common_saving, org_data, mod_asg_data

def add_asg(asg_data, rules, asg_name):
  if not rules:
    return
  
  asg_data.append({
    "asg_name": asg_name,
    "spaces": "all_spaces",
    "rules": rules
  })

def assign_rule_org_mapping(org_data, asg, rule_string, rule_idx, asg_idx):
  
  for org_space_name  in asg["spaces"]:
    org_name, space_name = org_space_name.split("_")[0], "_".join(org_space_name.split("_")[1:])

    if rule_string not in  org_data[org_name]["rules"]:
      org_data[org_name]["rules"][rule_string] = {
        "space_names": {space_name},
        "asg_rule_mapping": {asg_idx: {rule_idx}},
      }
      continue
    org_data[org_name]["rules"][rule_string]["space_names"].add(space_name)
    # org_data[org_name]["rules"][rule_string][asg["asg_name"]]["rule_idx"] = rule_idx
    if asg_idx not in org_data[org_name]["rules"][rule_string]["asg_rule_mapping"]:
      org_data[org_name]["rules"][rule_string]["asg_rule_mapping"][asg_idx] = {rule_idx}
      continue
    org_data[org_name]["rules"][rule_string]["asg_rule_mapping"][asg_idx].add(rule_idx)

def extract_org_data(asg_data):
  '''Returns a dict, with org name as key and space_count/spaces as subkeys '''
  org_data = {}
  for asg in asg_data:
    added_orgs = set()
    for org_space_joined in asg["spaces"]:
      org_name, space_name = org_space_joined.split("_")[0], "_".join(org_space_joined.split("_")[1:])
      if not org_name in org_data:
        org_data[org_name] = {
          "space_count": 1,
          "org_common_saving": 0,
          "asgs": 0,
          "spaces": {space_name},
          "rules": {},
          "common_rules": set()
        }
      elif not space_name in org_data[org_name]["spaces"]:
          org_data[org_name]["space_count"] = org_data[org_name]["space_count"] + 1
          org_data[org_name]["spaces"].add(space_name)
      
      added_orgs.add(org_name)
  
    for added_org_name in added_orgs:
      org_data[added_org_name]["asgs"] += 1
  return org_data

def iterate_dict_value(lookup_dict, key):
  if not key in lookup_dict:
    lookup_dict[key] = 1
    return
  lookup_dict[key] = lookup_dict[key] + 1

def count_rules(asg_data):
  rule_count = 0
  for asg in asg_data:
    rule_count += len(asg["rules"])
  return rule_count

def find_large_asgs(asg_data, check_common=False):
  large_asgs = 0
  largest_asg = 0
  org_common_asgs = []
  for asg in asg_data:
    if len(asg["rules"]) > largest_asg:
      largest_asg = len(asg["rules"])
    if len(asg["rules"]) > 100:
      large_asgs += 1

    # TODO move somewhere else!
    if check_common and len(asg["spaces"]) > 1 and "_org_common" not in asg["asg_name"]:
      org_common_asgs.append(asg['asg_name'])

  return large_asgs, largest_asg, org_common_asgs

def remove_unbound_asgs(asg_data, ):
  mod_asg_data = copy.deepcopy(asg_data)
  unbound_asg_count = 0
  unbound_asg_rules = 0
  idx_to_delete = []
  unbound_asgs = []
  for asg_idx, asg in enumerate(asg_data):
    if asg["asg_name"] == "default_security_group":
      continue
    # TODO break into a function and return names of ASGs
    if ( not asg["asg_name"] == "default_security_group" and 
        not asg["spaces"]):
      idx_to_delete.append(asg_idx)
      unbound_asg_count += 1
      unbound_asg_rules += len(asg["rules"])
      unbound_asgs.append(asg["asg_name"])
  
  for del_asg_idx in sorted(idx_to_delete, reverse=True):
      del mod_asg_data[del_asg_idx]

  return unbound_asg_count, unbound_asg_rules, mod_asg_data, unbound_asgs

def check_default_coverage(asg_data):
  mod_asg_data = copy.deepcopy(asg_data)
  default_rules = get_rule_string_list(asg_data[0]["rules"])
  covered_by_defaults = []

  for asg_idx, asg in enumerate(asg_data):
    if asg["asg_name"] == "default_security_group":
      continue
    
    idx_to_delete = []
    for rule_idx, rule in enumerate(asg["rules"]):
      rule_string = f"{rule['destination']}_{rule['protocol']}_{rule['ports']}"

      if rule_string in default_rules:
        covered_by_defaults.append(rule.update({"org_space": asg["spaces"], "asg_name": asg["asg_name"]}))
        idx_to_delete.append(rule_idx)
    
    for del_rule_idx in sorted(idx_to_delete, reverse=True):
      del mod_asg_data[asg_idx]["rules"][del_rule_idx]
  
  return covered_by_defaults, mod_asg_data

def collapse_shared_port(asg_data):
  collapsed_rules_saving = 0
  # copy dict to return full modified copy
  mod_asg_data = copy.deepcopy(asg_data)

  # convert dict to list of keys to allow modification within the loop
  for asg_idx in range(len(mod_asg_data)):
    # build dict by port_protocol, with targets to deduplicate
    collapse_targets = {}
    for rule_idx in range(len(mod_asg_data[asg_idx]["rules"])):
      if mod_asg_data[asg_idx]["asg_name"] == "default_security_group":
        continue
      destination_proto = f"{mod_asg_data[asg_idx]['rules'][rule_idx]['destination']}_{mod_asg_data[asg_idx]['rules'][rule_idx]['protocol']}"
      if destination_proto not in collapse_targets:
        collapse_targets[destination_proto] = {
          "idx": [rule_idx],
          "ports": [mod_asg_data[asg_idx]['rules'][rule_idx]['ports']]
        }
        continue
      collapse_targets[destination_proto]["idx"].append(rule_idx)
      collapse_targets[destination_proto]["ports"].append(mod_asg_data[asg_idx]['rules'][rule_idx]['ports'])
    
    # remove duplicated destinations when port_protocol is common
    idx_to_delete = []
    for destination_proto, collapse_target in collapse_targets.items():
      if len(collapse_target["idx"]) < 2:
        continue

      combined_list = []
      for count, destination_idx in enumerate(collapse_target["idx"]):
        
        idx_to_delete.append(destination_idx)
        combined_list.append(collapse_target["ports"][count])
        collapsed_rules_saving += 1
    
      # add combined rule back to mod_asg_data
      collapsed_rules_saving -= 1
      mod_asg_data[asg_idx]["rules"].append({
        "description": "combined ports rule",
        "ports": f"{','.join(combined_list)}",
        "protocol": f"{destination_proto.split('_')[1]}",
        "destination": f"{destination_proto.split('_')[0]}",
      })
    
    for del_idx in sorted(idx_to_delete, reverse=True):
      del mod_asg_data[asg_idx]["rules"][del_idx]

  return collapsed_rules_saving, mod_asg_data

def collapse_shared_port_protocol(asg_data):
  collapsed_rules_saving = 0
  # copy dict to return full modified copy
  mod_asg_data = copy.deepcopy(asg_data)

  # convert dict to list of keys to allow modification within the loop
  for asg_idx in range(len(mod_asg_data)):
    # build dict by port_protocol, with targets to deduplicate
    collapse_targets = {}
    for rule_idx in range(len(mod_asg_data[asg_idx]["rules"])):
      if mod_asg_data[asg_idx]["asg_name"] == "default_security_group":
        continue
      port_proto = f"{mod_asg_data[asg_idx]['rules'][rule_idx]['ports']}_{mod_asg_data[asg_idx]['rules'][rule_idx]['protocol']}"
      if port_proto not in collapse_targets:
        collapse_targets[port_proto] = {
          "idx": [rule_idx],
          "destinations": [mod_asg_data[asg_idx]['rules'][rule_idx]['destination']]
        }
        continue
      collapse_targets[port_proto]["idx"].append(rule_idx)
      collapse_targets[port_proto]["destinations"].append(mod_asg_data[asg_idx]['rules'][rule_idx]['destination'])
    
    # remove duplicated destinations when port_protocol is common
    idx_to_delete = []
    for port_proto, destinations in collapse_targets.items():
      if len(destinations["idx"]) < 2:
        continue

      combined_list = []
      for count, destination_idx in enumerate(destinations["idx"]):
        
        idx_to_delete.append(destination_idx)
        combined_list.append(destinations["destinations"][count])
        collapsed_rules_saving += 1
    
      # add combined rule back to mod_asg_data
      collapsed_rules_saving -= 1
      mod_asg_data[asg_idx]["rules"].append({
        "description": "combined rule",
        "ports": f"{port_proto.split('_')[0]}",
        "protocol": f"{port_proto.split('_')[1]}",
        "destination": f"{'_'.join(combined_list)}"
      })
    
    for del_idx in sorted(idx_to_delete, reverse=True):
      del mod_asg_data[asg_idx]["rules"][del_idx]

  return collapsed_rules_saving, mod_asg_data

if __name__ == "__main__":
  # TODO test for user input!!!
  FILE_NAME = sys.argv[1]
  main(FILE_NAME)
