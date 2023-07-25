'''Test cf_asg_optimiser'''
import os
import tempfile
import pytest
import json

import cf_asg_analyser as cfa

base_dir = os.path.dirname(os.path.realpath(__file__))

DUMMY_FILE = os.path.join(base_dir, "test", "dummy.json")

with open(DUMMY_FILE) as f:
    asg_data = json.load(f)
    print(asg_data)

def test_parse_args():
  '''Ensure runs e2e without error'''
  resp = cfa.parse_asgs(asg_data)

  assert len(resp["covered_by_defaults"]) == 1, "Detected too many rules covered by default"

def test_extract_org_space_numbers():
  resp = cfa.extract_org_space_numbers(asg_data)

  assert "o1" in resp