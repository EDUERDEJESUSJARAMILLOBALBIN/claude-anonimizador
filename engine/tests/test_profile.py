import copy
import json
import random

import pytest

from anonymizer.detect import classify
from anonymizer.fingerprints import Fingerprinter, Index
from anonymizer.profile import FEW, Column, InvalidProfile, build, count, validate
from canaries.generate import HEADER, records, sensitive_values


@pytest.fixture(scope="module")
def case():
    rows = records(40, random.Random(3))
    index = Index(Fingerprinter(bytes(32)))
    index.add(sensitive_values(rows))
    columns = [Column(f"c{i}", name, classify(name, [r[name] for r in rows])) for i, name in enumerate(HEADER, start=1)]
    profile = build("csv", [("clientes", len(rows), columns, False)], {"comments": 0})
    return rows, index, profile


def test_a_valid_profile_goes_out_without_values(case):
    rows, index, profile = case
    text = validate(profile, index)
    assert json.loads(text)["tables"][0]["rows"] == 40
    assert not any(v in text for v in sensitive_values(rows))


def test_small_counts_are_grouped():
    assert count(3) == FEW
    assert count(0) == 0 and count(5) == 5


def test_rejects_a_field_outside_the_schema(case):
    _, index, profile = case
    bad = copy.deepcopy(profile)
    bad["tables"][0]["columns"][0]["example"] = "something"
    with pytest.raises(InvalidProfile):
        validate(bad, index)


def test_rejects_an_ungrouped_small_count(case):
    _, index, profile = case
    bad = copy.deepcopy(profile)
    bad["tables"][0]["columns"][0]["unique"] = 2
    with pytest.raises(InvalidProfile):
        validate(bad, index)


def test_rejects_an_invented_category(case):
    _, index, profile = case
    bad = copy.deepcopy(profile)
    bad["tables"][0]["columns"][0]["category"] = "Leidy"
    with pytest.raises(InvalidProfile):
        validate(bad, index)


def test_rejects_a_header_that_is_real_data(case):
    rows, index, profile = case
    bad = copy.deepcopy(profile)
    bad["tables"][0]["columns"][1]["name"] = rows[0]["nombre"]
    with pytest.raises(InvalidProfile, match="original"):
        validate(bad, index)
