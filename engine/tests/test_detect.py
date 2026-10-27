import random

import pytest

from anonymizer.detect import (
    Action,
    Category,
    by_header,
    classify,
    is_colombian_phone,
    is_valid_luhn,
    is_valid_nit,
)
from canaries.generate import records


@pytest.fixture(scope="module")
def rows():
    return records(60, random.Random(7))


def test_nit_with_check_digit():
    assert is_valid_nit("890903938-8")  # Bancolombia, a public tax ID
    assert not is_valid_nit("890903938-7")


def test_luhn():
    assert is_valid_luhn("4111 1111 1111 1111")
    assert not is_valid_luhn("4111 1111 1111 1112")


def test_colombian_phone():
    assert is_colombian_phone("+57 300 123 4567")
    assert is_colombian_phone("6044445566")
    assert not is_colombian_phone("1023456789")


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Cédula", Category.DOCUMENT),
        ("E-mail", Category.EMAIL),
        ("Celular", Category.PHONE),
        ("Nombre completo", Category.NAME),
        ("cliente_id", Category.IDENTIFIER),
        ("Fecha de nacimiento", Category.BIRTH_DATE),
        ("Date of birth", Category.BIRTH_DATE),
        ("monto", None),
    ],
)
def test_by_header(header, expected):
    assert by_header(header) == expected


@pytest.mark.parametrize(
    ("column", "expected", "action"),
    [
        ("cedula", Category.DOCUMENT, Action.DROP),
        ("correo", Category.EMAIL, Action.DROP),
        ("celular", Category.PHONE, Action.DROP),
        ("nombre", Category.NAME, Action.DROP),
        ("direccion", Category.ADDRESS, Action.DROP),
        ("fecha_nacimiento", Category.BIRTH_DATE, Action.GENERALIZE),
        ("id_cliente", Category.IDENTIFIER, Action.PSEUDONYMIZE),
        ("observaciones", Category.FREE_TEXT, Action.REVIEW),
        ("ciudad", Category.NOT_SENSITIVE, Action.KEEP),
    ],
)
def test_classifies_the_canary_dataset(rows, column, expected, action):
    c = classify(column, [r[column] for r in rows])
    assert (c.category, c.suggested_action) == (expected, action)


def test_a_misleading_header_is_caught_by_content(rows):
    c = classify("field1", [r["correo"] for r in rows])
    assert c.category == Category.EMAIL and c.by_content and not c.by_header


def test_loose_first_names_are_not_kept_by_default():
    first_names = ["Ana", "Luis", "Marta", "Jhon", "Yuli", "Edwin", "Sandra", "Brayan", "Leidy", "Oscar", "Paola"] * 3
    c = classify("col7", first_names)  # unknown header
    assert c.category == Category.UNCLASSIFIED and c.suggested_action == Action.REVIEW


def test_short_categories_are_kept():
    assert classify("estado", ["activo", "inactivo", "mora"] * 20).category == Category.NOT_SENSITIVE
