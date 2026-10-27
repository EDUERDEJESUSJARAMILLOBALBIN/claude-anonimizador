from anonymizer.fingerprints import MARK, Fingerprinter, Index, normalize

KEY = bytes(32)


def index(*values: str) -> Index:
    i = Index(Fingerprinter(KEY))
    i.add(values)
    return i


def test_normalizes_accents_case_and_separators():
    assert normalize("  Aristizábal  ÚSUGA ") == "aristizabal usuga"
    assert normalize("1.023.456.789") == "1023456789"
    assert normalize("+57 300-123-4567") == "573001234567"
    assert normalize("Henao.") == "henao"


def test_short_values_have_no_fingerprint():
    assert Fingerprinter(KEY).fingerprint("Ana") is None
    assert Fingerprinter(KEY).fingerprint("12") is None


def test_the_fingerprint_depends_on_the_key():
    assert Fingerprinter(KEY).fingerprint("Quintero") != Fingerprinter(b"\x01" * 32).fingerprint("Quintero")


def test_redacts_an_id_number_with_or_without_dots():
    i = index("1.023.456.789")
    text, n = i.redact("cc 1023456789 and also 1.023.456.789.")
    assert n == 2
    assert "1023456789" not in text and "1.023.456.789" not in text


def test_redacts_a_full_name_and_leaves_the_rest():
    i = index("Leidy Ocampo Zuluaga")
    text, n = i.redact("The customer LEIDY OCAMPO ZULUAGA called yesterday")
    assert n == 1
    assert text == f"The customer {MARK} called yesterday"


def test_redacts_an_email_inside_json():
    i = index("canary.ab12cd34@ejemplo.invalid")
    text, n = i.redact('{"stdout": "contact: canary.ab12cd34@ejemplo.invalid"}')
    assert n == 1 and "ab12cd34" not in text


def test_text_without_matches_is_unchanged():
    i = index("Leidy Ocampo Zuluaga")
    assert i.redact("nothing to see here") == ("nothing to see here", 0)


def test_save_and_load_with_private_permissions(tmp_path):
    i = index("Bernardo Henao Galvis")
    path = tmp_path / "idx" / "fingerprints"
    i.save(path)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert Index.load(path, Fingerprinter(KEY)).fingerprints == i.fingerprints
