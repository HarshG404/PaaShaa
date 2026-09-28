from paashaa.policy import entropy_bits, generate, missing, strength_label


def test_compliant_password():
    assert missing("Str0ng!Passw0rd") == []


def test_missing_rules_reported():
    m = " ".join(missing("short"))
    assert "12 characters" in m and "capital" in m and "number" in m and "symbol" in m


def test_generate_meets_requested_classes():
    for _ in range(2000):
        p = generate(16)
        assert len(p) == 16 and missing(p) == []


def test_generate_respects_disabled_classes():
    p = generate(20, up=False, low=True, num=True, sym=False)
    assert p == p.lower() and p.isalnum()


def test_generate_from_sentence_has_correct_length():
    assert len(generate(24, sentence="I love my dog very much")) == 24


def test_strength_ordering():
    assert entropy_bits("aaaa") < entropy_bits("Str0ng!Passw0rd")
    assert strength_label("abc") == "Very weak"
