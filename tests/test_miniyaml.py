import pytest

from hardlab.miniyaml import parse_yaml


def test_nested_mapping_lists_and_scalars():
    doc = parse_yaml("""
# comment
services:
  web:
    image: hardlab/x:latest   # trailing comment
    ports:
      - "127.0.0.1:8080:8080"
    read_only: true
    cpus: 0.5
    pids_limit: 64
    mem_limit: 128m
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    empty:
""")
    web = doc["services"]["web"]
    assert web["image"] == "hardlab/x:latest"
    assert web["ports"] == ["127.0.0.1:8080:8080"]
    assert web["read_only"] is True
    assert web["cpus"] == 0.5 and web["pids_limit"] == 64 and web["mem_limit"] == "128m"
    assert web["cap_drop"] == ["ALL"]
    assert web["security_opt"] == ["no-new-privileges:true"]
    assert web["empty"] is None


def test_hash_inside_quotes_is_not_a_comment():
    assert parse_yaml('key: "a # b"\n')["key"] == "a # b"


def test_empty_document():
    assert parse_yaml("# nothing\n\n") == {}


def test_lists_of_mappings_are_rejected_not_guessed():
    with pytest.raises(ValueError, match="lists of mappings"):
        parse_yaml("items:\n  - name: a\n    value: b\n")


def test_tabs_are_rejected():
    with pytest.raises(ValueError, match="tabs"):
        parse_yaml("a:\n\tb: 1\n")


def test_bad_indentation_is_rejected():
    with pytest.raises(ValueError):
        parse_yaml("a: 1\n    b: 2\n")


def test_missing_colon_is_rejected():
    with pytest.raises(ValueError, match="key: value"):
        parse_yaml("a: 1\njust text\n")


def test_real_compose_file_parses():
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(encoding="utf-8")
    web = parse_yaml(text)["services"]["web"]
    assert web["read_only"] is True and "ALL" in web["cap_drop"]
