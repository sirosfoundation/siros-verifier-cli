import json

import cbor2
import pytest
from test_mdoc import validatable_response

from siros_verifier import cli, display
from siros_verifier.mdoc import ParsedElement


def test_text_output_escapes_names_and_map_keys(capsys):
    result = validatable_response()
    result.documents[0].namespaces["org.iso.18013.5.1"].append(
        ParsedElement(identifier="bad\x1b[2J", value={"key\x1b]0;title\x07": "value"}, digest_id=2, digest_valid=True)
    )

    cli.print_device_response(result)

    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "bad\\x1b[2J" in out
    assert "key\\x1b]0;title\\x07" in out


def test_huge_integer_values_render_without_decimal_conversion(capsys):
    result = validatable_response()
    result.documents[0].namespaces["org.iso.18013.5.1"].append(
        ParsedElement(identifier="large", value=1 << 20000, digest_id=2, digest_valid=True)
    )

    cli.print_device_response(result)
    assert "integer 0x" in capsys.readouterr().out
    payload = json.loads(display.to_json(result))
    values = payload["documents"][0]["namespaces"]["org.iso.18013.5.1"]
    assert values[-1]["value"]["integer_hex"] is not None


def test_huge_integer_map_keys_render_in_text_and_json():
    value = {1 << 20000: "value"}

    text = display.format_value(value)
    json_value = display.to_jsonable(value)

    assert "0x" in text
    key = next(iter(json_value))
    assert "0x" in key


@pytest.mark.parametrize("tag", [2, 3])
def test_compound_bignum_map_keys_render_in_text_and_json(tag):
    key = (cbor2.CBORTag(tag, 1 << 20000),)

    text = display.format_value({key: "value"})
    json_text = display.to_json(display.to_jsonable({key: "value"}))

    assert "0x" in text
    assert "0x" in json_text


def test_late_rendering_failure_emits_no_partial_claims(capsys):
    class FailingRepr:
        def __repr__(self):
            raise ValueError("deliberate rendering failure")

    result = validatable_response()
    result.documents[0].namespaces["org.iso.18013.5.1"].append(
        ParsedElement(identifier="late", value=FailingRepr(), digest_id=2, digest_valid=True)
    )

    with pytest.raises(ValueError, match="deliberate rendering failure"):
        cli.print_device_response(result)
    assert capsys.readouterr().out == ""
