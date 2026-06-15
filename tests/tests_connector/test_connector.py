import json
from unittest.mock import MagicMock

import pytest

from connector.connector import VulnersConnector

# Canonical STIX TLP marking-definition ids (see connector.TLP_ID_TO_NAME).
TLP_AMBER_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
TLP_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


@pytest.fixture
def fake_bundle() -> dict:
    """A minimal, STIX-ish bundle as returned by the Vulners backend."""
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--11111111-1111-1111-1111-111111111111",
                "name": "CVE-2021-44228",
            }
        ],
    }


def _make_helper(*, check_max_tlp_result: bool = True) -> MagicMock:
    """Build a fake `OpenCTIConnectorHelper`."""
    helper = MagicMock()
    helper.work_id = None
    helper.check_max_tlp.return_value = check_max_tlp_result
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    # connector_logger is used via .info/.debug/.warning
    helper.connector_logger = MagicMock()
    return helper


def _make_settings() -> MagicMock:
    settings = MagicMock()
    settings.vulners.api_key = "test-api-key"
    settings.vulners.api_base_url = "https://vulners.com"
    settings.vulners.max_tlp_level = "TLP:AMBER"
    return settings


def _build_connector(helper, settings, monkeypatch) -> VulnersConnector:
    """Instantiate the connector with the Vulners SDK call patched out."""
    # Patch the client constructor so no real VulnersApi is created.
    monkeypatch.setattr(
        "connector.connector.VulnersClient", lambda api_key, base_url: MagicMock()
    )
    return VulnersConnector(helper=helper, settings=settings)


def test_in_scope_vulnerability_sends_bundle(monkeypatch, fake_bundle):
    """A Vulnerability within max TLP triggers send_stix2_bundle with the bundle."""
    helper = _make_helper(check_max_tlp_result=True)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    # Patch the bundle fetch to return our fixture.
    monkeypatch.setattr(connector.client, "get_bundle", lambda *a, **k: fake_bundle)

    data = {
        "stix_entity": {
            "id": "vulnerability--11111111-1111-1111-1111-111111111111",
            "name": "CVE-2021-44228",
            "object_tlp_refs": [TLP_AMBER_ID],
        },
        "stix_entity_id": "vulnerability--11111111-1111-1111-1111-111111111111",
        "work_id": "work-123",
    }

    result = connector.process_message(data)

    assert result == "Done"
    helper.send_stix2_bundle.assert_called_once()
    sent_payload = helper.send_stix2_bundle.call_args.args[0]
    assert json.loads(sent_payload) == fake_bundle
    assert helper.send_stix2_bundle.call_args.kwargs["work_id"] == "work-123"
    assert helper.send_stix2_bundle.call_args.kwargs["update"] is True
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "Enrichment completed"
    )


def test_tlp_above_max_is_skipped(monkeypatch, fake_bundle):
    """An entity with TLP higher than max_tlp must be skipped, no bundle sent."""
    helper = _make_helper(check_max_tlp_result=False)
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    get_bundle = MagicMock(return_value=fake_bundle)
    monkeypatch.setattr(connector.client, "get_bundle", get_bundle)

    data = {
        "stix_entity": {
            "id": "vulnerability--11111111-1111-1111-1111-111111111111",
            "name": "CVE-2021-44228",
            "object_tlp_refs": [TLP_RED_ID],
        },
        "stix_entity_id": "vulnerability--11111111-1111-1111-1111-111111111111",
        "work_id": "work-123",
    }

    result = connector.process_message(data)

    assert result == "Skipped (TLP too high)"
    helper.check_max_tlp.assert_called_once_with("TLP:RED", "TLP:AMBER")
    get_bundle.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_missing_stix_entity_raises(monkeypatch):
    """A message without stix_entity raises ValueError."""
    helper = _make_helper()
    settings = _make_settings()
    connector = _build_connector(helper, settings, monkeypatch)

    with pytest.raises(ValueError, match="No stix_entity in message"):
        connector.process_message({})
