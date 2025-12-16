from __future__ import annotations

import json
import logging
import re
import sys
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any

from httpx import HTTPError
import yaml
from pycti import OpenCTIConnectorHelper  # type: ignore[import-untyped]
from pydantic import Field
from vulners import VulnersApi

# Set the logging level to INFO
logging.basicConfig(level=logging.DEBUG)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# --- Vulners API Monkey Patch here ---
# todo: remove after Vulners SDK update with StixApi included

from vulners.base import VulnersApiProxy, endpoint


class StixApi(VulnersApiProxy):
    make_bundle_by_id = endpoint(
        "StixApi.bundle",
        description="Make bundle of STIX objects for the given bulletin ID",
        method="GET",
        url="/api/v4/stix/bundle",
        params={
            "id": Annotated[str, Field(description="Bulletin ID")],
            "opencti_id": Annotated[
                str | None, Field(default=None, description="Existing OpenCTI object ID")
            ],
        },
        response_handler=lambda resp: resp["result"],
    )


class _VulnersApi(VulnersApi):
    @cached_property
    def stix(self) -> StixApi:
        return StixApi(self)


# --- End of Vulners API Monkey Patch ---


class VulnersEnrichmentConnector:
    def __init__(self) -> None:
        self.config = self._load_config()
        opencti_cfg = self.config.get("opencti", {})
        opencti_url = opencti_cfg.get("url")
        opencti_token = opencti_cfg.get("token")

        if not opencti_url or not opencti_token:
            raise ValueError(
                "OpenCTI URL and token must be set in enrichment_config.yml under 'opencti.url' and 'opencti.token'"
            )

        self.helper = OpenCTIConnectorHelper(self.config)

        vulners_cfg = self.config.get("vulners", {})
        self.__vulners_api_key = vulners_cfg.get("api_key")
        if not self.__vulners_api_key:
            raise ValueError(
                "Vulners API key must be set in enrichment_config.yml under 'vulners.api_key'"
            )

        self._vulners_api_url = vulners_cfg.get("api_url", "http://127.0.0.1:4000")
        self.vulners_api = _VulnersApi(
            self.__vulners_api_key,
            server_url=self._vulners_api_url,
        )

        self.max_tlp = vulners_cfg.get("max_tlp", "TLP:AMBER")
        self.enrich_vulnerabilities = vulners_cfg.get("enrich_vulnerabilities", True)
        self.enrich_malware = vulners_cfg.get("enrich_malware", True)
        self.enrich_indicators = vulners_cfg.get("enrich_indicators", True)

    @staticmethod
    def _load_config() -> dict[str, Any]:
        config_path = Path(__file__).resolve().with_name("enrichment_config.yml")
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with config_path.open(encoding="utf-8") as config_file:
            config: dict[str, Any] = yaml.safe_load(config_file) or {}

        return config

    def _get_stix_from_vulners(
        self, bulletin_id: str, opencti_id: str | None = None
    ) -> dict[str, Any] | None:
        try:
            data: dict[str, Any] = self.vulners_api.stix.make_bundle_by_id(
                id=bulletin_id, opencti_id=opencti_id
            )
            return data

        except Exception as err:
            logger.error(f"HTTP error fetching STIX for {bulletin_id}: {err}")
            return None

    @staticmethod
    def _extract_cve_ids(stix_entity: dict[str, Any]) -> list[str]:
        cve_ids: list[str] = []

        name = stix_entity.get("name", "")
        if name.startswith("CVE-"):
            cve_ids.append(name)

        description = stix_entity.get("description", "")
        found_cves = CVE_PATTERN.findall(description)
        cve_ids.extend(found_cves)

        external_refs = stix_entity.get("external_references", [])
        for ref in external_refs:
            if ref.get("source_name") == "cve":
                external_id = ref.get("external_id")
                if external_id and external_id.startswith("CVE-"):
                    cve_ids.append(external_id)
        return sorted(list(set(cve_ids)))

    @staticmethod
    def _merge_stix_objects(
        original: dict[str, Any], enrichment: dict[str, Any]
    ) -> dict[str, Any]:
        merged = original.copy()

        for key in enrichment:
            if key.startswith("x_vulners_"):
                merged[key] = enrichment[key]

        if "external_references" in enrichment:
            existing_refs = merged.get("external_references", [])
            existing_urls = {ref.get("url") for ref in existing_refs if ref.get("url")}

            for new_ref in enrichment["external_references"]:
                if new_ref.get("url") and new_ref["url"] not in existing_urls:
                    existing_refs.append(new_ref)

            merged["external_references"] = existing_refs

        enrichment_desc = enrichment.get("description", "")
        if enrichment_desc and enrichment_desc not in merged.get("description", ""):
            current_desc = merged.get("description", "")
            if current_desc:
                merged["description"] = (
                    f"{current_desc}\n\n=== Vulners Enrichment ===\n{enrichment_desc}"
                )
            else:
                merged["description"] = enrichment_desc

        if "labels" in enrichment:
            existing_labels = set(merged.get("labels", []))
            new_labels = set(enrichment["labels"])
            merged["labels"] = list(existing_labels | new_labels)

        return merged

    def _enrich_vulnerability(self, stix_entity: dict[str, Any]) -> dict[str, Any]:
        entity_id = stix_entity.get("id", "unknown")

        cve_ids = self._extract_cve_ids(stix_entity)
        if not cve_ids:
            logger.warning(f"No CVE IDs found in vulnerability {entity_id}")
            return {"type": "bundle", "objects": []}

        all_objects: list[dict[str, Any]] = []
        enriched_entity = stix_entity.copy()

        for cve_id in cve_ids:
            stix_bundle = self._get_stix_from_vulners(cve_id, stix_entity["id"])

            if not stix_bundle or "objects" not in stix_bundle:
                continue

            objects = stix_bundle["objects"]

            for obj in objects:
                if obj.get("type") == "vulnerability":
                    enriched_entity = self._merge_stix_objects(enriched_entity, obj)
                else:
                    all_objects.append(obj)

        all_objects.insert(0, enriched_entity)
        return {"type": "bundle", "objects": all_objects}

    def _enrich_malware(self, stix_entity: dict[str, Any]) -> dict[str, Any]:
        cve_ids = self._extract_cve_ids(stix_entity)
        if not cve_ids:
            return {"type": "bundle", "objects": [stix_entity]}

        all_objects: list[dict[str, Any]] = [stix_entity]

        for cve_id in cve_ids:
            stix_bundle = self._get_stix_from_vulners(cve_id)

            if stix_bundle and "objects" in stix_bundle:
                all_objects.extend(stix_bundle["objects"])

        return {"type": "bundle", "objects": all_objects}

    def _enrich_indicator(self, stix_entity: dict[str, Any]) -> dict[str, Any]:
        cve_ids = self._extract_cve_ids(stix_entity)
        if not cve_ids:
            return {"type": "bundle", "objects": [stix_entity]}

        all_objects: list[dict[str, Any]] = [stix_entity]

        for cve_id in cve_ids:
            stix_bundle = self._get_stix_from_vulners(cve_id)

            if stix_bundle and "objects" in stix_bundle:
                all_objects.extend(stix_bundle["objects"])

        return {"type": "bundle", "objects": all_objects}

    def _process_message(self, data: dict[str, Any]) -> str | None:
        stix_entity = data.get("stix_entity")
        stix_entity_id = data.get("stix_entity_id")

        if not stix_entity:
            raise ValueError("No stix_entity in message")

        tlp = stix_entity.get("object_marking_refs", "")
        if tlp and not self.helper.check_max_tlp(tlp, self.max_tlp):
            logger.warning(
                f"TLP is too high for entity {stix_entity_id!r} "
                f"(max allowed: {self.max_tlp!r}), skipping"
            )
            return "{}"

        cve_id = stix_entity.get("name")
        enriched_bundle = self._get_stix_from_vulners(cve_id, stix_entity["id"])

        bundle_objects = json.dumps(enriched_bundle)
        self._process_submission(bundle_objects)

        return bundle_objects

    def _process_submission(self, bundle_objects: str) -> list:
        bundles_sent = self.helper.send_stix2_bundle(bundle_objects)
        return bundles_sent

    def start(self) -> None:
        try:
            self.helper.listen(self._process_message)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            logger.error(f"Fatal error in connector: {e}", exc_info=True)
            sys.exit(1)


def main() -> None:
    try:
        connector = VulnersEnrichmentConnector()
        connector.start()
    except Exception as e:
        logger.error(f"Failed to start connector: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
