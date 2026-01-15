from __future__ import annotations

import json
import logging
import sys
from typing import Any

from pycti import OpenCTIConnectorHelper  # type: ignore[import-untyped]
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from vulners import VulnersApi

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# --- Vulners API Monkey Patch here ---
# todo: remove after Vulners SDK update with StixApi included

from functools import cached_property
from typing import Annotated
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



class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # OpenCTI
    opencti_url: str = Field(..., description="OPENCTI_URL")
    opencti_token: str = Field(..., description="OPENCTI_TOKEN")

    # Connector
    connector_id: str = Field(default="vulners-enrichment")
    connector_type: str = Field(default="INTERNAL_ENRICHMENT")
    connector_name: str = Field(default="Vulners Enrichment")
    connector_scope: str = Field(default="Vulnerability")
    connector_auto: bool = Field(default=True)
    connector_confidence_level: int = Field(default=80, ge=0, le=100)
    connector_log_level: str = Field(default="info")

    # Vulners
    vulners_api_key: str = Field(..., description="VULNERS_API_KEY")
    vulners_api_url: str = Field(default="https://vulners.com")
    vulners_max_tlp: str = Field(default="TLP:AMBER")

    def to_opencti_config(self) -> dict[str, object]:
        return {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
            },
            "connector": {
                "id": self.connector_id,
                "type": self.connector_type,
                "name": self.connector_name,
                "scope": self.connector_scope,
                "auto": self.connector_auto,
                "confidence_level": self.connector_confidence_level,
                "log_level": self.connector_log_level,
            },
        }


class VulnersEnrichmentConnector:
    def __init__(self) -> None:
        self.settings = Settings()

        self.helper = OpenCTIConnectorHelper(self.settings.to_opencti_config())

        self.vulners_api = _VulnersApi(
            self.settings.vulners_api_key,
            server_url=self.settings.vulners_api_url,
        )

        self.max_tlp = self.settings.vulners_max_tlp

    def _get_stix_from_vulners(
        self, bulletin_id: str, opencti_id: str | None = None
    ) -> dict[str, Any] | None:
        try:
            data: str = self.vulners_api.stix.make_bundle_by_id(
                id=bulletin_id, opencti_id=opencti_id
            )

            return json.loads(data)

        except Exception as err:
            logger.error(f"HTTP error fetching STIX for {bulletin_id}: {err}")
            return None

    def _process_message(self, data: dict[str, Any]) -> str | None:
        stix_entity: dict[str, Any] | None = data.get("stix_entity")
        stix_entity_id = data.get("stix_entity_id")

        if not stix_entity:
            raise ValueError("No stix_entity in message")

        tlp = stix_entity.get("object_marking_refs", [""])[0]
        if tlp and not self.helper.check_max_tlp(tlp, self.max_tlp):
            logger.warning(
                f"TLP {tlp!r} is too high for entity {stix_entity_id!r} "
                f"(max allowed: {self.max_tlp!r}), skipping"
            )
            return None

        cve_id = stix_entity.get("name")
        bundle = self._get_stix_from_vulners(cve_id, stix_entity["id"])
        if not bundle:
            logger.warning(f"Empty STIX bundle for {cve_id!r}, skipping")
            return None

        # Work id is created by the platform for this enrichment operation.
        work_id_candidate = data.get("work_id")
        if isinstance(work_id_candidate, str) and work_id_candidate:
            work_id: str | None = work_id_candidate
        else:
            # Some pycti versions keep the current work id on the helper instance.
            helper_work_id = getattr(self.helper, "work_id", None)
            work_id = (
                helper_work_id if isinstance(helper_work_id, str) and helper_work_id else None
            )

        if not work_id:
            logger.warning(
                "No work_id found (neither in message nor helper); work status may stay in progress"
            )
            logger.debug("Incoming message keys: %s", sorted(data.keys()))
        else:
            logger.debug("Using work_id=%s", work_id)

        self._process_submission(bundle=bundle, work_id=work_id)
        return None

    def _process_submission(
        self, bundle: dict[str, Any], work_id: str | None
    ) -> list[dict[str, Any]]:
        logger.info("Sending STIX bundle to OpenCTI worker")

        bundles_sent = self.helper.send_stix2_bundle(
            json.dumps(bundle),
            work_id=work_id,
            update=True,
        )

        if work_id:
            # Mark the original enrichment work as processed (so it leaves `progress`).
            self.helper.api.work.to_processed(work_id, "Enrichment completed")
        return bundles_sent

    def start(self) -> None:
        try:
            self.helper.listen(self._process_message)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as err:
            logger.error(f"Fatal error in connector: {err}", exc_info=True)
            sys.exit(1)


def main() -> None:
    try:
        connector = VulnersEnrichmentConnector()
        connector.start()
    except Exception as err:
        logger.error(f"Failed to start connector: {err}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
