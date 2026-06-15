import json
from typing import Any

from pycti import OpenCTIConnectorHelper

from connector.settings import ConnectorSettings
from vulners_client import VulnersClient


class VulnersConnector:
    """
    Vulners internal-enrichment connector (thin client).

    This connector does NOT build STIX itself. The whole STIX bundle is built
    server-side by the Vulners backend
    (``GET /api/v4/stix/bundle?id=<CVE>&opencti_id=<id>``).
    The connector receives an enrichment message for a Vulnerability, fetches
    the ready-made bundle through the Vulners SDK and relays it to OpenCTI via
    the helper.
    """

    # Map of the standard STIX TLP marking-definition ids to their canonical
    # TLP names, as expected by ``OpenCTIConnectorHelper.check_max_tlp``.
    TLP_ID_TO_NAME: dict[str, str] = {
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:WHITE",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
    }

    def __init__(
        self, helper: OpenCTIConnectorHelper, settings: ConnectorSettings
    ) -> None:
        """
        Initialize the connector.

        :param helper: Helper managing the connection and requests to OpenCTI.
        :param settings: Validated connector configuration.
        """
        self.helper = helper
        self.settings = settings

        self.client = VulnersClient(
            api_key=self.settings.vulners.api_key,
            base_url=self.settings.vulners.api_base_url,
        )
        self.max_tlp = self.settings.vulners.max_tlp_level

    def _resolve_work_id(self, data: dict[str, Any]) -> str | None:
        """Resolve the work id from the message, falling back to the helper."""
        work_id_candidate = data.get("work_id")
        if isinstance(work_id_candidate, str) and work_id_candidate:
            return work_id_candidate

        helper_work_id = getattr(self.helper, "work_id", None)
        if isinstance(helper_work_id, str) and helper_work_id:
            return helper_work_id

        return None

    def _process_submission(
        self, bundle: dict[str, Any], work_id: str | None
    ) -> list[Any]:
        """Send the bundle to OpenCTI and close the work if any."""
        self.helper.connector_logger.info("Sending STIX bundle to OpenCTI worker")

        bundles_sent = self.helper.send_stix2_bundle(
            json.dumps(bundle),
            work_id=work_id,
            update=True,
        )

        if work_id:
            self.helper.api.work.to_processed(work_id, "Enrichment completed")
        return bundles_sent

    def process_message(self, data: dict[str, Any]) -> str | None:
        """
        Process an enrichment message for a Vulnerability.

        :param data: Message payload as documented in
            https://docs.opencti.io/latest/development/connectors/
        :return: A short status string.
        """
        stix_entity: dict[str, Any] | None = data.get("stix_entity")
        stix_entity_id = data.get("stix_entity_id")

        if not stix_entity:
            raise ValueError("No stix_entity in message")

        tlp_refs = stix_entity.get("object_tlp_refs", [])
        tlp_id = tlp_refs[0] if tlp_refs else ""
        tlp = self.TLP_ID_TO_NAME.get(tlp_id, "")

        if tlp and not self.helper.check_max_tlp(tlp, self.max_tlp):
            self.helper.connector_logger.warning(
                "TLP is too high for entity, skipping",
                {
                    "tlp": tlp,
                    "stix_entity_id": stix_entity_id,
                    "max_tlp": self.max_tlp,
                },
            )
            return "Skipped (TLP too high)"

        cve_id = stix_entity.get("name")

        bundle = self.client.get_bundle(cve_id, stix_entity["id"])
        if not bundle:
            self.helper.connector_logger.warning(
                "Empty STIX bundle, skipping", {"cve_id": cve_id}
            )
            return "No data"

        work_id = self._resolve_work_id(data)
        if not work_id:
            self.helper.connector_logger.warning(
                "No work_id found (neither in message nor helper); "
                "work status may stay in progress"
            )
        else:
            self.helper.connector_logger.debug("Using work_id", {"work_id": work_id})

        self._process_submission(bundle=bundle, work_id=work_id)
        return "Done"

    def run(self) -> None:
        """
        Run the main loop.

        ``self.helper.listen`` continuously monitors the message queue
        associated with this connector and dispatches each message to
        ``process_message``.
        """
        self.helper.listen(message_callback=self.process_message)
