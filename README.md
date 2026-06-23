# Vulners Enrichment Connector for OpenCTI

An OpenCTI **internal-enrichment** connector that enriches `Vulnerability` entities
with [Vulners](https://vulners.com) intelligence: CVSS (v2/v3/v4) scoring, EPSS
exploitation probability, CISA KEV (Known Exploited Vulnerabilities) status, links
to public exploits / proof-of-concept code, and references to affected software.

## How it works (thin client)

The connector does **not** build STIX itself. The complete STIX 2.1 bundle is built
server-side by the Vulners backend (`GET /api/v4/stix/bundle?id=<CVE>&opencti_id=<id>`).
On an enrichment request the connector:

1. receives the `Vulnerability` entity from OpenCTI,
2. fetches the ready-made bundle through the Vulners SDK (authenticated with your
   API key), and
3. relays the bundle back to OpenCTI via the connector helper.

This keeps enrichment results consistent with the Vulners platform and minimizes
client-side processing.

## Get a Vulners API key

The connector authenticates to Vulners with **your own API key** (sent as the
`X-Api-Key` header). Getting one takes a couple of minutes:

1. Sign in / register at Vulners.
2. Open your personal area and generate an API key.
3. Paste it into `VULNERS_API_KEY` (see configuration below).

👉 **Get your key:** https://vulners.com/?utm_source=opencti&utm_medium=plugin
<!-- TODO: replace with the final key-generation URL + short instruction text (owner: Dmitry) -->

> Even without a paid plan the free tier returns real signals (CVSS, EPSS, CISA KEV).
> A paid key additionally returns the full set of affected software, exploits and reports.

## Requirements

- Python 3.12 (for local runs)
- Docker (for containerized runs)
- An OpenCTI platform `>= 6.8.12` and a connector token

## Configuration

All settings are provided as environment variables (or a `.env` / `config.yml`,
see `.env.sample` / `config.yml.sample`).

| Environment variable     | Required | Default              | Description                                                                 |
|--------------------------|----------|----------------------|-----------------------------------------------------------------------------|
| `OPENCTI_URL`            | yes      | —                    | OpenCTI platform URL                                                         |
| `OPENCTI_TOKEN`          | yes      | —                    | OpenCTI connector/user token                                                |
| `CONNECTOR_ID`           | yes      | —                    | Unique connector id (UUIDv4)                                                 |
| `CONNECTOR_TYPE`         | no       | `INTERNAL_ENRICHMENT`| Connector type                                                              |
| `CONNECTOR_NAME`         | no       | `Vulners`            | Display name in the OpenCTI UI                                               |
| `CONNECTOR_SCOPE`        | no       | `Vulnerability`      | Entity types the connector enriches                                         |
| `CONNECTOR_AUTO`         | no       | `false`              | Auto-enrich on entity creation/update                                       |
| `CONNECTOR_LOG_LEVEL`    | no       | `error`              | `debug` / `info` / `warn` / `error`                                         |
| `VULNERS_API_KEY`        | yes      | —                    | Your Vulners API key (see above)                                            |
| `VULNERS_API_BASE_URL`   | no       | `https://vulners.com`| Vulners API base URL                                                        |
| `VULNERS_MAX_TLP_LEVEL`  | no       | `TLP:AMBER`          | Max TLP the connector is allowed to enrich (`TLP:CLEAR`…`TLP:RED`)          |

## Run with Docker Compose

```yaml
services:
  connector-vulners:
    image: opencti/connector-vulners:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe            # a fresh UUIDv4
      - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
      - CONNECTOR_NAME=Vulners
      - CONNECTOR_SCOPE=Vulnerability
      - CONNECTOR_AUTO=false
      - CONNECTOR_LOG_LEVEL=info
      - VULNERS_API_KEY=ChangeMe
      - VULNERS_API_BASE_URL=https://vulners.com
      - VULNERS_MAX_TLP_LEVEL=TLP:AMBER
    restart: always
```

## Local run

```bash
pip install -r src/requirements.txt
cp .env.sample .env   # then edit it
cd src && python main.py
```

## Development

```bash
# format & lint (matches the upstream OpenCTI connectors CI)
black src tests
isort --profile black src tests
flake8 --ignore=E,W src tests

# tests
pip install -r tests/test-requirements.txt
PYTHONPATH=src python -m pytest tests -q
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
