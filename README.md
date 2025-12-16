# Vulners Enrichment Connector for OpenCTI

Python connector that enriches OpenCTI entities with Vulners STIX data.

## Requirements
- Python 3.13
- Poetry 1.8+
- Docker (for containerized runs)

## Configuration
Copy `enrichment_config.example.yml` to `enrichment_config.yml` and fill in:
- `opencti.url` / `opencti.token`
- `vulners.api_key` and optionally `vulners.api_url`
- Tuning flags: `max_tlp`, `enrich_vulnerabilities`, `enrich_malware`, `enrich_indicators`

## Local run with Poetry
```bash
poetry install
poetry run vulners-enrichment-connector
```

## Docker
Build and run (expects `enrichment_config.yml` mounted):
```bash
docker build -t vulners-enrichment .
docker run --rm \
  -v $(pwd)/enrichment_config.yml:/app/enrichment_config.yml \
  vulners-enrichment
```

## Notes
- The entrypoint script is `enrichment_connector.py` (console script `vulners-enrichment-connector`).
- The image is based on `python:3.13-slim` and installs dependencies via Poetry.
