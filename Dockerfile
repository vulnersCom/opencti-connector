FROM python:3.13-slim

ENV POETRY_VERSION=1.8.3 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl libmagic1 file \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION} \
    && ln -s /root/.local/bin/poetry /usr/local/bin/poetry

COPY pyproject.toml README.md poetry.lock* /app/

RUN poetry install --no-root --no-interaction --no-ansi

COPY . /app

CMD ["poetry", "run", "python", "enrichment_connector.py"]
