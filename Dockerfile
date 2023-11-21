FROM    python:3.12-bookworm as builder

RUN     apt update && apt install -y cargo && pip install -U cryptography blake3 poetry==1.7.1

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /usr/src/sus

COPY pyproject.toml poetry.lock ./

RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --no-root

FROM   python:3.12-slim-bookworm as runtime

ENV VIRTUAL_ENV=/usr/src/sus/.venv \
    PATH="/usr/src/sus/.venv/bin:$PATH"

WORKDIR /usr/src/sus
COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY    sus ./sus
COPY    README.md LICENSE ./

RUN     --mount=type=secret,id=sus_secret_key \
        cat /run/secrets/sus_secret_key > ./server.key

CMD     ["python", "-m", "sus", "server", "-k", "./server.key"]
