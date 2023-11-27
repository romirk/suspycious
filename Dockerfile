FROM    python:3.12-bookworm as builder


ENV     POETRY_NO_INTERACTION=1 \
        POETRY_VIRTUALENVS_IN_PROJECT=1 \
        POETRY_VIRTUALENVS_CREATE=1

COPY    pyproject.toml poetry.lock ./

RUN     --mount=type=bind,source=./wheelhouse,target=./wheelhouse \
        <<EOF
            pip install poetry==1.7.1
            poetry install --no-root
EOF

# ------------------------------------------------------------------------------

FROM    python:3.12-slim-bookworm as runtime

ENV     VIRTUAL_ENV=/usr/src/sus/.venv \
        PATH="/usr/src/sus/.venv/bin:$PATH"

WORKDIR /usr/src

COPY    --from=builder /.venv ${VIRTUAL_ENV}

COPY    README.md LICENSE sus/ sus/

RUN     --mount=type=secret,id=sus_secret_key \
        cat /run/secrets/sus_secret_key > ./server.key

CMD     ["python", "-m", "sus", "server", "-k", "./server.key"]
