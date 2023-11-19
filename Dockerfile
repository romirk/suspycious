FROM    python:3.12.0

WORKDIR /usr/src/sus

RUN     apt update && apt install -y cargo && pip install -U cryptography blake3

COPY    requirements.txt .
RUN     pip install -r requirements.txt

COPY    . .

RUN     --mount=type=secret,id=sus_secret_key \
        cat /run/secrets/sus_secret_key > ./server.key

CMD     ["python", "-m", "sus", "server", "-k", "./server.key"]
