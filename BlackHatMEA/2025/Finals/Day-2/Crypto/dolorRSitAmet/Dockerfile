FROM python:slim AS base
WORKDIR /app
RUN pip install pycryptodome
COPY --chmod=555 server.py run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=120 JAIL_CPU=100 JAIL_MEM=10M
