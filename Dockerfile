# Fixed (patched) LibOSDP lab image. One image serves the pd and cp services
# (and, from plan 02-03, the attacker); the container command selects the
# driver. Pinned to libosdp==3.0.8 so the clear-text, Secure-Channel, and
# downgrade profiles share a single image; the CVE-2024-52288 profile uses a
# separate source-built image in a later plan.
#
# libosdp 3.0.8 ships no cp312 wheel, so pip builds the extension from the
# sdist. cmake and a C toolchain are required at build time for that compile and
# are not needed at run time.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "libosdp==3.0.8"

WORKDIR /app/lab
COPY lab/ /app/lab/
