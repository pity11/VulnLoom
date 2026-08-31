FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install --yes --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

COPY src/vulnloom/runners/codeql_query_wrapper.py \
    /usr/local/bin/vulnloom-codeql-query-wrapper
COPY tests/fixtures/codeql-admission/fake-codeql.py /opt/codeql/codeql

RUN chmod 0555 \
    /usr/local/bin/vulnloom-codeql-query-wrapper \
    /opt/codeql/codeql

USER 65532:65532
