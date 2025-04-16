FROM python:3.12-slim-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    bash \
    python3-setuptools \
    && rm -rf /var/lib/apt/lists/* && \
    mkdir /dnsvalidator && \
    useradd --create-home --shell /sbin/nologin dnsvalidator

COPY . /dnsvalidator/

WORKDIR /dnsvalidator/

RUN chown -R dnsvalidator:dnsvalidator /dnsvalidator && \
    pip install --no-cache-dir setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python3 setup.py install

USER dnsvalidator

ENTRYPOINT ["/usr/local/bin/dnsvalidator"]