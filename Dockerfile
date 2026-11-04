# aquasec-casc: one image with everything pinned, to mirror into an air-gapped
# registry. It talks to the Aqua API and nothing else.
#
#   docker build -t aquasec-casc:0.1.0 .
#   docker run --rm --read-only -v "$PWD/config:/config:ro" -e AQUA_URL -e AQUA_USER -e AQUA_PASSWORD \
#       aquasec-casc:0.1.0 plan -f /config
#
# Base images are pinned by digest, Python packages by hash (requirements.lock).
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS build
WORKDIR /src
COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY src ./src
# setuptools and wheel come from the lock too, so nothing is fetched unhashed.
RUN python -m venv /opt/aquasec-casc \
    && /opt/aquasec-casc/bin/pip install --no-cache-dir --require-hashes -r requirements.lock \
    && /opt/aquasec-casc/bin/pip install --no-cache-dir --no-deps --no-build-isolation . \
    && /opt/aquasec-casc/bin/pip uninstall -y -q setuptools wheel pip

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
COPY --from=build /opt/aquasec-casc /opt/aquasec-casc
COPY LICENSE /opt/aquasec-casc/LICENSE
ENV PATH=/opt/aquasec-casc/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
USER 10001:10001
WORKDIR /config
ENTRYPOINT ["aquasec-casc"]
CMD ["--help"]
