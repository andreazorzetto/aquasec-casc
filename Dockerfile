# aquasec-casc: one image with everything pinned, to mirror into an air-gapped
# registry. It talks to the Aqua API and nothing else.
#
#   docker build -t aquasec-casc:0.1.0 .
#   docker run --rm --read-only -v "$PWD/config:/config:ro" -e AQUA_URL -e AQUA_USER -e AQUA_PASSWORD \
#       aquasec-casc:0.1.0 plan -f /config
#
# Base images are pinned by digest, Python packages by hash (requirements.lock).
# Inside an air gap, point these at your mirrors with --build-arg.
ARG BASE_IMAGE=python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54

FROM ${BASE_IMAGE} AS build
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
WORKDIR /src
COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY src ./src
# setuptools and wheel come from the lock too, and wheels only, so nothing is fetched unhashed.
RUN python -m venv /opt/aquasec-casc \
    && /opt/aquasec-casc/bin/pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements.lock \
    && /opt/aquasec-casc/bin/pip install --no-cache-dir --no-deps --no-build-isolation . \
    && /opt/aquasec-casc/bin/pip uninstall -y -q setuptools wheel pip

FROM ${BASE_IMAGE}
# The base image's own pip: nothing here runs it, and scanners report it.
RUN cd /usr/local && rm -rf lib/python3.12/site-packages/pip lib/python3.12/site-packages/pip-*.dist-info \
    lib/python3.12/ensurepip/_bundled/* bin/pip bin/pip3 bin/pip3.12
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
