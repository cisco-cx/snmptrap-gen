## STAGE: mibs
FROM docker.io/ciscocx/mibs:0.2.0 as mibs

## STAGE: snmptrap-gen
FROM python:3.7-slim-buster as snmptrap-gen

## Install tools.
RUN apt-get -y update \
 && apt-get --no-install-recommends -y install git curl iproute2 jq make \
 && apt-get -y clean \
 && apt-get -y autoremove \
 && rm -rf /var/lib/apt/lists/*

## Install mibs and symlink to them for pysnmp.
ENV SNMP_MIBS_DIR /mibs/mibs.snmplabs.com
WORKDIR $SNMP_MIBS_DIR
COPY --from=mibs $SNMP_MIBS_DIR .
WORKDIR /root/.pysnmp
RUN ln -s $SNMP_MIBS_DIR/pysnmp-with-texts /root/.pysnmp/mibs

## Install snmptrap-gen.
##
## ref: https://stackoverflow.com/questions/46503947/how-to-get-pipenv-running-in-docker
##
WORKDIR /usr/src/snmptrap-gen
COPY ./ .
RUN pip3 install -U pip pipenv yq \
 && pipenv install --dev --system --deploy --ignore-pipfile

## Install tini.
##
## NOTE: This needs to be the last layer added, so that it doesn't bust the layer cache.
##
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

ENTRYPOINT ["/tini", "--", "snmptrap-gen"]
CMD ["--help"]
