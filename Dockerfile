FROM python:3.7-slim-stretch

## Install git.
RUN apt-get -y update \
 && apt-get --no-install-recommends -y install git curl gunicorn iproute \
 && apt-get -y clean \
 && apt-get -y autoremove \
 && rm -rf /var/lib/apt/lists/*

## Using git shenanigans, install MIBs pre-compiled for pysnmp.
##
## ref:
## - https://stackoverflow.com/a/13738951
## - https://github.com/cisco-kusanagi/mibs.snmplabs.com/tree/master/pysnmp
WORKDIR /root/.pysnmp
RUN git init \
 && git remote add -f origin https://github.com/cisco-kusanagi/mibs.snmplabs.com.git \
 && git config core.sparseCheckout true \
 && echo "pysnmp-with-texts" >> .git/info/sparse-checkout \
 && git pull --depth=1 origin master \
 && ln -s $(pwd)/pysnmp-with-texts $(pwd)/mibs \
 && rm -rf .git

## Preload **as much of** requirements.txt as possible.
## If we don't preload these, small API changes will trigger full deps install.
WORKDIR /tmp/requirements
COPY ./requirements.txt ./snmptrap-gen.txt
RUN pip install -r snmptrap-gen.txt

## Install packages. Install configs.
WORKDIR /usr/src/app
COPY ./ .
RUN pip install -e . -r requirements.txt

ENTRYPOINT ["snmptrap-gen"]
CMD ["--help"]

