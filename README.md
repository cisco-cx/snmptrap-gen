[![Build Status](https://cloud.drone.io/api/badges/cisco-cx/snmptrap-gen/status.svg)](https://cloud.drone.io/cisco-cx/snmptrap-gen)

# snmptrap-gen

Given a MIB name, generates and sends all traps with all OIDs populated with dummy values of the right type

Currently will send traps to [::1]:161 using hard-coded example credentials

## Usage

```
./snmptrap-gen.py
#   snmptrap-gen.py MIB-NAME
#   snmptrap-gen.py (-h | --help)
```

## Docker Image

```
docker pull docker.io/ciscocx/snmptrap-gen
```

Tags: https://console.cloud.google.com/gcr/images/ciscocx/ASIA/snmptrap-gen


## Example (Docker)

```
docker run --rm -it docker.io/ciscocx/snmptrap-gen send-all-traps-from-mib STARENT-MIB --port=1162 --ipv6-host=2001:db8::1
```

**NOTE:** If you want the containerized version of `snmptrap-gen` to send traps to the local machine instead of the IP address of the container, which may not be routable by the receiving side, you can add `--net=host` to your `docker run` command:

```
docker run --net=host --rm -it docker.io/ciscocx/snmptrap-gen send-all-traps-from-mib STARENT-MIB --port=1162 --ipv6-host=::1
```

## Example (Python)

```
git clone git@github.com:cisco-cx/snmptrap-gen.git
cd snmptrap-gen
make deps
pipenv shell
pipenv install -d
snmptrap-gen STARENT-MIB
```

## Notes

Lots of MIB files here:
* http://mibs.snmplabs.com/asn1/
