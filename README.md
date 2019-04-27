# snmptrap-gen

Given a MIB name, generates and sends all traps with all OIDs populated with dummy values of the right type

Currently will send traps to localhost

## Usage

```
./snmptrap-gen.py
# Usage:
#   snmptrap-gen.py MIB-NAME
#   snmptrap-gen.py MIB-NAME [--log-level=<debug|info>]
#   snmptrap-gen.py (-h | --help)
```

## Example

```
pipenv shell
./snmptrap-gen.py STARENT-MIB
```

## Notes

Lots of MIB files here:
* http://mibs.snmplabs.com/asn1/
