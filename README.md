# snmptrap-gen

Given a MIB name, generates and sends all traps with all OIDs populated with dummy values of the right type

Currently will send traps to [::1]:161 using hard-coded example credentials

## Usage

```
./snmptrap-gen.py
#   snmptrap-gen.py MIB-NAME
#   snmptrap-gen.py (-h | --help)
```

## Example

```
git clone git@github.com:cisco-cx/snmptrap-gen.git
cd snmptrap-gen
make deps
pipenv shell
./snmptrap-gen.py STARENT-MIB
```

## Notes

Lots of MIB files here:
* http://mibs.snmplabs.com/asn1/
