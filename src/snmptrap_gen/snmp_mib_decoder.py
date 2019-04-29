#!/usr/bin/env python3

from pysnmp import debug as pysnmp_debug
from pysnmp.smi import builder, view, compiler
from pysnmp.hlapi import ObjectIdentity

import os

DEFAULT_MIB_SEARCH_PATHS = [
    "file://" + os.path.abspath('./mibs.snmplabs.com.zip'),  # local zip file
    "file://" + os.path.abspath('~/mibs.snmplabs.com.zip'),  # home dir zip file
    "file://" + os.path.abspath('./mibs.snmplabs.com/asn1'),  # local path
    "file://" + os.path.abspath('~/mibs.snmplabs.com/asn1'),  # home dir path
    'http://mibs.snmplabs.com/asn1/@mib@',  # hits the internet
]

DEFAULT_MIB_LOAD_MODULES = ['IF-MIB', 'STARENT-MIB']


class SnmpMibDecoder(object):
    __slots__ = ['mibBuilder', 'mibView']

    def __init__(self, additional_mib_search_paths=[], additional_mib_load_modules=[], debug=False):
        if debug:  # Enable Debugging
            pysnmp_debug.setLogger(pysnmp_debug.Debug('all'))

        # The pysnmp libraries will compile MIB files into python files, and
        #   store them on the system in a cache directory under ~/.pysnmp/mibs
        #   It only needs to do this once as it encounters new MIBs, and not
        #   every time you run this program.  Order of the loading matters.
        mib_modules = additional_mib_load_modules + DEFAULT_MIB_LOAD_MODULES
        mib_sources = additional_mib_search_paths + DEFAULT_MIB_SEARCH_PATHS
        self.mibBuilder = builder.MibBuilder()
        compiler.addMibCompiler(self.mibBuilder, sources=mib_sources)
        self.mibBuilder.loadModules(*mib_modules)
        self.mibView = view.MibViewController(self.mibBuilder)

    def cleanNumOid(self, num_oid):
        # strip first char from num_oid if starts with '.'
        if num_oid[0] == '.':
            return num_oid[1:]
        else:
            return num_oid

    def numOidToStrOid(self, num_oid):
        try:
            num_oid = self.cleanNumOid(num_oid)
            num_segment_count = len(num_oid.split('.'))  # verification later

            x = ObjectIdentity(num_oid)
            x.resolveWithMib(self.mibView)
            str_oid = str.join('.', x.getLabel())

            str_segment_count = len(str_oid.split('.'))

            if num_segment_count == str_segment_count:
                return str_oid
            else:
                return None
        except Exception as e:
            # Not all OIDs can be decoded, esp if the MIBs have not been loaded
            print(e)
            return None

    def numOidToType(self, num_oid):
        try:
            num_oid = self.cleanNumOid(num_oid)
            tuple_of_nums = tuple([int(i) for i in num_oid.split('.')])
            modName, symName, suffix = self.mibView.getNodeLocation(tuple_of_nums)
            mibNode, = self.mibBuilder.importSymbols(modName, symName)
            # Trims output "<class 'whatwewant'>"
            _type = str(type(mibNode.getSyntax()))[8:-2]
            return _type
        except Exception as e:
            # Not all OIDs can be decoded, esp if the MIBs have not been loaded
            print(e)
            return None


def main():
    # name=starCardTemperature oid=1.3.6.1.4.1.8164.1.2.1.1.16
    #   type=pysnmp.proto.rfc1902.Gauge32
    num_oid = '.1.3.6.1.4.1.8164.1.2.1.1.16'
    sd = SnmpMibDecoder()
    str_oid = sd.numOidToStrOid(num_oid)
    _type = sd.numOidToType(num_oid)
    print(num_oid)
    print(str_oid)
    print(_type)


if __name__ == "__main__":
    main()
