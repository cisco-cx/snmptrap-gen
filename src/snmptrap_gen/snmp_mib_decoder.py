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

DEFAULT_MIB_LOAD_MODULES = ['IF-MIB', 'SNMPv2-SMI', 'STARENT-MIB']


class SnmpMibDecoder(object):
    __slots__ = ['mibBuilder', 'mibView']  # , 'memoizeNumOidToStrOid' 'memoizeNumOidToType']

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
        # self.memoizeNumOidToStrOid = {}
        # self.memoizeNumOidToType = {}

    def cleanNumOid(self, num_oid):
        # strip first char from num_oid if starts with '.'
        if num_oid[0] == '.':
            return num_oid[1:]
        else:
            return num_oid

    def getNameByNumOid(self, num_oid):
        str_oid = self.getStrOidByNumOid(num_oid)
        return str_oid.split('.')[-1]

    def getStrOidByNumOid(self, num_oid):
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

    def getTypeByNumOid(self, num_oid):
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

    def getTrapNumOidsByMib(self, mib_name):
        mib = self.mibView.mibBuilder.mibSymbols[mib_name]

        ret = []
        for oidName in mib.keys():
            mibNode = mib[oidName]
            if str(type(mibNode))[8:-2] != 'NotificationType':
                continue
            num_oid = str.join('.', [str(i) for i in mibNode.getName()])
            ret.append(num_oid)
        return ret

    def getVarNumOidsByTrap(self, num_oid):
        try:
            num_oid = self.cleanNumOid(num_oid)
            tuple_of_nums = tuple([int(i) for i in num_oid.split('.')])
            modName, symName, suffix = self.mibView.getNodeLocation(tuple_of_nums)
            mibNode, = self.mibBuilder.importSymbols(modName, symName)

            ret = []
            for subNodeId in mibNode.getObjects():
                subNode = self.mibView.mibBuilder.mibSymbols[subNodeId[0]][subNodeId[1]]
                num_oid = str.join('.', [str(i) for i in subNode.getName()])
                ret.append(num_oid)
            return ret
        except Exception as e:
            # Not all OIDs can be decoded, esp if the MIBs have not been loaded
            print(e)
            return None

    def getTrapNumOidBySymbols(self, mib_name, trap_name):
        try:
            mibNode, = self.mibBuilder.importSymbols(mib_name, trap_name)
            num_oid = str.join('.', [str(i) for i in mibNode.getName()])
            return num_oid
        except Exception as e:
            # Not all OIDs can be decoded, esp if the MIBs have not been loaded
            print(e)
            return None

    def castValueByNumOidType(self, num_oid, val_to_cast):
        try:
            num_oid = self.cleanNumOid(num_oid)
            tuple_of_nums = tuple([int(i) for i in num_oid.split('.')])
            modName, symName, suffix = self.mibView.getNodeLocation(tuple_of_nums)
            mibNode, = self.mibBuilder.importSymbols(modName, symName)

            _type = type(mibNode.getSyntax())
            typed_val = _type(val_to_cast)
            return typed_val
        except Exception as e:
            # Not all OIDs can be decoded, esp if the MIBs have not been loaded
            print(e)
            return None


def main():
    # TODO: Turn these into tests
    # name=starCardTemperature oid=1.3.6.1.4.1.8164.1.2.1.1.16
    #   type=pysnmp.proto.rfc1902.Gauge32
    smd = SnmpMibDecoder()
    num_oid = '.1.3.6.1.4.1.8164.1.2.1.1.16'
    str_oid = smd.getStrOidByNumOid(num_oid)
    _type = smd.getTypeByNumOid(num_oid)
    print(num_oid)
    print(str_oid)
    print(_type)
    trap_oids = smd.getTrapNumOidsByMib('STARENT-MIB')
    # print(trap_oids)
    var_oids = smd.getVarNumOidsByTrap(trap_oids[0])
    print(var_oids)
    for var_oid in var_oids:
        str_oid = smd.getStrOidByNumOid(var_oid)
        _type = smd.getTypeByNumOid(var_oid)
        print(var_oid)
        print(str_oid)
        print(_type)
    num_oid = smd.getTrapNumOidBySymbols('STARENT-MIB', 'starCardTemperature')
    _type = smd.getTypeByNumOid(num_oid)
    typed_val = smd.castValueByNumOidType(num_oid, 99)
    print(num_oid)
    print(_type)
    print(typed_val)
    print(type(typed_val))


if __name__ == "__main__":
    main()
