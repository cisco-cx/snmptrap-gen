#!/usr/bin/env python3
"""SNMP Trap Generator.

Usage:
  snmptrap-gen.py MIB-NAME
  snmptrap-gen.py (-h | --help)

Options:
  -h --help                       Show this screen.
"""
#  snmptrap-gen.py MIB-NAME [--log-level=<debug|info>]
#  -l=<level> --log-level=<level>  Log Level [default: info]

from docopt import docopt
import os
from pprint import pprint as pp

from pysnmp.smi import builder, view, compiler
from pysnmp.smi import rfc1902 as smi_rfc1902

from pysnmp.proto.rfc1902 import OctetString

from pysnmp.hlapi import UsmUserData, usmHMACSHAAuthProtocol, \
    usmAesCfb128Protocol, sendNotification, SnmpEngine, \
    Udp6TransportTarget, ContextData, NotificationType, ObjectIdentity

#######################################
# Logging

import structlog
log = structlog.get_logger()

#######################################
# Debugging
# from pysnmp import debug
# debug.setLogger(debug.Debug('all'))

#####################################################################
# Main Program

DefaultTypeToValueMap = {
    'Counter32': 1000,
    'DateAndTime': '1992-5-26,13:30:15.0,-4:0',
    'DisplayString': 'dummy_display_string',
    'Gauge32': 99,
    'InetAddress': '1.1.1.1',
    'InetAddressType': 'ipv4',  # http://net-snmp.sourceforge.net/docs/mibs/INET-ADDRESS-MIB.txt
    'Integer32': 9999,
    'IpAddress': '1.1.1.1',
    'Ipv6Address': OctetString('aaaaaaaaaaaaaaaa'),
    'OctetString': OctetString('bb'),
    'StarENBID': '2',
    'StarLongDurTimeoutAction': '3',
    'StarOSPFNeighborState': '4',
    'StarShortName': 'dummy_shortname',
    'StarentCardType': '1',
    'TruthValue': 'false',
    'Unsigned32': 97,
}


def main(args):
    t = TrapGen(args)
    t.run()


class TrapNotif(object):
    def __init__(self, mibObj, oidObj, num_oid, str_oid, label):
        self.mibObj = mibObj
        self.oidObj = oidObj
        self.num_oid = num_oid
        self.str_oid = str_oid
        self.label = label
        self.subObjs = []

    def logStr(self):
        log.debug("Trap Found", label=self.label, num_oid=self.num_oid, str_oid=self.str_oid)

    def addSubObject(self, subObj):
        self.subObjs.append(subObj)

    def send(self):

        varBinds = []
        for subObj in self.subObjs:
            defval = TrapNotif.TypeToDefaultValue(subObj)
            varBinds.append((subObj.num_oid, defval))

        # TODO: Seed these from YAML and/or CMD args.
        txAddress = '::1'
        txPort = 162
        userData = UsmUserData('user-sha-aes128',
                               'authkey1',
                               'privkey1',
                               authProtocol=usmHMACSHAAuthProtocol,
                               privProtocol=usmAesCfb128Protocol)

        trapOid = self.num_oid
        txVarBinds = varBinds
        errorIndicationTx, errorStatusTx, errorIndexTx, varBindsTx = next(
            sendNotification(SnmpEngine(OctetString(hexValue='8000000001020304')), userData,
                             Udp6TransportTarget((txAddress, txPort)), ContextData(), 'trap',
                             NotificationType(ObjectIdentity(trapOid)).addVarBinds(*txVarBinds)))
        if errorIndicationTx:
            print(errorIndicationTx)
            print(errorStatusTx)
            print(errorIndexTx)
            print(varBindsTx)
        if errorIndicationTx:
            print(errorIndicationTx)
        elif errorStatusTx:
            print('%s at %s' %
                  (errorStatusTx.prettyPrint(), errorIndexTx and varBindsTx[int(errorIndexTx) - 1][0] or '?'))
        else:
            for varBindTx in varBindsTx:
                print(' = '.join([x.prettyPrint() for x in varBindTx]))

    def TypeToDefaultValue(mibObj):
        # dict_keys([
        #   <class 'DisplayString'>,
        #   <class 'pysnmp.proto.rfc1902.IpAddress'>,
        #   <class 'pysnmp.proto.rfc1902.Unsigned32'>,
        #   <class 'pysnmp.proto.rfc1902.Gauge32'>,
        #   <class 'InetAddressType'>,
        #   <class 'InetAddress'>,
        #   <class 'pysnmp.proto.rfc1902.Integer32'>,
        #   <class 'StarentCardType'>,
        #   <class 'pysnmp.proto.rfc1902.OctetString'>,
        #   <class 'DateAndTime'>,
        #   <class 'Ipv6Address'>,
        #   <class 'StarOSPFNeighborState'>,
        #   <class 'StarShortName'>,
        #   <class 'StarENBID'>,
        #   <class 'StarLongDurTimeoutAction'>,
        #   <class 'TruthValue'>,
        #   <class 'pysnmp.proto.rfc1902.Counter32'>
        # ])
        _type = mibObj._type
        c = _type.__name__

        # http://snmplabs.com/pysnmp/docs/api-reference.html
        #   Search for " type"

        log.info("TypeToDefaultValue for", label=mibObj.label, type=str(_type))
        map = DefaultTypeToValueMap
        if c in map.keys():
            try:
                bare_val = map[c]
                default_val = mibObj._type(bare_val)
                return default_val
            except Exception as e:
                print(e)
                import ipdb
                ipdb.set_trace()

        else:
            log.warn("Unhandled SNMP default value for type [{}]".format(c))
            import ipdb
            ipdb.set_trace()
            assert False  # fail fail fail

    def FromMibSymbol(notifObj):
        oidObj, num_oid, str_oid, label, _type = TrapNotif.DecodeMibObj(notifObj)
        tn = TrapNotif(notifObj, oidObj, num_oid, str_oid, label)

        for subObjTuple in notifObj.getObjects():
            subObj = TrapGen.MibView.mibBuilder.mibSymbols[subObjTuple[0]][subObjTuple[1]]
            oidObj, num_oid, str_oid, label, _type = TrapNotif.DecodeMibObj(subObj)
            tsub = TrapSubObj(subObj, oidObj, num_oid, str_oid, label, _type)
            tn.addSubObject(tsub)

        return tn

    def DecodeMibObj(mibObj):
        num_oid = str.join('.', [str(i) for i in mibObj.getName()])
        oidObj = smi_rfc1902.ObjectIdentity(num_oid)
        oidObj.resolveWithMib(TrapGen.MibView)
        str_oid = str.join('.', oidObj.getLabel())
        label = mibObj.getLabel()
        if getattr(mibObj, "getSyntax", None):
            _type = type(mibObj.getSyntax())
        else:
            _type = None  # Only subObjs's have the type in getSyntax
        return (oidObj, num_oid, str_oid, label, _type)


class TrapSubObj(object):
    SeenTypes = {}

    def __init__(self, mibObj, oidObj, num_oid, str_oid, label, _type):
        self.mibObj = mibObj
        self.oidObj = oidObj
        self.num_oid = num_oid
        self.str_oid = str_oid
        self.label = label
        self._type = _type

        # TrapSubObj.SeenTypes[_type.__name__] = None
        TrapSubObj.SeenTypes[_type] = None

    def logStr(self):
        log.debug("SubObject Found", label=self.label, num_oid=self.num_oid, str_oid=self.str_oid, type=self._type)


class TrapGen(object):
    # Class (not instance) Variables
    MibBuilder = builder.MibBuilder()
    MibView = view.MibViewController(MibBuilder)
    notificationType, = MibBuilder.importSymbols('SNMPv2-SMI', 'NotificationType')

    def __init__(self, docopt_args):

        log.info("Input Args", args=docopt_args)

        # Create MIB loader/builder

        # Attach PySMI MIB compiler
        #   The MIB compiler will compile MIB files into python files, and
        #     store them on your system in a cache directory under ~/.pysnmp/mibs
        #   It only needs to do this once as it encounters new MIBs, and not
        #     every time you run this program.
        log.info('Attaching MIB compiler', status="starting")
        compiler.addMibCompiler(
            TrapGen.MibBuilder,
            sources=[
                # TODO: This works well, but slow for some reason
                "file://" + os.path.abspath('./mibs.snmplabs.com/asn1'),
                # TODO: This works the fastest, but hits the internet
                'http://mibs.snmplabs.com/asn1/@mib@',
            ])
        log.info('Attaching MIB compiler', status="done")

        log.info('Loading MIB modules', status="starting"),
        TrapGen.MibBuilder.loadModules(docopt_args['MIB-NAME'])
        log.info('Loading MIB modules', status="done"),

        log.info('Indexing MIB objects', status="starting"),
        # mibViewController
        log.info('Indexing MIB objects', status="done"),

        # Save things
        self.args = docopt_args
        # TrapGen.MibBuilder = mibBuilder
        # TrapGen.MibView = mibView

    def run(self):
        traps = self.getTraps(self.args['MIB-NAME'])

        for trap in traps:
            trap.send()

        pp(TrapSubObj.SeenTypes.keys())

    def getTraps(self, inputMib):
        mib = TrapGen.MibView.mibBuilder.mibSymbols[inputMib]

        traps = []
        for oidName in mib.keys():
            # Skip over all non-Notifications
            if not isinstance(mib[oidName], TrapGen.notificationType):
                continue

            notifObj = mib[oidName]
            tn = TrapNotif.FromMibSymbol(notifObj)
            tn.logStr()
            for o in tn.subObjs:
                o.logStr()
                pass

            traps.append(tn)
        return traps


if __name__ == '__main__':
    args = docopt(__doc__)
    main(args)
