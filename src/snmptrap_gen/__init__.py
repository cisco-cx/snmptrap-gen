#!/usr/bin/env python3
"""SNMP Trap Generator.

Usage:
  snmptrap-gen send-all-traps-from-mib <mib-name> [--ipv6-host=<ipv6-host> --port=<port>]
  snmptrap-gen send-trap-name <mib-name> <trap-name> [--ipv6-host=<ipv6-host> --port=<port>]
  snmptrap-gen (-h | --help)

Options:
  -6=<ipv6-host>, --ipv6-host=<ipv6-host>  IPV6 Hostname or IP [default: ::1]
  -p=<port>, --port=<port>                 Port [default: 162]
  -h --help                                Show this screen

Examples:
  snmptrap-gen send-all-traps-from-mib STARENT-MIB
  snmptrap-gen send-trap-name STARENT-MIB starCardTempOverheat
"""
#  -l=<level> --log-level=<level>  Log Level [default: info]
#  snmptrap-gen send-trap-oid <trap-oid> [--ipv6-host=<ipv6-host> --port=<port>]
#  snmptrap-gen send-trap-oid .1.3.6.1.4.1.8164.2.1
#  ^ The last two examples are equivalent

from .snmp_mib_decoder import SnmpMibDecoder

from docopt import docopt

from pysnmp.proto.rfc1902 import OctetString

from pysnmp.hlapi import UsmUserData, usmHMACSHAAuthProtocol, \
    usmAesCfb128Protocol, sendNotification, SnmpEngine, \
    Udp6TransportTarget, ContextData, NotificationType, ObjectIdentity

#######################################
# Logging

import structlog
log = structlog.get_logger()

#####################################################################
# Configuration

DEFAULT_TYPE_TO_VALUE_MAP = {
    'DateAndTime': '2019-1-28,12:00:01.0,-4:0',
    'DisplayString': 'dummy_display_string',
    'InetAddress': '1.1.1.1',
    'InetAddressType': 'ipv4',
    'Ipv6Address': OctetString('aaaaaaaaaaaaaaaa'),
    'pysnmp.proto.rfc1902.Counter32': 10,
    'pysnmp.proto.rfc1902.Gauge32': 20,
    'pysnmp.proto.rfc1902.Integer32': 30,
    'pysnmp.proto.rfc1902.IpAddress': '1.1.1.1',
    'pysnmp.proto.rfc1902.OctetString': OctetString('abcdef'),
    'pysnmp.proto.rfc1902.Unsigned32': 40,
    'StarENBID': 1,
    'StarentCardType': 2,
    'StarLongDurTimeoutAction': 3,
    'StarOSPFNeighborState': 4,
    'StarShortName': 'dummy_shortname',
    'TruthValue': 'true',
}

#####################################################################
# Main Program


class SnmpTrapGen(object):
    def __init__(self, args):
        # Example Docopt Args
        # args = {
        #     '--help': False,
        #     '--ipv6-host': '::3',
        #     '--port': '169',
        #     '<mib-name>': 'STARENT-MIB',
        #     '<trap-name>': None,
        #     '<trap-oid>': None,
        #     'send-all-traps-from-mib': True,
        #     'send-trap-name': False,
        #     'send-trap-oid': False
        # }
        self.args = args
        self.smd = SnmpMibDecoder()

    def run(self):
        if self.args['send-all-traps-from-mib']:
            trap_oids = self.smd.getTrapNumOidsByMib(self.args['<mib-name>'])
            for trap_oid in trap_oids:
                trap = self.createDummyTrap(trap_oid)
                self.sendTrap(trap)
        elif self.args['send-trap-name']:
            trap_oid = self.smd.getTrapNumOidBySymbols(self.args['<mib-name>'], self.args['<trap-name>'])
            trap = self.createDummyTrap(trap_oid)
            self.sendTrap(trap)
        else:
            assert False, "Major Code Error"

    def createDummyTrap(self, num_oid):
        trap = {
            'trap_oid': num_oid,
            'var_binds': [],
        }
        trap_oid = num_oid
        var_oids = self.smd.getVarNumOidsByTrap(trap_oid)
        for var_oid in var_oids:
            type_str = self.smd.getTypeByNumOid(var_oid)
            default_value = self.getDefaultValueByType(var_oid, type_str)
            tup = (var_oid, default_value)
            trap['var_binds'].append(tup)
        return trap

    def getDefaultValueByType(self, num_oid, type_str):
        map = DEFAULT_TYPE_TO_VALUE_MAP
        if type_str in map.keys():
            try:
                bare_val = map[type_str]
                default_val = self.smd.castValueByNumOidType(num_oid, bare_val)
                return default_val
            except Exception as e:
                assert "Code Error: " + str(e)
        else:
            log.warn("Unhandled SNMP default value", type=type_str)
            assert False  # fail fail fail

    def sendTrap(self, trap):
        trap_oid = trap['trap_oid']

        txAddress = self.args['--ipv6-host']
        txPort = self.args['--port']
        userData = UsmUserData('user-sha-aes128',
                               'authkey1',
                               'privkey1',
                               authProtocol=usmHMACSHAAuthProtocol,
                               privProtocol=usmAesCfb128Protocol)

        log.info("Sending SNMP Trap", address=txAddress, port=txPort)
        log.info("  Notification", name=self.smd.getNameByNumOid(trap_oid), oid=trap_oid)
        for var_bind in trap['var_binds']:
            var_oid = var_bind[0]
            var_val = var_bind[1]
            log.info("  with Object", name=self.smd.getNameByNumOid(var_oid), oid=var_oid, type=type(var_val))

        trapOid = trap['trap_oid']
        txVarBinds = trap['var_binds']
        errorIndicationTx, errorStatusTx, errorIndexTx, varBindsTx = next(
            sendNotification(SnmpEngine(OctetString(hexValue='8000000001020304')), userData,
                             Udp6TransportTarget((txAddress, txPort)), ContextData(), 'trap',
                             NotificationType(ObjectIdentity(trapOid)).addVarBinds(*txVarBinds)))
        if errorIndicationTx:
            print(errorIndicationTx)
        else:
            for varBindTx in varBindsTx:
                print(' = '.join([x.prettyPrint() for x in varBindTx]))


def main():
    args = docopt(__doc__)
    t = SnmpTrapGen(args)
    t.run()


if __name__ == "__main__":
    main()
