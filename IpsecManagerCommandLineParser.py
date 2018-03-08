#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

import re
from collections import OrderedDict
from os import linesep

class HelpRequestedException(Exception):
    pass

class InsufficientInputException(Exception):
    pass

class IpsecManagerCommandLineParser(object):
    def __init__(self):
        def ipAddressIsValid(ipAddress):
            if not re.search(r'^(\d+\.){3}\d+$', ipAddress):
                return False

            for ipField in ipAddress.split('.'):
                if int(ipField) > 255:
                    return False
            return True

        def ipAddressWithNetmaskIsValid(ipAddress):
            if not re.search(r'^(\d+\.){3}\d+/\d+$', ipAddress):
                return False

            ip, netmask = tuple(ipAddress.split('/'))
            return ipAddressIsValid(ip) and int(netmask) <= 32

        self.commandsAndParams = OrderedDict([('createIpsecGateway',  OrderedDict([('ovsBridge',        lambda _: True),
                                                                                   ('gatewayIp',        ipAddressWithNetmaskIsValid)])),
                                              ('destroyIpsecGateway', {}),
                                              ('addIpsecTunnel',      OrderedDict([('name',             lambda _: True),
                                                                                   ('sourceIp',         ipAddressIsValid),
                                                                                   ('destIp',           ipAddressIsValid),
                                                                                   ('remoteGatewayIp',  ipAddressIsValid),
                                                                                   ('localId',          lambda _: True),
                                                                                   ('remoteId',         lambda _: True)])),
                                              ('removeIpsecTunnel',   OrderedDict([('name',             lambda _: True)])),
                                              ('listIpsecTunnels',    {})])

    def parseCommandLine(self, args):
        if len(args) < 2:
            raise InsufficientInputException()

        for userInput in args:
            if userInput == 'help' or userInput == '--help' or userInput == '-h':
                raise HelpRequestedException()

        command = args[1]
        if command not in self.commandsAndParams:
            raise ValueError('Unrecognized command: ' + command + linesep + self.getGlobalHelpMessage())

        commandParams = args[2:]
        if len(self.commandsAndParams[command]) != len(commandParams):
            raise ValueError(command + ' has an incorrect amount of parameters, received ' + str(len(commandParams)) + ' instead of ' + str(len(self.commandsAndParams[command])) + linesep + 'Usage: ' + self.getCommandHelpMessage(command))

        for paramIndex, paramName in enumerate(self.commandsAndParams[command]):
            validationMethod = self.commandsAndParams[command][paramName]
            if not validationMethod(commandParams[paramIndex]):
                raise ValueError(paramName + ' has an illegal input' + linesep + 'Usage: ' + self.getCommandHelpMessage(command))

        return command, tuple(commandParams)

    def getCommandHelpMessage(self, command, padding=0):
        return ' '.join([command + ' '*padding] + ['<' + param + '>' for param in self.commandsAndParams[command]])

    def getGlobalHelpMessage(self):
        maxCommandLen = max([len(command) for command in self.commandsAndParams])
        return 'Usage: ipsecManager.py <command> [parameters]' + linesep + (linesep + '    ').join(['Commands:'] + [self.getCommandHelpMessage(command, maxCommandLen - len(command)) for command in self.commandsAndParams])
