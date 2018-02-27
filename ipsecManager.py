#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

from IpsecManagerCommandLineParser import IpsecManagerCommandLineParser, HelpRequestedException, InsufficientInputException
from IpsecManager import IpsecManager
from sys import argv, exit
from os import linesep

if __name__ == "__main__":
    commandLineParser = IpsecManagerCommandLineParser()
    try:
        command, params = commandLineParser.parseCommandLine(argv)
    except HelpRequestedException:
        exit(commandLineParser.getGlobalHelpMessage())
    except InsufficientInputException:
        exit('Insufficient input' + linesep + commandLineParser.getGlobalHelpMessage())
    except ValueError as e:
        exit(str(e))

    ipsecManager = IpsecManager()
    try:
        returnVal = getattr(ipsecManager, command)(*params)
    except RuntimeError as e:
        exit(str(e))

    if command == 'listIpsecTunnels':
        ipsecTunnels = returnVal
        if len(ipsecTunnels) > 0:
            maxNameLen = max([len(tunnelName) for tunnelName, _, _ in ipsecTunnels])
            print (linesep + '    ').join(['Current ISPEC tunnels:'] + [tunnelName + ': ' + ' '*(maxNameLen - len(tunnelName)) + sourceIp + ' <===> ' + destIp for tunnelName, sourceIp, destIp in ipsecTunnels])
        else:
            print 'No ISPEC tunnels are currently up'
