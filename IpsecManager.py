#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

import os
import re
from time import sleep

from BashCommand import BashCommand, TimedBashCommand, TimeoutException
from IpsecManagerUtilityMethods import writeToFileFromTemplate, removeLinesFromFile, interfaceExists, getMacAddr, convertIpToHex
from IpsecManagerErrorHandlers import ipRouteAddStderrHandler

class IpsecManager(object):
    def __init__(self):
        self.gatewayConfFilename  = '/etc/ipsecManager/gateway.conf'
        self.ipsecConfFilename    = '/etc/strongswan/ipsec.conf'
        self.ipsecSecretsFilename = '/etc/strongswan/ipsec.secrets'
        self.gatewayOvsPort       = 'veth_ovs'
        self.gatewayInterfaceName = 'veth_ipsec'
        self.ipsecConfTitleLine   = '### IpsecManager Tunnels ###'
        templateDirectory         = 'templates/'
        self.gatewayTemplate      = templateDirectory + 'gateway.template'
        self.ipsecConfTemplate    = templateDirectory + 'ipsec.conf.template'
        self.ipsecSecretsTemplate = templateDirectory + 'ipsec.secrets.template'

    # Creates infrastructure for a new transparent IPSEC Gateway with the given ip address, which will be synchronized with the given OVS bridge.
    def createIpsecGateway(self, ovsBridge, gatewayIp):
        if interfaceExists(self.gatewayInterfaceName):
            raise RuntimeError('A gateway already exists')

        gatewayCreationCommands = [BashCommand('ip link add ' + self.gatewayOvsPort + ' type veth peer name ' + self.gatewayInterfaceName, 'ip link delete ' + self.gatewayOvsPort),
                                   BashCommand('ovs-vsctl add-port ' + ovsBridge + ' ' + self.gatewayOvsPort, 'ovs-vsctl del-port ' + ovsBridge + ' ' + self.gatewayOvsPort),
                                   BashCommand('ip link set ' + self.gatewayOvsPort + ' up'),
                                   BashCommand('ip link set ' + self.gatewayInterfaceName + ' up'),
                                   BashCommand('echo 1 > /proc/sys/net/ipv4/ip_forward'),
                                   BashCommand('ip addr add ' + gatewayIp + ' dev ' + self.gatewayInterfaceName),
                                   BashCommand('strongswan start', 'strongswan stop')]

        for index, command in enumerate(gatewayCreationCommands):
            try:
#                 command.announce()
                command.execute()
            except BaseException as e:
                for completedCommand in reversed(gatewayCreationCommands[:index]):
                    completedCommand.undo()
                sleep(1)
                raise RuntimeError((os.linesep + '    ').join(['Failed to execute \'' + command.command + '\':'] + str(e).split(os.linesep)))

        if not os.path.exists('/'.join(self.gatewayConfFilename.split('/')[:-1])):
            os.makedirs('/'.join(self.gatewayConfFilename.split('/')[:-1]))

        writeToFileFromTemplate(self.gatewayTemplate, open(self.gatewayConfFilename, 'w'), {'GATEWAY_IP'  : gatewayIp,
                                                                                            'GATEWAY_MAC' : getMacAddr(self.gatewayInterfaceName),
                                                                                            'OVS_BRIDGE'  : ovsBridge})
        if not re.search(r'^' + self.ipsecConfTitleLine + r'$', open(self.ipsecConfFilename, 'r').read(), re.MULTILINE):
            open(self.ipsecConfFilename, 'a').write(os.linesep + self.ipsecConfTitleLine + os.linesep)

    # Removes an existing transparent IPSEC Gateway, and removes any IPSEC tunnels associated with it
    def destroyIpsecGateway(self):
        if not interfaceExists(self.gatewayInterfaceName):
            raise RuntimeError('There is no local gateway')

        for tunnelName in self.getIpsecTunnelNames():
            self.removeIpsecTunnel(tunnelName)

        BashCommand('ovs-vsctl del-port ' + self.getOvsBridgeFromGatewayConf() + ' ' + self.gatewayOvsPort).execute()
        BashCommand('ip link delete ' + self.gatewayOvsPort).execute()
        BashCommand('strongswan stop').execute()
        os.remove(self.gatewayConfFilename)

    # Adds a new transparent IPSEC tunnel, from the given source ip address to the given destination ip address, with the given ids
    def addIpsecTunnel(self, name, sourceIp, destIp, remoteGateway, localId, remoteId):
        if not interfaceExists(self.gatewayInterfaceName):
            raise RuntimeError('There is no local gateway')

        for currentTunnelName, currentSourceIp, currentDestIp in self.listIpsecTunnels():
            if name == currentTunnelName:
                raise RuntimeError('A tunnel named ' + name + ' already exists')
            if sourceIp == currentSourceIp and destIp == currentDestIp:
                raise RuntimeError('A tunnel from ' + sourceIp + ' to ' + destIp + ' already exists')

        localGatewayIp = self.getLocalGatewayIpFromGatewayConf()
        ovsBridge = self.getOvsBridgeFromGatewayConf()
        localGatewayMacAddress = self.getLocalGatewayMacAddressFromGatewayConf()

        # Update the strongswan configuration files:
        writeToFileFromTemplate(self.ipsecConfTemplate, open(self.ipsecConfFilename, 'a'), {'LOCAL_GATEWAY_IP'  : localGatewayIp,
                                                                                            'REMOTE_GATEWAY_IP' : remoteGateway,
                                                                                            'SOURCE_IP'         : sourceIp,
                                                                                            'DEST_IP'           : destIp,
                                                                                            'LOCAL_ID'          : localId,
                                                                                            'REMOTE_ID'         : remoteId,
                                                                                            'TUNNEL_NAME'       : name})
        writeToFileFromTemplate(self.ipsecSecretsTemplate, open(self.ipsecSecretsFilename, 'a'), {'LOCAL_ID'    : localId,
                                                                                                  'REMOTE_ID'   : remoteId,
                                                                                                  'TUNNEL_NAME' : name})

        # Add an openFlow rule to forward packets coming from the sourceIp to the IPSEC module, via the gateway interface veth-pair:
        BashCommand('ovs-ofctl add-flow ' + ovsBridge + ' table=0,ip,nw_src=' + sourceIp + ',nw_dst=' + destIp + ',action=mod_dl_dst:' + localGatewayMacAddress + ',' + self.gatewayOvsPort).execute()
        # Add an openFlow rule to respond to spoof ARP requests coming from the gateway interface directed at the sourceIp to have appear as if they were generated from the destIp:
        BashCommand(self.getArpIpSpoofingRule(ovsBridge, sourceIp, destIp)).execute()
        # Add an entry to the routing table, allowing the IPSEC module to forward packets to the source IP via the gateway interface:
        BashCommand('ip route add ' + sourceIp + '/32 via 0.0.0.0 dev ' + self.gatewayInterfaceName, errorHandler=ipRouteAddStderrHandler).execute()
        # Update strongswan based on the newly written configuration files:
        BashCommand('strongswan update').execute()
        BashCommand('strongswan secrets').execute()
        # Raise the new tunnel:
        upCommand = TimedBashCommand('strongswan up ' + name, timeout=5)
        try:
            upCommand.execute()
        except TimeoutException:
            raise RuntimeError('Tunnel \'' + name + '\' is set up locally, but the remote gateway couldn\'t be reached')
        if 'connection \'' + name + '\' established successfully' not in upCommand.output:
            if 'AUTHENTICATION_FAILED' in upCommand.output or 'NO_PROPOSAL_CHOSEN' in upCommand.output:
                raise RuntimeError('Tunnel \'' + name + '\' is set up, but the connection couldn\'t be authenticated on the other side')
            else:
                self.removeIpsecTunnel(name)
                raise RuntimeError('Failed to set up the tunnel' + os.linesep + (os.linesep + '    ').join(['strongswan up ' + name + '\'s output:'] + upCommand.output.split(os.linesep)))

    # Removes a transparent IPSEC tunnel with the given name
    def removeIpsecTunnel(self, name):
        def secretsLineMatchesTunnel(line):
            return bool(re.search(r'# ' + name + r'$', line))

        def confLineStartsTunnel(line):
            return bool(re.search(r'^conn ' + name + r'$', line))

        def confLineStartsNextTunnel(line):
            return bool(re.search(r'^conn \S', line)) and not confLineStartsTunnel(line)

        if name not in self.getIpsecTunnelNames():
            raise RuntimeError('No tunnel named ' + name + ' exists')

        ovsBridge = self.getOvsBridgeFromGatewayConf()
        sourceIp  = self.getSourceIpFromIpsecConf(name)
        destIp    = self.getDestIpFromIpsecConf(name)

        removeLinesFromFile(self.ipsecSecretsFilename, secretsLineMatchesTunnel, lambda line: not secretsLineMatchesTunnel(line))
        removeLinesFromFile(self.ipsecConfFilename, confLineStartsTunnel, confLineStartsNextTunnel)

        BashCommand('strongswan update').execute()
        BashCommand('strongswan secrets').execute()
        BashCommand('strongswan down ' + name).execute()

        BashCommand('ovs-ofctl del-flows ' + ovsBridge + ' table=0,ip,nw_src=' + sourceIp + ',nw_dst=' + destIp).execute()
        BashCommand('ovs-ofctl del-flows ' + ovsBridge + ' table=0,arp,nw_dst=' + sourceIp + ',in_port=' + self.gatewayOvsPort).execute()

        if self.anotherTunnelSharesSourceIp(name, sourceIp):
            _, _, alternateDestIp = self.getTunnelThatSharesSourceIp(name, sourceIp)
            BashCommand(self.getArpIpSpoofingRule(ovsBridge, sourceIp, alternateDestIp)).execute()
        else:
            BashCommand('ip route del ' + sourceIp + '/32').execute()

    # Returns a list of the transparent IPSEC tunnels in existence
    # Each tunnel is represented by a tuple with the tunnel's name, source ip adresss and destination ip address
    def listIpsecTunnels(self):
        tunnelEntryLen = len(open(self.ipsecConfTemplate).readlines())
        ipsecTunnels = []
        tunnelTitleLineRegex = r'^conn (?P<tunnelName>\S+)$'
        ipsecConfFileLines = open(self.ipsecConfFilename).readlines()
        ipsecConfTitleLineFound = False
        for lineIndex, line in enumerate(ipsecConfFileLines):
            if not ipsecConfTitleLineFound:
                ipsecConfTitleLineFound = bool(re.search(r'^' + self.ipsecConfTitleLine + r'$', line.strip()))
                continue
            dataMatches = re.search(tunnelTitleLineRegex, line)
            if dataMatches:
                sourceIp, destIp = tuple(self.getIpFromTunnelLines(ipsecConfFileLines[lineIndex:lineIndex + tunnelEntryLen], keyword) for keyword in ['leftsubnet', 'rightsubnet'])
                ipsecTunnels.append((dataMatches.group('tunnelName'), sourceIp, destIp))

        return ipsecTunnels

    def getIpsecTunnelNames(self):
        return [tunnelName for tunnelName, _, _ in self.listIpsecTunnels()]

    def getLocalGatewayIpFromGatewayConf(self):
        return re.search(r'gatewayIp\s+:\s+(?P<localGatewayIp>(\d+\.){3}\d+)', open(self.gatewayConfFilename).read()).group('localGatewayIp')

    def getOvsBridgeFromGatewayConf(self):
        return re.search(r'ovsBridge\s+:\s+(?P<ovsBridge>\S+)', open(self.gatewayConfFilename).read()).group('ovsBridge')

    def getLocalGatewayMacAddressFromGatewayConf(self):
        return re.search(r'gatewayMac\s+:\s+(?P<localGatewayMacAddress>([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', open(self.gatewayConfFilename).read()).group('localGatewayMacAddress')

    def getArpIpSpoofingRule(self, ovsBridge, sourceIp, destIp):
        return 'ovs-ofctl add-flow ' + ovsBridge + ' "table=0, arp, nw_dst=' + sourceIp + ', in_port=' + self.gatewayOvsPort + ', actions=load:0x' + convertIpToHex(destIp) + '->NXM_OF_ARP_SPA[], normal"'

    def getIpFromTunnelLines(self, tunnelLines, keyword):
        for line in tunnelLines:
            dataMatches = re.search(keyword + r'=(?P<Ip>(\d+\.){3}\d+)', line.strip())
            if dataMatches:
                return dataMatches.group('Ip')

    def getIpFromIpsecConf(self, tunnelName, keyword):
        tunnelEntryLen = len(open(self.ipsecConfTemplate).readlines())
        ipsecConfFileLines = open(self.ipsecConfFilename).readlines()
        for lineIndex, line in enumerate(ipsecConfFileLines):
            if re.search(r'^conn ' + tunnelName + r'$', line):
                return self.getIpFromTunnelLines(ipsecConfFileLines[lineIndex:lineIndex + tunnelEntryLen], keyword)

    def getSourceIpFromIpsecConf(self, tunnelName):
        return self.getIpFromIpsecConf(tunnelName, 'leftsubnet')

    def getDestIpFromIpsecConf(self, tunnelName):
        return self.getIpFromIpsecConf(tunnelName, 'rightsubnet')

    def getTunnelThatSharesSourceIp(self, tunnelName, sourceIp):
        for currentTunnelName, currentSourceIp, currentDestIp in self.listIpsecTunnels():
            if tunnelName != currentTunnelName and sourceIp == currentSourceIp:
                return currentTunnelName, currentSourceIp, currentDestIp
        return None

    def anotherTunnelSharesSourceIp(self, tunnelName, sourceIp):
        return bool(self.getTunnelThatSharesSourceIp(tunnelName, sourceIp))
