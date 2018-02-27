#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

import socket
import fcntl
import struct
from BashCommand import BashCommand

def writeToFileFromTemplate(templateFilename, destinationFile, replacementDictionary = {}):
    with open(templateFilename, 'rt') as fin:
        for line in fin:
            for key in replacementDictionary:
                line = line.replace(key, replacementDictionary[key])
            destinationFile.write(line)

def removeLinesFromFile(filename, isFirstLineToOmit, isFirstLineToContinue):
    lines = open(filename, 'r').readlines()
    outFile = open(filename, 'w+')
    inLinesToOmit = False
    for line in lines:
        if inLinesToOmit:
            inLinesToOmit = not isFirstLineToContinue(line.strip())
        else:
            inLinesToOmit = isFirstLineToOmit(line.strip())
        if not inLinesToOmit:
            outFile.write(line)

def interfaceExists(interfaceName):
    try:
        BashCommand('ip link show ' + interfaceName).execute()
        return True
    except RuntimeError as e:
        if 'does not exist' in str(e):
            return False
        raise e

def getMacAddr(interfaceName):
    SIOCGIFHWADDR = 0x8927
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', interfaceName[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def convertIpToHex(ip):
    return ''.join([format(int(ipField), '02x') for ipField in ip.split('.')])

def stripMacAddress(macAddress):
    return ''.join(macAddress.split(':'))
