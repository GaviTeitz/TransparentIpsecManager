#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

import re

def ipRouteAddStderrHandler(stderrOutput):
    if not re.search(r'^RTNETLINK answers: File exists$', stderrOutput.strip()):
            raise RuntimeError(stderrOutput)
