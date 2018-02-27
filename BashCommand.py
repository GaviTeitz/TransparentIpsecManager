#!/usr/bin/python
#written by Gavi - gavi@mellanox.com

import subprocess
import threading
import signal
import os

class BashCommand(object):
    def __init__(self, command, undoCommand = None, errorHandler = None):
        self.command = command
        self.undoCommand = undoCommand
        self.errorOutput = None
        self.output = None
        self.errorHandler = errorHandler if errorHandler != None else self.defaultErrorHandler

    def defaultErrorHandler(self, errorOutput):
        raise RuntimeError(self.errorOutput)

    def executeCommand(self):
        subproc = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.output, self.errorOutput = tuple(output.strip() for output in subproc.communicate())
        return subproc.returncode

    def execute(self):
        if self.executeCommand() != 0:
            self.errorHandler(self.errorOutput)

    def undo(self):
        if self.undoCommand:
            subprocess.Popen(self.undoCommand, shell=True)

class TimeoutException(Exception):
    pass

class TimedBashCommand(BashCommand):
    def __init__(self, command, undoCommand = None, errorHandler = None, timeout = 10):
        super(TimedBashCommand, self).__init__(command, undoCommand, errorHandler)
        self.timeout = timeout

    #Override
    def executeCommand(self):
        def target():
            self.subproc = subprocess.Popen(self.command, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.output, self.errorOutput = tuple(output.strip() for output in self.subproc.communicate())

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(self.timeout)
        if thread.is_alive():
            os.killpg(os.getpgid(self.subproc.pid), signal.SIGTERM)
            thread.join()
            raise TimeoutException()
        return self.subproc.returncode
