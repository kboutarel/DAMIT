#!/usr/bin/env python2

import sys
import threading
import subprocess

TIMER = 10

def execute_reset(cli, thrift_port, register_name):
    cmd = [cli, "--thrift-port", str(thrift_port), "-c",
           "register_reset %s" % register_name]
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print e
        print e.output
    threading.Timer(TIMER, execute_reset, [cli, thrift_port, register_name]).start()


if __name__ == "__main__":
    cli, thrift_port, register_name = sys.argv[1:4]
    thrift_port = int(thrift_port)
    execute_reset(cli, thrift_port, register_name)
