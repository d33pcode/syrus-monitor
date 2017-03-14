#!/usr/bin/env python
# coding=utf-8

import ast
import requests
import socket
import socket
import sys
import threading
from datetime import datetime


class PortScanner(object):

    threads = []

    def __init__(self, config, logfile):
        socket_codes = self.getSocketCodes()
        start_time = datetime.now()
        out = "PortScanner started at {}\n\n".format(start_time)
        print(out)
        if logfile:
            logfile.write(out)
            logfile.flush()
        for address in config:
            if config[address]:
                t = threading.Thread(target=self.scanPorts,
                                     args=(address, config[address], logfile, True))
                self.threads.append(t)
                t.start()
            else:

                allports = range(1,1025)
                sliced_ports = []
                while allports: # getting ports in batches of 20
                    slice = allports[:20]
                    sliced_ports.append(slice)
                    allports = [p for p in allports if p not in slice]
                for ports in sliced_ports:
                    t=threading.Thread(target=self.scanPorts,
                                         args=(address, ports, logfile, False))
                    self.threads.append(t)
                    t.start()
        while threading.enumerate():
            pass
        end_time=datetime.now()
        out="Scanning completed in {}".format(end_time - start_time)
        print(out)
        if logfile:
            logfile.write(out)
            logfile.close()

    def scanPorts(self, host, ports, logfile, detailed):
        '''
        Tries to open a socket and logs the result.
        host, ports:
            the address and the ports to test
        logfile:
            the file in which to write the results
        detailed:
            if True, the TCP result code is logged for every port.
            if False, only the open ports will be registered.
        '''
        try:
            if detailed:
                codes=self.getSocketCodes()
                for port in ports:
                    sock=socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    result=sock.connect_ex((host, int(port)))
                    out="[{0}] Port {1} returned code {2}: {3}\n".format(host,
                                                                           port,
                                                                           result,
                                                                           codes[result])
                    print out
                    if logfile:
                        logfile.write(out)
                        logfile.flush()
            else:
                for port in ports:
                    print("testing {0}:{1}".format(host, port))
                    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result=sock.connect_ex((host, int(port)))
                    sock.close()
                    if result == 0:
                        out='[{0}] Port {1} is open\n'.format(host, port)
                        print out
                        if logfile:
                            logfile.write(out)
                            logfile.flush()

        except KeyboardInterrupt:
            out += "WARNING: You pressed Ctrl+C."
            if logfile:
                logfile.write(out)
                logfile.flush()
        except socket.gaierror:
            out += 'Hostname could not be resolved. Exiting'
            if logfile:
                logfile.write(out)
                logfile.flush()
            sys.exit()

        except socket.error:
            print "Couldn't connect to server"
            sys.exit()

    def getSocketCodes(self):
        res=requests.get(
            "https://gist.githubusercontent.com/d33pcode/2542a87dd80ba35dbffd2cffbb65b53a/raw/8a137eae6bd56ad0e55d8ea3cf1b590ef25698fe/socketcodes.txt")
        return ast.literal_eval(res.content)


def main():
    test_list=readConf('addresslist.conf')
    output=open('scan.log', 'w')
    PortScanner(test_list, output)


def readConf(path):
    with open(path, 'r') as f:
        content=f.read()
    return ast.literal_eval(content)

if __name__ == '__main__':
    main()
