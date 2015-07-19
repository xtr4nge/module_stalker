#!/usr/bin/env python

# Copyright (C) 2015 xtr4nge [_AT_] gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from scapy.all import *

import sys, getopt
from datetime import datetime, timedelta
import logging

# AUDIO
import math
import pyaudio

# ------------------------------------
# HELP
# ------------------------------------
gVersion = "1.0"

def usage():
    print "\nFruityWifi Stalker " + gVersion + " by @xtr4nge"
    
    print "Usage: ./stalker.py -i INTERFACE -m MAC <options>\n"
    print "Options:"
    print "-i INTERFACE              WLAN Interface (monitor mode required)"
    print "-m MAC                    MAC address to be stalked"
    print "-t TIME                   Target gone time (default 10 seconds)"
    print "-l LOG                    Log path (default ./stalker.log)"
    print "-h                        This help"
    print ""
    print "FruityWifi: http://www.fruitywifi.com"
    print ""

def parseOptions(argv):
    valueInterface = ""
    valueMAC       = ""
    valueTIME      = 10
    valueLOG       = "./stalker.log"
    
    try:                                
        opts, args = getopt.getopt(argv, "hi:m:t:l:", ["help","interface=","mac=","time=","log="])
        
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-i", "--interface"):
                valueInterface = arg
            elif opt in ("-m", "--mac"):
                valueMAC = arg
            elif opt in ("-t", "--time"):
                valueTIME = arg
            elif opt in ("-l", "--log"):
                valueLOG = arg
        
        if valueInterface == "" or valueMAC == "":
            usage()
            sys.exit()
        
        return (valueInterface, valueMAC, valueTIME, valueLOG)
                    
    except getopt.GetoptError:
        usage()
        sys.exit(2)

(valueInterface, valueMAC, valueTIME, valueLOG) = parseOptions(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger('fruitywifi-stalker')
fileHandler = logging.FileHandler(valueLOG)
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

class Stalker(object):
    
    def __init__(self, valueMAC, valueTIME):
        self.theTime = datetime.now()
        self.targetIsHere = False
        self.lastTimePresent = datetime.now()
        self.mac_target = valueMAC
        self.valueTime = valueTIME
        
        print "Stalking: " + str(self.mac_target)
        logger.debug("[Stalker] ["+self.mac_target+"] Stalker Mode ON")

    def handle_pkt(self, pkt):
        
        self.theTime = datetime.now()
        
        if Dot11 in pkt and (str(self.mac_target).lower() == pkt[Dot11].addr2 or str(self.mac_target).lower() == pkt[Dot11].addr1):
            try:
                hwaddr = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt][0].info
                hwaddr1 = pkt[Dot11].addr1
                
                signal_strength = -(256 - ord(pkt.notdecoded[-4:-3]))

            except KeyboardInterrupt:
                print "Shutdown requested...exiting"
                sys.exit(0)
                
            except Exception as e:
                pass
                print e
                
            if self.targetIsHere == False:
                print " + Target present"
                logger.debug("[Stalker] ["+self.mac_target+"] Target present")
                self.targetIsHere = True
                self.playAudio(1000)
                self.playAudio(1000)
                self.lastTimePresent = datetime.now()
                
            elif (self.theTime - self.lastTimePresent) > timedelta(seconds=2):
                logger.debug("[Stalker] ["+self.mac_target+"]")
                self.playAudio(900)
                self.lastTimePresent = datetime.now()
            else: 
                self.lastTimePresent = datetime.now()
                
        else:
            if (self.theTime - self.lastTimePresent) > timedelta(seconds=int(valueTIME)):
                if self.targetIsHere:
                    print "- Target gone"
                    logger.debug("[Stalker] ["+self.mac_target+"] Target gone")
                    #print self.theTime
                    self.targetIsHere = False
                    self.playAudio(600)
                    self.playAudio(500)
    
    def playAudio(self, wave):
        try:
            PyAudio = pyaudio.PyAudio
            RATE = 16000
            WAVE = wave #original: 1000
            data = ''.join([chr(int(math.sin(x/((RATE/WAVE)/math.pi))*127+128)) for x in xrange(RATE)])
            p = PyAudio()
            
            stream = p.open(format =
                            p.get_format_from_width(1),
                            channels = 1,
                            rate = RATE,
                            output = True)
            for DISCARD in xrange(1):
                stream.write(data)
            stream.stop_stream()
            stream.close()
            p.terminate()
        except Exception:
            print "error..."
    

stalker = Stalker(valueMAC, valueTIME)

conf.iface = valueInterface

sniff(prn=stalker.handle_pkt, store=0)