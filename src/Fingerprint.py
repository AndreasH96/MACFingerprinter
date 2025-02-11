import pyshark
import datetime
import json
from PacketComparator import PacketComparator
from timeAnalysis import TimeAnalyser
from timeAnalysisV2 import TimeAnalyser2
import wx
from pyshark.capture.capture import Capture
import ctypes
import pyshark.tshark as tshark
class FingerPrint:

    """
    FingerPrint is used to generate a fingerprint for a randomized MAC-address
    The fingerprint is currently based only on what SSIDs the device sends probe request to.
    """

    def __init__(self,SSID= None, MAC= None, timeStamp=datetime.datetime.now(), OUI=None, extCap= None, htCap = None):

        """
        Takes in the first SSID the MAC address has transmitted a probe request to
        Takes in the MAC address to hash it if the device is using it's global
        TimeStamp[0] is a Time Stamp for the initiation of the Fingerprint
        TimeStamp[1] is a Time Stamp for the latest time a SSID was added to the fingerprint
        :param SSID:
        """
        self.TimeStamp = [timeStamp, timeStamp]
        self.SSIDArray = [str(SSID)]

        if(OUI != None):
            self.OUI = OUI
        self.HTCapabilities = htCap
        self.ExtendedCapabilities = extCap
        self.hashFingerPrint()
        self.maxSignalStrenght = 1000
        if(MAC != None):
            self.LocalMAC = False
        elif(MAC == None):
            self.LocalMAC = True

    def addExtendedCapabilitiesLen(self,input):
        self.ExtendedCapLen = input

    def addHTCapabilities(self,input):
        self.HTCapabilities = input
    def addSignalStrengh(self,input):
        if int(input[1:]) < self.maxSignalStrenght:
            self.maxSignalStrenght=int(input[1:])
    def getMaxSignalStrenght(self):
        return self.maxSignalStrenght
    def addSSID(self, SSID, timeStamp = None):
        """
        Adds the SSID to the SSID Array, sorts the array, generates new hash and updates timestamp
        :param SSID: SSID from probe request
        """
        if(SSID not in self.SSIDArray):
            self.SSIDArray.append(str(SSID))
            self.SSIDArray.sort()
            if timeStamp is not None:
                self.updateTimeStamp(timeStamp)
            self.hashFingerPrint()
    def getSSIDArray(self):
        """
        :return: The SSID Array of the FingerPrint
        """
        if(self.SSIDArray != None):
            return self.SSIDArray

    def getTimeStamp(self):
        """
        :return: The Array of Time Stamps
        """
        return self.TimeStamp

    def getOUI(self):
        return self.OUI

    def getHash(self):
        """
        :return: The Hash of the fingerprint
        """
        return self.fingerHash

    def hashFingerPrint(self):
        """
        Hashes the current state of the SSID Array
        """
        if(self.SSIDArray != None):
            if "SSID: " in self.SSIDArray and len(self.SSIDArray) > 1:
                self.SSIDArray.remove("SSID: ")

            if(self.OUI != None):
                self.fingerHash =   hash(str(self.SSIDArray) +str(self.HTCapabilities) + str(self.ExtendedCapabilities) + str(self.OUI))
            else:
                self.fingerHash =   hash(str(self.SSIDArray) +str(self.HTCapabilities) + str(self.ExtendedCapabilities))
    
    def updateTimeStamp(self, timeStamp):

        """
         Updates TimeStamp[1] to the current date and time
        """
        self.TimeStamp[1] = timeStamp

    def mergeFingerPrints(self, fingerprint):
        for ssid in fingerprint.getSSIDArray():
            if ssid not in self.SSIDArray:
                self.addSSID(ssid)
        if self.TimeStamp[1] < fingerprint.TimeStamp[1]:
            self.TimeStamp[1] = fingerprint.TimeStamp[1]

    def isLocalMAC(self):
        return self.LocalMAC

class MACFingerPrinter:
    """
    This program creates a python Dictionary with Randomized MAC-addresses as keys and Fingerprints as items. This is used
    to count mobile devices more accurately.
    """
    def __init__(self):
        """
        ----------------------Initiates the Dictionary------------------------------------
        """
    
        with open("/home/andreas/Documents/Programming/Python/MACFingerPrinter/MACFingerprinter/assets/OUIs.json") as JSON_DATA:
            self.OUIs = json.load(JSON_DATA)
    
        self.MAC_Fingerprints = {}
        self.LocalBitSetSigns =['2','3','6','7','a','b','e','f']
        self.UniqueDevices = []
        self.PacketComparator = PacketComparator()
        self.timeAnalyser = TimeAnalyser2()


    def appendToDict(self, inputMAC, inputSSID,inputOUI,inputHTCap,extCap ,timeStamp, signalStrenght):
        """
        Adds the MAC and SSID to the dictionary if the MAC is new
        Adds SSID to corresponding MAC if the SSID has not been read to that MAC earlier
        :param inputMAC: MAC address read from probe request
        :param inputSSID: SSID read from probe request
        """

        if((str(inputMAC))[1] in self.LocalBitSetSigns):
            if inputMAC in self.MAC_Fingerprints.keys() and inputSSID not in self.MAC_Fingerprints[inputMAC].getSSIDArray():
                newFingerprint = self.MAC_Fingerprints[inputMAC]
                newFingerprint.addSSID(inputSSID, timeStamp)
                newFingerprint.addSignalStrengh(signalStrenght)
                self.MAC_Fingerprints[inputMAC] = newFingerprint
            else:
                fingerPrint = FingerPrint(SSID = inputSSID,OUI=inputOUI, timeStamp=timeStamp, extCap = extCap,htCap=inputHTCap)
                fingerPrint.addSignalStrengh(signalStrenght)
                self.MAC_Fingerprints[inputMAC] = fingerPrint
        else:
            if inputMAC not in self.MAC_Fingerprints.keys():
                newFingerprint = FingerPrint(SSID = inputSSID, MAC=1,OUI = inputOUI, timeStamp=timeStamp, extCap = extCap,htCap= inputHTCap)
                newFingerprint.addSignalStrengh(signalStrenght)
                self.MAC_Fingerprints[inputMAC] = newFingerprint
            else:
                fingerPrint = self.MAC_Fingerprints[inputMAC]
                fingerPrint.addSSID(inputSSID)
                fingerPrint.addSignalStrengh(signalStrenght)
                self.MAC_Fingerprints[inputMAC] = fingerPrint
        self.MAC_Fingerprints[inputMAC].hashFingerPrint()

#&& wlan_radio.signal_dbm > -90
    def readMACAddresses(self,mode,selectedFile = None,consoleAddress = None,runningApplication = None):

        Probe_Request_Type = 4
        self.runningApplication = runningApplication
    
        if(mode.lower() =="file"):
            try:
                self.source = selectedFile
                self.packets = pyshark.FileCapture(input_file=self.source, display_filter= 'wlan.fc.type_subtype eq 4')
            except:
                print("Could not find packet file!")
            
        elif (mode.lower() =="live"):
            try:
        
                self.source = "wlan0mon"
                self.packets = Capture(display_filter="wlan.fc.type_subtype eq 4")
                self.packets.load_packets(timeout=20, packet_count=10)

            except Exception as e:
                print("Failed to run Live Capture, error message : {}".format(e))

        """
        Reads probe requests packets and extracts valuable parts
        """
        for packet in self.packets:

            if "wlan_mgt" in packet:
                if int(packet.wlan_mgt.fc_type_subtype) == Probe_Request_Type:
                    nossid = False
                    if not str(packet.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
                        ssid = packet.wlan_mgt.ssid

                        oui = packet.wlan_mgt.tag_oui
                        #self.appendToDict(packet.wlan.ta, ssid,oui, packet.sniff_time)
                    else:
                        nossid = True
            else:
                nossid = False
                try:
                    if not str(packet[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
                        ssid = packet[3].ssid
                        try:
                            oui = hex(int(packet[3].tag_oui))
                            oui = ("0" * (8-len(oui)) + oui[(8-len(oui)):]).upper()
                        except:
                            oui = 000000
                        try:
                            htCap = packet[3].ht_capabilities
                        except:
                            htCap = 0
                        """-------------------------Extraction of Extended Capabilities------------------------"""
                        extCapField = []
                        tempOcts = []
                        for extCapBit in range(0,64):
                            try:
                                if(extCapBit == 41):
                                    """This is done since bit 41-43 are merged together as one variable within Wireshark/Pyshark"""
                                    threeBits =  packet[3].extcap_serv_int_granularity
                                    for bit in range(0,3):
                                        exec('tempOcts.append(threeBits & 0x0' + str(2^bit)+')')
                                    extCapBit = 43
                                elif(extCapBit == 60):
                                    """This is done since Wireshark 2.6.6 has a bug where the Protected QLoad report (bit 60) is read as bit 61"""

                                    tempOcts.append('0')
                                else:
                                    exec('tempOcts.append('  + 'packet[3].extcap_b'+str(extCapBit) +')')

                                    if "x" in tempOcts[extCapBit %8]:
                                        tempOcts[extCapBit % 8] = int(tempOcts[extCapBit % 8][2:])

                                    if ((extCapBit +1) % 8 == 0) and extCapBit > 0:
                                        byteString = ""
                                        for item in range(0,8):
                                            byteString = byteString +  str(tempOcts[item])
                                        tempOcts.clear()
                                        extCapField.append(str(int((byteString[4:8])[::-1],2)) + str(int((byteString[:4])[::-1],2)))
                            except:
                                pass
                        print("Reading packet number: {}".format(packet.number))
                        
                        """------------------------------------------------------------------------------------"""
                        self.appendToDict(inputMAC= str(packet.wlan.ta),inputSSID= ssid,inputOUI= oui,inputHTCap= htCap,extCap= extCapField ,timeStamp= packet.sniff_time,signalStrenght=packet.wlan_radio.signal_dbm)
                    else:
                        nossid = True
                except:
                    pass
        return self.presentUniqueDevices()

    def processFingerprints(self):
        starttime = datetime.datetime.now()
        devices_not_to_be_time_analysed = []
        readItems = []
        for dictItem in self.MAC_Fingerprints.items():
            ssidArray = dictItem[1].getSSIDArray()
            if (ssidArray[0] != "SSID: " or (not dictItem[1].isLocalMAC()) ):#or dictItem[1].getMaxSignalStrenght()>84 :

                devices_not_to_be_time_analysed.append(dictItem[0])
            if (not (dictItem[1].getHash() in readItems)) and (dictItem[0] in devices_not_to_be_time_analysed) :#and dictItem[1].getMaxSignalStrenght()<84:
                readItems.append(dictItem[1].getHash())
                self.UniqueDevices.append(dictItem)
        timeAnalyseAmount = self.timeAnalyser.processData(self.packets,devices_not_to_be_time_analysed)

        for packetX in self.UniqueDevices:
            matches = []
            print(
                "Processing packet nr: {} of {}".format(self.UniqueDevices.index(packetX) + 1, len(self.UniqueDevices)))
            for packetY in self.UniqueDevices:
                if packetX[1].isLocalMAC() and packetY[1].isLocalMAC():
                    if (packetX[0] != packetY[0]):
                        similarity = self.PacketComparator.comparePackets(packetX[1], packetY[1])
                        print("Similarity of packets {} and {} is : {}".format(packetX[0], packetY[0], similarity))
                        if (0.8 < similarity < 1):
                            matches.append(packetY)
            for match in matches:
                packetX[1].mergeFingerPrints(match[1])
                self.UniqueDevices.remove(match)
                print("Length of UniqueDevices: {}".format(len(self.UniqueDevices)))
        print("Processing time: {} ".format(datetime.datetime.now() - starttime))
        return len(self.UniqueDevices) + timeAnalyseAmount

    def presentUniqueDevices(self):
        """
        Presents Amount of read devices and the different MAC Addresses with Fingerprints.
        """
        deviceAmount = self.processFingerprints()
        resultString = []
        print("Amount of devices discovered: {}".format(deviceAmount))
        for item in self.UniqueDevices:
            currentDevice = ""
            if item[1].getOUI() in self.OUIs.keys():

                currentDevice =(
                    "MAC-Address:{} --- Fingerprint:{} --- \nOUI: {} --- First Timestamp: {} --- Last Modified Timestamp: {}--- \nMax Signal Strenght: -{}dBm --- Hash: {}"
                        .format(item[0], item[1].getSSIDArray(), self.OUIs[item[1].getOUI()],
                                item[1].getTimeStamp()[0], item[1].getTimeStamp()[1],item[1].getMaxSignalStrenght(),item[1].getHash()))
                    
            else:   

                currentDevice =("MAC-Address:{} --- Fingerprint:{} --- OUI: {} --- First Timestamp: {} --- Last Modified Timestamp: {} --- Hash: {}"
                        .format(item[0], item[1].getSSIDArray(), item[1].getOUI(),
                                item[1].getTimeStamp()[0], item[1].getTimeStamp()[1],
                                item[1].getHash()))
                                
            #print(currentDevice)
            resultString.append(currentDevice)
        print("RETURNING")
        return [deviceAmount,resultString]

