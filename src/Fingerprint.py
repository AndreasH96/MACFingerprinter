import pyshark
import datetime
import json
from PacketComparator import PacketComparator
from timeAnalysis import TimeAnalyser



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

    def addExtendedCapabilitiesLen(self,input):
        self.ExtendedCapLen = input

    def addHTCapabilities(self,input):
        self.HTCapabilities = input

    def addSSID(self, SSID, timeStamp = None):
        """
        Adds the SSID to the SSID Array, sorts the array, generates new hash and updates timestamp
        :param SSID: SSID from probe request
        """
        self.SSIDArray.append(str(SSID))
        self.SSIDArray.sort()
        self.hashFingerPrint()
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
            if "SSID: " in self.SSIDArray and len(self.SSIDArray) >1:
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
class MACFingerPrinter:
    """
    This program creates a python Dictionary with Randomized MAC-addresses as keys and Fingerprints as items. This is used
    to count mobile devices more accurately.
    """
    def __init__(self):
        """
        ----------------------Initiates the Dictionary------------------------------------
        """

        with open("../assets/OUIs.json") as JSON_DATA:
            self.OUIs = json.load(JSON_DATA)
        self.MAC_Fingerprints = {}
        self.LocalBitSetSigns =['2','3','6','7','a','b','e','f']
        self.UniqueDevices = []
        self.PacketComparator = PacketComparator()
        self.timeAnalyser = TimeAnalyser()


    def appendToDict(self, inputMAC, inputSSID,inputOUI,inputHTCap,extCap ,timeStamp):
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
                self.MAC_Fingerprints[inputMAC] = newFingerprint
            else:
                fingerPrint = FingerPrint(SSID = inputSSID,OUI=inputOUI, timeStamp=timeStamp, extCap = extCap,htCap=inputHTCap)

                self.MAC_Fingerprints[inputMAC] = fingerPrint
        else:
            if inputMAC not in self.MAC_Fingerprints.keys():
                newFingerprint = FingerPrint(SSID = inputSSID, MAC=inputMAC,OUI = inputOUI, timeStamp=timeStamp, extCap = extCap,htCap= inputHTCap)
                self.MAC_Fingerprints[inputMAC] = newFingerprint
        self.MAC_Fingerprints[inputMAC].hashFingerPrint()
    def readMACAddresses(self,mode):
        Probe_Request_Type = 4
        try:
            if(mode =="File"):
                self.source = input("Enter file path to a .pcapng file: ")
                #self.source = r"C:\Users\Andreas\PycharmProjects\SSIDFingerprint\Fingerprint\SniffFree8plus_7Plus_6Plus_HTC.pcapng"
                self.packets = pyshark.FileCapture(input_file=self.source, display_filter= 'wlan.fc.type_subtype eq 4')
            elif (mode =="Live"):
                self.source = "Wi-Fi 2"
                self.packets = pyshark.LiveCapture(interface= self.source,bpf_filter="wlan.fc.type_subtype eq 4")
                self.packets.sniff(timeout=5)
                if len(self.packets ) > 0:
                    for packet in self.packets:
                        print(packet)
                print(self.packets)
        except:
            print("Could not find packet file!")


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
                        self.appendToDict(packet.wlan.ta, ssid,oui, packet.sniff_time)
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
                                        for item in  range(0,8):
                                            byteString = byteString +  str(tempOcts[item])
                                        tempOcts.clear()
                                        extCapField.append(str(int((byteString[4:8])[::-1],2)) + str(int((byteString[:4])[::-1],2)))

                            except:
                                pass
                        print("Reading packet number: {}".format(packet.number))
                        """------------------------------------------------------------------------------------"""

                        self.appendToDict(inputMAC= str(packet.wlan.ta),inputSSID= ssid,inputOUI= oui,inputHTCap= htCap,extCap= extCapField ,timeStamp= packet.sniff_time)

                    else:
                        nossid = True
                except:
                    pass
        self.presentUniqueDevices()

    def processFingerprints(self):
        starttime = datetime.datetime.now().microsecond
        devices_not_to_be_time_analysed = []
        readItems = []
        for dictItem in self.MAC_Fingerprints.items():
            ssidArray = dictItem[1].getSSIDArray()
            if  (ssidArray[0] != "SSID: "):#len(ssidArray) > 1:
                devices_not_to_be_time_analysed.append(dictItem[0])

            if (not (dictItem[1].getHash() in readItems)) and (dictItem[0] in devices_not_to_be_time_analysed):
                readItems.append(dictItem[1].getHash())
                self.UniqueDevices.append(dictItem)

        timeAnalyseAmount = self.timeAnalyser.processFile(self.packets,devices_not_to_be_time_analysed)

        for packetX in self.UniqueDevices:
            matches = []
            print(
                "Processing packet nr: {} of {}".format(self.UniqueDevices.index(packetX) + 1, len(self.UniqueDevices)))
            for packetY in self.UniqueDevices:
                if (packetX[0] != packetY[0]):
                    similarity = self.PacketComparator.comparePackets(packetX[1], packetY[1])
                    print("Similarity of packets {} and {} is : {}".format(packetX[0], packetY[0], similarity))
                    if (0.5 < similarity < 1):
                        matches.append(packetY)
            for match in matches:
                packetX[1].mergeFingerPrints(match[1])
                self.UniqueDevices.remove(match)
                print("Length of UniqueDevices: {}".format(len(self.UniqueDevices)))
        print("This took {} mikroseconds".format(datetime.datetime.now().microsecond - starttime))
        return  len(self.UniqueDevices) +timeAnalyseAmount
        #342483
    def presentUniqueDevices(self):
        """
        Presents Amount of read devices and the different MAC Addresses with Fingerprints.
        """
        deviceAmount = self.processFingerprints()
        print("Amount of devices discovered: {}".format(deviceAmount))
        for item in self.UniqueDevices:
            if item[1].getOUI() in self.OUIs.keys():

                print(
                    "MAC-Address:{} --- Fingerprint:{} --- OUI: {} --- First Timestamp: {} --- Last Modified Timestamp: {} --- Hash: {}"
                        .format(item[0], item[1].getSSIDArray(), self.OUIs[item[1].getOUI()],
                                item[1].getTimeStamp()[0], item[1].getTimeStamp()[1],
                                item[1].getHash()))
            else:
                print(
                    "MAC-Address:{} --- Fingerprint:{} --- OUI: {} --- First Timestamp: {} --- Last Modified Timestamp: {} --- Hash: {}"
                        .format(item[0], item[1].getSSIDArray(), item[1].getOUI(),
                                item[1].getTimeStamp()[0], item[1].getTimeStamp()[1],
                                item[1].getHash()))



