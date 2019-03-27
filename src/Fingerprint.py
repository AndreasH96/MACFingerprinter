import pyshark
import datetime
import json
from math import *
import numpy
from PacketComparator_Jaccard import JaccardComparator



class FingerPrint:

    """
    FingerPrint is used to generate a fingerprint for a randomized MAC-address
    The fingerprint is currently based only on what SSIDs the device sends probe request to.
    """

    def __init__(self,SSID= None, MAC= None, timeStamp=datetime.datetime.now(), OUI=None):

        """
        Takes in the first SSID the MAC address has transmitted a probe request to
        Takes in the MAC address to hash it if the device is using it's global
        TimeStamp[0] is a Time Stamp for the initiation of the Fingerprint
        TimeStamp[1] is a Time Stamp for the latest time a SSID was added to the fingerprint
        :param SSID:
        """
        self.TimeStamp = [timeStamp, 0]
        if MAC != None:
            self.fingerHash= hash(MAC)

        else:
            self.fingerHash = 0
        self.SSIDArray = [str(SSID)]

        if(OUI != None):
            self.OUI = OUI
        self.HTCapabilities = None
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

            self.fingerHash = hash(str(self.SSIDArray))

            if(self.OUI != None):
                self.fingerHash = hash(str(self.SSIDArray) + str(self.OUI))
            else:
                self.fingerHash = hash(str(self.SSIDArray))
    
    def updateTimeStamp(self, timeStamp):

        """
         Updates TimeStamp[1] to the current date and time
        """
        self.TimeStamp[1] = timeStamp

    def mergeFingerPrints(self, fingerprint):
        for ssid in fingerprint.getSSIDArray():
            if ssid not in self.SSIDArray:
                self.addSSID(ssid)

class MACFingerPrinter:
    """
    This program creates a python Dictionary with Randomized MAC-addresses as keys and Fingerprints as items. This is used
    to count mobile devices more accurately.
    """
    def __init__(self):
        """
        ----------------------Initiates the Dictionary------------------------------------
        """
        try:
            file = input("Enter file path to a .pcapng file: ")
            self.packets = pyshark.FileCapture(input_file=file)
        except:
            print("Could not find packet file!")

        with open("../assets/OUIs.json") as JSON_DATA:
            self.OUIs = json.load(JSON_DATA)
        self.MAC_Fingerprints = {}
        self.LogicalBitSetSigns =['2','3','6','7','a','b','e','f']
        self.UniqueDevices = []
        self.JaccardComparator = JaccardComparator()
        #TEMPORARY TEST ARRAY
        self.AllPackets = {}

    def appendToDict(self, inputMAC, inputSSID,inputOUI,inputHTCap, timeStamp):
        """
        Adds the MAC and SSID to the dictionary if the MAC is new
        Adds SSID to corresponding MAC if the SSID has not been read to that MAC earlier
        :param inputMAC: MAC address read from probe request
        :param inputSSID: SSID read from probe request
        """

        if((str(inputMAC))[1] in self.LogicalBitSetSigns):

            if inputMAC in self.MAC_Fingerprints.keys() and inputSSID not in self.MAC_Fingerprints[inputMAC].getSSIDArray():
                newFingerprint = self.MAC_Fingerprints[inputMAC]
                newFingerprint.addSSID(inputSSID, timeStamp)
                newFingerprint.addHTCapabilities(inputHTCap)
                self.MAC_Fingerprints[inputMAC] = newFingerprint
            else:
                fingerPrint = FingerPrint(SSID = inputSSID,OUI=inputOUI, timeStamp=timeStamp)
                fingerPrint.addHTCapabilities(inputHTCap)
                self.MAC_Fingerprints[inputMAC] = fingerPrint
        else:
            if inputMAC not in self.MAC_Fingerprints.keys():
                newFingerprint = FingerPrint(SSID = inputSSID, MAC=inputMAC,OUI = inputOUI, timeStamp=timeStamp)
                self.MAC_Fingerprints[inputMAC] = newFingerprint

    def calcDeviceAmount(self):
        """
        Compares hashes of the Fingerprints to estimate amount of devices
        :return: Estimated amount of devices
        """
        amount = 0
        readItems = []
        for dictItem in self.MAC_Fingerprints.items():
            if not (dictItem[1].getHash()  in readItems):
                readItems.append(dictItem[1].getHash())
                amount = amount +1
        return amount

    def readMACAddresses(self):
        Probe_Request_Type = 4
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
                if int(packet.wlan.fc_type_subtype) == Probe_Request_Type:
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
                            extCapField = []

                            tempOcts = []
                            for extCapBit in range(0,64):
                                try:
                                    exec('tempOcts.append('  + 'packet[3].extcap_b'+str(extCapBit) +')')
                                    if "x" in tempOcts[extCapBit]:
                                        tempOcts[extCapBit] = int(tempOcts[extCapBit][2:])
                                    if (extCapBit % 8 == 0) and extCapBit > 0:
                                        extCapField.append(tempOcts[extCapBit-8:extCapBit])

                                except:
                                    pass
                            #print(extCapField)


                            self.AllPackets[packet.wlan.ta] = packet
                            self.appendToDict(packet.wlan.ta, ssid,oui,htCap, packet.sniff_time)

                        else:
                            nossid = True
                    except:
                        pass

    def processFingerprints(self):
        readItems = []
        for dictItem in self.MAC_Fingerprints.items():
            if not (dictItem[1].getHash()  in readItems):
                readItems.append(dictItem[1].getHash())
                self.UniqueDevices.append(dictItem)

        for packet1 in self.UniqueDevices:
            for packet2 in self.UniqueDevices:
                data1 = packet1[1]
                data2 = packet2[1]
                jaccard = self.JaccardComparator.comparePackets(packet1[1],packet2[1])
                print("Jaccard similarity of packets {} and {} is : {}".format(packet1[0], packet2[0], jaccard))
                if(0.5 < jaccard <1 ):
                    packet1[1].mergeFingerPrints(packet2[1])
                    self.UniqueDevices.remove(packet2)
                    break

    def calcJaccard_Similarity(self,object1,object2):
        intersection_cadrinality = len(set.intersection(*[set(object1),set(object2)]))
        union_cardinality = len(set.union(*[set(object1),set(object2)]))
        return intersection_cadrinality/float(union_cardinality)

    def presentUniqueDevices(self):
        """
        Presents Amount of read devices and the different MAC Addresses with Fingerprints.
        """
        Fingerprinter.processFingerprints()
        print("Amount of devices discovered: {}".format(len(self.UniqueDevices)))
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
Fingerprinter = MACFingerPrinter()
Fingerprinter.readMACAddresses()

Fingerprinter.presentUniqueDevices()
