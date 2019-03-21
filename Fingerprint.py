import pyshark
import datetime
class FingerPrint:

    """
    FingerPrint is used to generate a fingerprint for a randomized MAC-address
    The fingerprint is currently based only on what SSIDs the device sends probe request to.
    """
    def __init__(self,SSID= None, MAC= None):
        """
        Takes in the first SSID the MAC address has transmitted a probe request to
        Takes in the MAC address to hash it if the device is using it's global
        TimeStamp[0] is a Time Stamp for the initiation of the Fingerprint
        TimeStamp[1] is a Time Stamp for the latest time a SSID was added to the fingerprint
        :param SSID:
        """
        self.TimeStamp = [datetime.datetime.now(),datetime.datetime.now()]
        if((SSID == None) and (MAC != None)):
            self.fingerHash= hash(MAC)
            self.SSIDArray =None
        else:
            self.fingerHash = 0
            self.SSIDArray = [SSID]
            self.hashFingerPrint()

    def addSSID(self,SSID):
        """
        Adds the SSID to the SSID Array, sorts the array, generates new hash and updates timestamp
        :param SSID: SSID from probe request
        """
        self.SSIDArray.append(SSID)
        self.SSIDArray.sort()
        self.hashFingerPrint()
        self.updateTimeStamp()

    def get_SSIDArray(self):
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
            self.fingerHash = hash(str(self.SSIDArray))
    def updateTimeStamp(self):
        """
         Updates TimeStamp[1] to the current date and time
        """
        self.TimeStamp[1] = datetime.datetime.now()

class MACFingerPrinter:
    """
    This program creates a python Dictionary with Randomized MAC-addresses as keys and Fingerprints as items. This is used
    to count mobile devices more accurately.
    """
    def __init__(self):
        """
        Initiates the Dictionary
        """
        try:
            self.packets = pyshark.FileCapture('SniffFree8plus_7Plus_6Plus_HTC.pcapng')
        except:
            print("Could not find packet file!")

        self.MAC_Fingerprints = {}
        self.LogicalBitSetSigns =['2','3','6','7','a','b','e','f']
    def appendToDict(self, inputMAC, inputSSID):
        """
        Adds the MAC and SSID to the dictionary if the MAC is new
        Adds SSID to corresponding MAC if the SSID has not been read to that MAC earlier
        :param inputMAC: MAC address read from probe request
        :param inputSSID: SSID read from probe request
        """
        if((str(inputMAC))[1] in self.LogicalBitSetSigns):

            if inputMAC in self.MAC_Fingerprints.keys() and inputSSID not in self.MAC_Fingerprints[inputMAC].get_SSIDArray():
                newFingerprint = self.MAC_Fingerprints[inputMAC]
                newFingerprint.addSSID(inputSSID)
                self.MAC_Fingerprints[inputMAC] = newFingerprint
            else:
                fingerPrint = FingerPrint(SSID = inputSSID)
                self.MAC_Fingerprints[inputMAC] = fingerPrint
        else:
            if inputMAC not in self.MAC_Fingerprints.keys():
                newFingerprint = FingerPrint(MAC=inputMAC)
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
                print(
                    "MAC-Address:{} --- Fingerprint:{} --- First Timestamp: {} --- Last Modified Timestamp: {} --- Hash: {}"
                    .format(dictItem[0], dictItem[1].get_SSIDArray(), dictItem[1].getTimeStamp()[0], dictItem[1].getTimeStamp()[1],
                            dictItem[1].getHash()))
        return amount

    def readMACAddresses(self):
        """
        Reads probe requests packets and extracts valuable parts
        """
        for packet in self.packets:
            if "wlan_mgt" in packet:
                nossid = False
                if not str(packet.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
                    ssid = packet.wlan_mgt.ssid
                    self.appendToDict(packet.wlan.ta, ssid)
                else:
                    nossid = True


            else:
                nossid = False
                try:
                    if not str(packet[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
                        ssid = packet[3].ssid
                        self.appendToDict(packet.wlan.ta, ssid)#,vendor)

                        vendor = packet.wlan.tag.vendor.data
                        print(vendor)
                    else:
                        nossid = True
                except:
                    pass

    def present(self):
        """
        Presents Amount of read devices and the different MAC Addresses with Fingerprints.
        """
        print("Amount of devices discovered: {}".format(self.calcDeviceAmount()))
 #       for item in self.MAC_Fingerprints.items():
 #           print ( "MAC-Address:{} --- Fingerprint:{} --- First Timestamp: {} --- Last Modified Timestamp: {} --- Hash: {}"
  #                  .format(item[0],item[1].get_SSIDArray(), item[1].getTimeStamp()[0],item[1].getTimeStamp()[1] ,item[1].getHash()) )

Fingerprinter = MACFingerPrinter()
Fingerprinter.readMACAddresses()
Fingerprinter.present()