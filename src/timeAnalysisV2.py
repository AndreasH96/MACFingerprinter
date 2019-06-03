import numpy as np
from sklearn.cluster import MeanShift


class TimeAnalyser2:

    def __init__(self):
        pass
    def hex_to_bin(self,input):
        theBytes = str.encode(input)
        ints = int(theBytes, base=16)
        return ints


    def convert_MAC_to_int(self,packet):
        MAC_Adr = packet.wlan.sa.split(":")
        value = 0
        for byte in MAC_Adr:
            value = value + self.hex_to_bin(byte)
        return value


    def calcSignature(self,IFATArray, binning):
        binMean1, binMean2, binMean3 = [0, 0, 0]
        numBin1, numBin2, numBin3 = [0, 0, 0]
        for _IFAT in IFATArray:
            if _IFAT <= binning[0]:
                binMean1 = binMean1 + _IFAT
                numBin1 += 1
            elif _IFAT > binning[0] and _IFAT <= binning[1]:
                binMean2 = binMean2 + _IFAT
                numBin2 += 1
            else:
                binMean3 = binMean3 + _IFAT
                numBin3 += 1
        return [self.divide(numBin1, len(IFATArray)), self.divide(binMean1, numBin1), self.divide(numBin2, len(IFATArray)), self.divide(binMean2, numBin2), self.divide(numBin3, len(IFATArray)), self.divide(binMean3, numBin3)]

    #--- Inter frame arrival time ---#


    def IFAT(self,packetA, packetB):
        try:
            dateTimeDelta = packetA.sniff_time - packetB.sniff_time
            return dateTimeDelta
        except:
            print("Could not calculate delta time!")
            pass


    def divide(self,a, b):
        try:
            return a / b
        except:
            return 0.0


    def packetTimeToSeconds(self,packet):
        return packet.sniff_time.hour * 60 * 60 + packet.sniff_time.minute * 60 + packet.sniff_time.second + packet.sniff_time.microsecond * pow(10, -6)


    def calcIFAT(self,packets, minDeltaTime):
        IFATArray = []
        burstSets = []
        i = 0
        try:
            while i < len(packets):
                startTime = self.packetTimeToSeconds(packets[i])

                while (i < len(packets) - 1) and (self.packetTimeToSeconds(packets[i+1]) - startTime < minDeltaTime and self.packetTimeToSeconds(packets[i+1]) - startTime >= 0):
                    #print(packetTimeToSeconds(packets[i+1]) - startTime, packets[i+1].wlan.sa + " - " + packets[i].wlan.sa)
                    if (packets[i].wlan.sa == packets[i+1].wlan.sa):
                        deltaTime = self.IFAT(packets[i+1], packets[i])
                        IFATArray.append(deltaTime.seconds +
                                         deltaTime.microseconds * pow(10, -6))
                    i += 1
                burstSets.append(IFATArray)
                IFATArray = []
                i += 1
            return burstSets
        except Exception as e:
            print(e)
            print(i)


    def processData(self,inputFile,devicesNotToProcess):
        pysharkFilter = "wlan.fc.type_subtype eq 4 && wlan.tag.vendor.oui.type == 8"

        for device in devicesNotToProcess:
            pysharkFilter = pysharkFilter +"&& wlan.ta != {}".format(device)
        pysharkFilter = pysharkFilter + " && wlan.ta != 38:0a:ab:01:07:8c"
        try:
            captureFile = inputFile
            captureFile.display_filter = pysharkFilter

            packets_Sorted = sorted(captureFile, key=self.convert_MAC_to_int)
            burstSets = self.calcIFAT(packets_Sorted, 0.7)

            signatures = []
            for burst in burstSets:
                signatures.append(self.calcSignature(burst, [0.15, 0.3, 0.45]))

            ms = MeanShift()
            ms.fit(signatures)
            labels = ms.labels_
            cluster_centers = ms.cluster_centers_

            n_clusters_ = len(np.unique(labels))

            print("Num clusters", n_clusters_)
            print("Cluster centers:\n", cluster_centers)
            print(labels)
            return n_clusters_

        except Exception as e:
            print("Could not find packet file!")
            print(e)


