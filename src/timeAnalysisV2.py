import pyshark
from itertools import tee, islice, chain
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import MeanShift
from decimal import Decimal
import binascii

path2 = "/home/kalle/Dropbox/KJ/Skola/Exjobb/lh9.pcapng"


def hex_to_bin(input):
    theBytes = str.encode(input)
    ints = int(theBytes, base=16)
    return ints


def convert_MAC_to_int(packet):
    MAC_Adr = packet.wlan.sa.split(":")
    value = 0
    for byte in MAC_Adr:
        value = value + hex_to_bin(byte)
    return value


def calcSignature(IFATArray, binning):
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
    return [divide(numBin1, len(IFATArray)), divide(binMean1, numBin1), divide(numBin2, len(IFATArray)), divide(binMean2, numBin2), divide(numBin3, len(IFATArray)), divide(binMean3, numBin3)]

#--- Inter frame arrival time ---#


def IFAT(packetA, packetB):
    try:
        dateTimeDelta = packetA.sniff_time - packetB.sniff_time
        return dateTimeDelta
    except:
        print("Could not calculate delta time!")
        pass


def divide(a, b):
    try:
        return a / b
    except:
        return 0.0


def packetTimeToSeconds(packet):
    return packet.sniff_time.hour * 60 * 60 + packet.sniff_time.minute * 60 + packet.sniff_time.second + packet.sniff_time.microsecond * pow(10, -6)


def calcIFAT(packets, minDeltaTime):
    IFATArray = []
    burstSets = []
    i = 0
    try:
        while i < len(packets):
            startTime = packetTimeToSeconds(packets[i])

            while (i < len(packets) - 1) and (packetTimeToSeconds(packets[i+1]) - startTime < minDeltaTime and packetTimeToSeconds(packets[i+1]) - startTime >= 0):
                #print(packetTimeToSeconds(packets[i+1]) - startTime, packets[i+1].wlan.sa + " - " + packets[i].wlan.sa)
                if (packets[i].wlan.sa == packets[i+1].wlan.sa):
                    deltaTime = IFAT(packets[i+1], packets[i])
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


def main():

    try:
        captureFile = pyshark.FileCapture(path2, display_filter="""wlan.fc.type_subtype eq 4 && 
                                                                    wlan.sa != d0:16:b4:53:a1:14 && 
                                                                    wlan.sa != 50:01:d9:c6:fe:07 && 
                                                                    wlan.sa != 4a:7a:c2:82:4d:c7 &&
                                                                    wlan.sa != 8c:f5:a3:73:20:56 &&
                                                                    wlan.sa != da:a1:19:9b:5b:9b &&
                                                                    wlan.sa != ac:37:43:3c:d5:53""")

        packets_Sorted = sorted(captureFile, key=convert_MAC_to_int)
        burstSets = calcIFAT(packets_Sorted, 0.7)

        signatures = []
        for burst in burstSets:
            signatures.append(calcSignature(burst, [0.15, 0.3, 0.45]))

        ms = MeanShift()
        ms.fit(signatures)
        labels = ms.labels_
        cluster_centers = ms.cluster_centers_

        n_clusters_ = len(np.unique(labels))

        print("Num clusters", n_clusters_)
        #print("Cluster centers:\n", cluster_centers)
        #print(labels)

    except Exception as e:
        print("Could not find packet file!")
        print(e)


if __name__ == "__main__":
    main()
