import pyshark
from itertools import tee, islice, chain
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import MeanShift
from decimal import Decimal

class TimeAnalyser:
    def __init__(self):
        pass
    def previous_and_next(self,some_iterable):
        prevs, items, nexts = tee(some_iterable, 3)
        prevs = chain([None], prevs)
        nexts = chain(islice(nexts, 1, None), [None])
        return zip(prevs, items, nexts)

    #--- Inter frame arrival time ---#
    def IFAT(self,packetA, packetB):
        try:
            dateTimeDelta = packetA.sniff_time - packetB.sniff_time
            return dateTimeDelta
        except:
            print("Could not calculate delta time!")
            pass

    def getIFAT(self,capture):
        IFATArray = []
        try:
            for previous, item, nxt in self.previous_and_next(capture):
                if(nxt != None):
                    deltaTime = self.IFAT(nxt, item)
                    IFATArray.append(deltaTime.seconds + deltaTime.microseconds * pow(10, -6))
                    #timeDeltaListTime.append([deltaTime.seconds + deltaTime.microseconds*pow(10,-6), float(nxt.sniff_timestamp) - sniffStartTime])
            return IFATArray
        except Exception as e:
            print("Could not append data to array!")
            print(e)

    def getBurstSets(self,capture):
        burstSets = []
        burst = []
        firstTimestamp = float(capture[0].sniff_timestamp)
        for previous, item, nxt in self.previous_and_next(capture):
            if nxt != None:
                if str(nxt.wlan.sa) != str(item.wlan.sa) and len(burst) > 2:
                    burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp, float(item.sniff_timestamp) - float(previous.sniff_timestamp)])
                    burstSets.append(burst)
                    burst = []
                else:
                    if previous != None:
                        burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp, float(item.sniff_timestamp) - float(previous.sniff_timestamp)])
                    else:
                        burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp, 0.0])
            else:
                burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp, float(item.sniff_timestamp) - float(previous.sniff_timestamp)])
                burstSets.append(burst)
                burst = []
        return burstSets

    def getIFATAsBurstSets(self,capture):
        burstSets = []
        burst = []
        for previous, item, nxt in self.previous_and_next(capture):
            if nxt != None:
                if (str(nxt.wlan.sa) != str(item.wlan.sa)) and len(burst) > 2:
                    burst.append(item)
                    IFATArr = self.getIFAT(burst)
                    burstSets.append(IFATArr)
                    burst = []
                elif str(nxt.wlan.sa) == str(item.wlan.sa):
                    burst.append(item)
                else:
                    pass
            else:
                burst.append(item)
                IFATArr = self.getIFAT(burst)
                burstSets.append(IFATArr)
                burst = []
        return burstSets

    def getBurstSetsAsPackets(self,capture):
        burstSets = []
        burst = []
        for previous, item, nxt in self.previous_and_next(capture):
            if nxt != None:
                if (str(nxt.wlan.sa) != str(item.wlan.sa)) and len(burst) > 2:
                    burst.append([item, item.wlan.sa])
                    burstSets.append(burst)
                    burst = []
                elif str(nxt.wlan.sa) == str(item.wlan.sa):
                    burst.append([item, item.wlan.sa])
                else:
                    pass
            else:
                burst.append([item, item.wlan.sa])
                burstSets.append(burst)
                burst = []
        return burstSets

    def divide(self,a,b):
        try:
            return a / b
        except:
            return 0.0

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

    def plotData(data):
        data = np.array(data)
        plt.plot(data, marker=".")
        plt.show()

    def processFile(self,inputFile,devicesToProcess):
        pysharkFilter = "wlan.fc.type_subtype  eq 4 "

        for device in devicesToProcess:
            pysharkFilter = pysharkFilter +"&& wlan.sa != {}".format(device)
        try:
            #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22 && wlan.sa != ac:37:43:3c:d5:53")
            #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22")
            captureFile = pyshark.FileCapture(inputFile, display_filter= pysharkFilter)


            #IFATArray = getIFAT(captureFile)
            burstSets = self.getIFATAsBurstSets(captureFile)
            #print(burstSets)
            signatures = []
            for burst in burstSets:
                signatures.append(self.calcSignature(burst, [0.15, 0.7, 2]))

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
