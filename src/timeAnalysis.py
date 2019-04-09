import pyshark
from itertools import tee, islice, chain
import matplotlib.pyplot as plt
import numpy as np
from decimal import Decimal



path = r"C:\Users\kalle\Högskolan i Halmstad\Andreas Häggström [andhag16] - Exjobb\Sniffings\SecondSniff\Iphone7Plus_Unlocked.pcapng"
path2 = "/home/kalle/Dropbox/KJ/Skola/Exjobb/SecondSniff/Iphone7Plus_Unlocked.pcapng"


def previous_and_next(some_iterable):
    prevs, items, nexts = tee(some_iterable, 3)
    prevs = chain([None], prevs)
    nexts = chain(islice(nexts, 1, None), [None])
    return zip(prevs, items, nexts)

#--- Inter frame arrival time ---#
def IFAT(packetA, packetB):
    try:
        dateTimeDelta = packetA.sniff_time - packetB.sniff_time
        return dateTimeDelta
    except:
        print("Could not calculate delta time!")
        pass

def getIFAT(capture):
    IFATArray = []
    try:
        for previous, item, nxt in previous_and_next(capture):
            if(nxt != None):
                deltaTime = IFAT(nxt, item)
                IFATArray.append(deltaTime.seconds)
                #timeDeltaListTime.append([deltaTime.seconds + deltaTime.microseconds*pow(10,-6), float(nxt.sniff_timestamp) - sniffStartTime])
        return IFATArray    
    except Exception as e:
        print("Could not append data to array!")
        print(e)

def getBurstSets(capture):
    burstSets = []
    burst = []
    firstTimestamp = float(capture[0].sniff_timestamp)
    for previous, item, nxt in previous_and_next(capture):
        if nxt != None:
            if str(nxt.wlan.sa) != str(item.wlan.sa):
                burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp])
                burstSets.append(burst)
                burst = []
            else:
                burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp])
        else:
            burst.append([item.wlan.sa, float(item.sniff_timestamp) - firstTimestamp])
            burstSets.append(burst)
            burst = []
    return burstSets


def main():

    try:
        #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22 && wlan.sa != ac:37:43:3c:d5:53")
        #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22")
        captureFile = pyshark.FileCapture(path2, display_filter="""wlan.fc.type_subtype eq 4 && 
                                                                    wlan.sa != d0:16:b4:53:a1:14 && 
                                                                    wlan.sa != 50:01:d9:c6:fe:07 && 
                                                                    wlan.sa != 4a:7a:c2:82:4d:c7 &&
                                                                    wlan.sa != 8c:f5:a3:73:20:56 &&
                                                                    wlan.sa != da:a1:19:9b:5b:9b &&
                                                                    wlan.sa != ac:37:43:3c:d5:53""")
        IFATArray = getIFAT(captureFile)
        burstSets = getBurstSets(captureFile)
        
        IFATArray = np.array(IFATArray)
        plt.plot(IFATArray, marker=".")
        plt.show()

    except Exception as e:
        print("Could not find packet file!")
        print(e)



if __name__ == "__main__":
    main()