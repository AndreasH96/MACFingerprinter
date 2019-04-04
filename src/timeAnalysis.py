import pyshark
from itertools import tee, islice, chain
import matplotlib.pyplot as plt
import numpy as np
from sklearn.preprocessing import normalize


path = r"C:\Users\kalle\Högskolan i Halmstad\Andreas Häggström [andhag16] - Exjobb\Sniffings\SecondSniff\Iphone7Plus_Unlocked.pcapng"


def previous_and_next(some_iterable):
    prevs, items, nexts = tee(some_iterable, 3)
    prevs = chain([None], prevs)
    nexts = chain(islice(nexts, 1, None), [None])
    return zip(prevs, items, nexts)

def packetDeltaTime(packetA, packetB):
    try:
        dateTimeDelta = packetB.sniff_time - packetA.sniff_time
        return dateTimeDelta
    except:
        print("Could not calculate delta time!")
        pass


def IFAT(deltaTime):
    if(deltaTime.seconds != 0):
        return pass #deltaTime.mi


def main():
    timeDeltaArray = []
    timeDeltaAvg = 0.0
    try:
        #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22 && wlan.sa != ac:37:43:3c:d5:53")
        #captureFile = pyshark.FileCapture(input("Enter file path to a .pcapng file: "), display_filter="wlan.sa != 22:22:22:22:22:22 && wlan.da != 22:22:22:22:22:22")
        captureFile = pyshark.FileCapture(path, display_filter="""wlan.fc.type_subtype eq 4 && 
                                                                    wlan.sa != d0:16:b4:53:a1:14 && 
                                                                    wlan.sa != 50:01:d9:c6:fe:07 && 
                                                                    wlan.sa != 4a:7a:c2:82:4d:c7 &&
                                                                    wlan.sa != 8c:f5:a3:73:20:56 &&
                                                                    wlan.sa != da:a1:19:9b:5b:9b &&
                                                                    wlan.sa != ac:37:43:3c:d5:53""")
        try:
            for previous, item, nxt in previous_and_next(captureFile):
                if(nxt != None):
                    deltaTime = packetDeltaTime(item, nxt)
                    timeDeltaArray.append(deltaTime.seconds)
                    

        except:
            print("Could not append data to array!")
    except:
        print("Could not find packet file!")

    timeDeltaArray = np.array(timeDeltaArray)
    #norm1 = timeDeltaArray / np.linalg.norm(timeDeltaArray)
 
    #print(timeDeltaArray)
    #print(norm1)
    #timeDeltaArray1 = np.dstack((timeDeltaArray, norm1))
    #print(timeDeltaArray1)

    plt.plot(timeDeltaArray, marker=".")
    plt.show()


if __name__ == "__main__":
    main()