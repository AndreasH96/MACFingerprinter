from Fingerprint import MACFingerPrinter
import time
import pyshark

deviceCounter = MACFingerPrinter()
modeSelect = input("Select Mode, Live or File: ")
if (modeSelect == "Live") :
    while(1):
        deviceCounter.readMACAddresses(mode=modeSelect)
        time.sleep(6)
elif (modeSelect == "File"):
    deviceCounter.readMACAddresses(mode = modeSelect)
