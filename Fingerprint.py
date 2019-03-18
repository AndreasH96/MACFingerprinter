import pyshark

packets = pyshark.FileCapture('SniffFree8plus_7Plus_6Plus_HTC.pcapng')
macaddress = dict()
def appendToList(inputdict, MAC, SSID):
    if MAC in inputdict.keys() and SSID not in inputdict[MAC]:
        inputdict[MAC] = inputdict[MAC] + " , " + SSID
        #inputdict[MAC].append(SSID)
    else:
        inputdict[MAC] = SSID



def calcDeviceAmount(inputDict):
    amount = 0
    readItems = []
    for dictItem in inputDict.items():
        if not dictItem[1] in readItems:
            readItems.append(dictItem[1])
            amount = amount + 1

    return amount

for packet in packets:
    if "wlan_mgt" in packet:
        nossid = False
        if not str(packet.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = packet.wlan_mgt.ssid
            appendToList(macaddress,packet.wlan.ta, ssid)
        else:
            nossid = True
         #macaddress.append([packet.wlan.ta, ssid])

    else:
        nossid = False
        try:
            if not str(packet[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
                ssid = packet[3].ssid
                appendToList(macaddress,packet.wlan.ta, ssid)#,vendor)

                vendor = packet.wlan.tag.vendor.data
                print(vendor)
            else:
                nossid = True
        except:
            pass
print(calcDeviceAmount(macaddress))
for item in macaddress:
    print (item)
