

class JaccardComparator:

    def __init__(self):
        pass
    def comparePackets(self,packet1 , packet2):

        if (packet1 is None) or (packet2 is None):
            print("ERROR: NONE ARGUMENT")

        else:
            """--------Compare SSID Arrays---------"""
            ssid_intersection_cadrinality = len(set.intersection(*[set(packet1.SSIDArray), set(packet2.SSIDArray)]))
            ssid_union_cardinality = len(set.union(*[set(packet1.SSIDArray), set(packet2.SSIDArray)]))
            ssidJaccard = (ssid_intersection_cadrinality/float(ssid_union_cardinality)) * 0.5

            ouijaccard = 0
            if packet1.OUI == packet2.OUI:
                ouijaccard = 1

            htcapjaccard = 0
            if packet1.HTCapabilities == packet2.HTCapabilities:
                htcapjaccard = 1

            extcapjaccard = 0
            if packet1.ExtendedCapabilities == packet2.ExtendedCapabilities:
                extcapjaccard = 1

            """intersection_cadrinality = len(set.intersection(*[set(packet1), set(packet2)]))
            union_cardinality = len(set.union(*[set(packet1), set(packet2)]))"""
            return (ssidJaccard  +  (ouijaccard * htcapjaccard * extcapjaccard * 0.5))