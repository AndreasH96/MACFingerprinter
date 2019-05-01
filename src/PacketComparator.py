from collections import Counter
class PacketComparator:

    def __init__(self):
        pass
    def comparePackets(self,packetx , packety):

        if (packetx is None) or (packety is None):
            print("ERROR: NONE ARGUMENT")

        else:
            """--------Compare SSID Arrays---------"""

            """---------Jaccard Method--------"""
            """ssid_intersection_cadrinality = len(set.intersection(*[set(packetx.SSIDArray), set(packety.SSIDArray)]))
            ssid_union_cardinality = len(set.union(*[set(packetx.SSIDArray), set(packety.SSIDArray)]))
            ssidJaccard = (ssid_intersection_cadrinality/float(ssid_union_cardinality)) * 0.5"""

            """-------------------------------"""

            """---------Cosine Method---------"""
            a_vals = Counter(packetx.SSIDArray)
            b_vals = Counter(packety.SSIDArray)
            words = list(a_vals.keys() | b_vals.keys())
            a_vect =[a_vals.get(word,0) for word in words]
            b_vect =[b_vals.get(word,0) for word in words]

            len_a = sum(av*av for av in a_vect) **0.5
            len_b = sum(bv*bv for bv in b_vect) **0.5
            dot =   sum(av*bv for av,bv in zip(a_vect,b_vect))

            cosine = (dot/(len_a *len_b)) * 0.5
            """------------------------------"""
            equalOUI = 0
            if packetx.OUI == packety.OUI:
                equalOUI = 1

            equalHTcap = 0
            if packetx.HTCapabilities == packety.HTCapabilities:
                equalHTcap = 1

            equalEXTcap = 0
            if packetx.ExtendedCapabilities == packety.ExtendedCapabilities:
                equalEXTcap = 1

            equalFields = equalOUI * equalHTcap * equalEXTcap * 0.5
            return ((cosine)  + equalFields )