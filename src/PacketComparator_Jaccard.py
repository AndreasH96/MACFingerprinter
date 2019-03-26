

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

            """intersection_cadrinality = len(set.intersection(*[set(packet1), set(packet2)]))
            union_cardinality = len(set.union(*[set(packet1), set(packet2)]))"""
            return ssid_intersection_cadrinality / float(ssid_union_cardinality)