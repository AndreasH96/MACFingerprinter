
from sklearn.metrics.pairwise import cosine_similarity
from collections import Counter
class JaccardComparator:

    def __init__(self):
        pass
    def comparePackets(self,packet1 , packet2):

        if (packet1 is None) or (packet2 is None):
            print("ERROR: NONE ARGUMENT")

        else:
            """--------Compare SSID Arrays---------"""

            """---------Jaccard Method--------"""
            ssid_intersection_cadrinality = len(set.intersection(*[set(packet1.SSIDArray), set(packet2.SSIDArray)]))
            ssid_union_cardinality = len(set.union(*[set(packet1.SSIDArray), set(packet2.SSIDArray)]))
            ssidJaccard = (ssid_intersection_cadrinality/float(ssid_union_cardinality)) * 0.5

            """-------------------------------"""


            
            """---------Cosine Method---------"""
            a_vals = Counter(packet1.SSIDArray)
            b_vals = Counter(packet2.SSIDArray)
            words = list(a_vals.keys() | b_vals.keys())
            a_vect =[a_vals.get(word,0) for word in words]
            b_vect =[b_vals.get(word,0) for word in words]

            len_a = sum(av*av for av in a_vect) **0.5
            len_b = sum(bv*bv for bv in b_vect) **0.5
            dot =   sum(av*bv for av,bv in zip(a_vect,b_vect))

            cosine = (dot/(len_a *len_b)) * 0.5
            """------------------------------"""
            ouijaccard = 0
            if packet1.OUI == packet2.OUI:
                ouijaccard = 1

            htcapjaccard = 0
            if packet1.HTCapabilities == packet2.HTCapabilities:
                htcapjaccard = 1

            extcapjaccard = 0
            if packet1.ExtendedCapabilities == packet2.ExtendedCapabilities:
                extcapjaccard = 1


            return (( cosine)  +  (ouijaccard * htcapjaccard * extcapjaccard * 0.5))