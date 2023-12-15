

from extractor.tshark_flow.util import precify_float

import numpy as np
import math, sys

Markov_BINS_LEN = 10
Markov_BINS_TIME = 10
Markov_BINS_SIZE_LEN = 150
Markov_BINS_SIZE_TIME = 50

class Feat:
    """
    Feature class represents features for a stream.
    "up" means oubound, and "down" mean inbound.
    """
    def __init__(self):

        # meta features
        self.pcap_name = ""
        self.stream_index = ""
        self.src_ip = ""
        self.dest_ip = ""
        self.src_port = 0
        self.dest_port = 0
        self.timestamp = 0     # nanoseconds
        self.duration = 0.0    # seconds

        # pkt number features
        self.pkt_total_num = 0
        self.pkt_up_num = 0
        self.pkt_down_num = 0

        # pkt len features
        self.pkt_len_total_sum = 0
        self.pkt_len_total_max = 0
        self.pkt_len_total_min = 0
        self.pkt_len_total_mean = 0
        self.pkt_len_total_std = 0

        self.pkt_len_up_sum = 0
        self.pkt_len_up_max = 0
        self.pkt_len_up_min = 0
        self.pkt_len_up_mean = 0
        self.pkt_len_up_std = 0

        self.pkt_len_down_sum = 0
        self.pkt_len_down_max = 0
        self.pkt_len_down_min = 0
        self.pkt_len_down_mean = 0
        self.pkt_len_down_std = 0

        # Inter-Arrival-Time(iat) features
        self.pkt_iat_total_sum = 0
        self.pkt_iat_total_max = 0
        self.pkt_iat_total_min = 0
        self.pkt_iat_total_mean = 0
        self.pkt_iat_total_std = 0

        self.pkt_iat_up_sum = 0
        self.pkt_iat_up_max = 0
        self.pkt_iat_up_min = 0
        self.pkt_iat_up_mean = 0
        self.pkt_iat_up_std = 0

        self.pkt_iat_down_sum = 0
        self.pkt_iat_down_max = 0
        self.pkt_iat_down_min = 0
        self.pkt_iat_down_mean = 0
        self.pkt_iat_down_std = 0

        # SPLT features
        self.mc_len = []   # 100 floats
        self.mc_time = []  # 100 floats

        # byte distribution features
        self.bd_dist = []   # 256 floats
        self.bd_std = 0.0
        self.bd_entropy = 0.0


class FeatGenerator:
    """
    Generate features from a stream object.
    """
    def __init__(self, stream):
        """
        Initialization function
        :param stream(Stream): stream object
        """

        self.feat = Feat()
        self.feat.pcap_name = stream.pcap_name
        self.feat.stream_index = stream.stream_index
        self.pkts = stream.pkts

    def generate_feats(self):
        """
        Major function to generate stream features
        :return: feat(Feat): features wrapped in Feat object
        """

        self.generate_meta_feat(self.pkts)
        pkt_len, pkt_iat = self.generate_pkt_len_iat_feat(self.pkts)
        self.generate_splt_feat(pkt_len, pkt_iat)
        self.generate_bd_feat(self.pkts)

        return self.feat

    def generate_meta_feat(self, pkts):
        """
        Generate meta features
        :param pkts(Pkt list): a list of Packet objects from the stream
        :return: nothing
        """

        pkt0 = pkts[0]
        pktn = pkts[-1]

        self.feat.src_ip = pkt0.src_ip
        self.feat.dest_ip = pkt0.dest_ip
        self.feat.src_port = pkt0.src_port
        self.feat.dest_port = pkt0.dest_port
        self.feat.timestamp = int(pkt0.timestamp * pow(10, 6))   # from seconds to microseconds
        self.feat.duration = precify_float(pktn.timestamp - pkt0.timestamp)

    def generate_pkt_len_iat_feat(self, pkts):
        """
        Generate packet len and inter-arrival-time statistical features
        :param pkts(Pkt list): Packet objects
        :return: pkt_len(list)
                 pkt_iat(list)
        """

        prev_pkt_ts = pkts[0].timestamp
        for i, pkt in enumerate(pkts):
            self.feat.pkt_total_num += 1

            if pkt.direction == "up":
                self.feat.pkt_up_num += 1
            else:
                self.feat.pkt_down_num += 1

            curr_pkt_ts = pkt.timestamp
            inter_arrival_time = curr_pkt_ts - prev_pkt_ts
            pkts[i].inter_arrival_time = inter_arrival_time  # round to 6 digits to be consistent with Wireshark
            prev_pkt_ts = curr_pkt_ts

        pkt_total_len = []
        pkt_up_len = []
        pkt_down_len = []
        pkt_total_iat = []
        pkt_up_iat = []
        pkt_down_iat = []

        for pkt in self.pkts:
            pkt_total_len.append(pkt.pkt_len)
            pkt_total_iat.append(pkt.inter_arrival_time)

            if pkt.direction == "up":
                pkt_up_len.append(pkt.pkt_len)
                pkt_up_iat.append(pkt.inter_arrival_time)
            else:
                pkt_down_len.append(pkt.pkt_len)
                pkt_down_iat.append(pkt.inter_arrival_time)

        # pkt num features
        np_pkt_total_len = np.array(pkt_total_len)
        np_pkt_up_len = np.array(pkt_up_len)
        np_pkt_down_len = np.array(pkt_down_len)

        np_pkt_total_iat = np.array(pkt_total_iat)
        np_pkt_up_iat = np.array(pkt_up_iat)
        np_pkt_down_iat = np.array(pkt_down_iat)

        # pkt len feature
        self.feat.pkt_len_total_sum = precify_float(np.sum(np_pkt_total_len))
        self.feat.pkt_len_total_max = precify_float(np.max(np_pkt_total_len))
        self.feat.pkt_len_total_min = precify_float(np.min(np_pkt_total_len))
        self.feat.pkt_len_total_mean = precify_float(np.mean(np_pkt_total_len))
        self.feat.pkt_len_total_std = precify_float(np.std(np_pkt_total_len))

        self.feat.pkt_len_up_sum = precify_float(np.sum(np_pkt_up_len))
        self.feat.pkt_len_up_max = precify_float(np.max(np_pkt_up_len))
        self.feat.pkt_len_up_min = precify_float(np.min(np_pkt_up_len))
        self.feat.pkt_len_up_mean = precify_float(np.mean(np_pkt_up_len))
        self.feat.pkt_len_up_std = precify_float(np.std(np_pkt_up_len))

        self.feat.pkt_len_down_sum = precify_float(np.sum(np_pkt_down_len))
        self.feat.pkt_len_down_max = precify_float(np.max(np_pkt_down_len))
        self.feat.pkt_len_down_min = precify_float(np.min(np_pkt_down_len))
        self.feat.pkt_len_down_mean = precify_float(np.mean(np_pkt_down_len))
        self.feat.pkt_len_down_std = precify_float(np.std(np_pkt_down_len))

        # pkt iat features
        self.feat.pkt_iat_total_sum = precify_float(np.sum(np_pkt_total_iat))
        self.feat.pkt_iat_total_max = precify_float(np.max(np_pkt_total_iat))
        self.feat.pkt_iat_total_min = precify_float(np.min(np_pkt_total_iat))
        self.feat.pkt_iat_total_mean = precify_float(np.mean(np_pkt_total_iat))
        self.feat.pkt_iat_total_std = precify_float(np.std(np_pkt_total_iat))

        self.feat.pkt_iat_up_sum = precify_float(np.sum(np_pkt_up_iat))
        self.feat.pkt_iat_up_max = precify_float(np.max(np_pkt_up_iat))
        self.feat.pkt_iat_up_min = precify_float(np.min(np_pkt_up_iat))
        self.feat.pkt_iat_up_mean = precify_float(np.mean(np_pkt_up_iat))
        self.feat.pkt_iat_up_std = precify_float(np.std(np_pkt_up_iat))

        self.feat.pkt_iat_down_sum = precify_float(np.sum(np_pkt_down_iat))
        self.feat.pkt_iat_down_max = precify_float(np.max(np_pkt_down_iat))
        self.feat.pkt_iat_down_min = precify_float(np.min(np_pkt_down_iat))
        self.feat.pkt_iat_down_mean = precify_float(np.mean(np_pkt_down_iat))
        self.feat.pkt_iat_down_std = precify_float(np.std(np_pkt_down_iat))

        return pkt_total_len, pkt_total_iat

    def generate_splt_feat(self, pkts_len, pkts_time):
        """
        Wrapper function to generate SPLT features
        :param pkts_len(int list):  pkt length list
        :param pkts_time(float list): pkt inter-arrival-time list
        :return: nothing
        """

        self.feat.mc_len = self._get_splt_len(pkts_len)
        self.feat.mc_time = self._get_splt_time(pkts_time)

    def _get_splt_len(self, pkts_len):
        '''
        Get Markov len sequence feature, which is a reimplementation of Joy and its research paper.
        Params:
            pkts_len(int list): packet len list
        Returns:
            mc_len(float list): Markov array of packet len
        '''

        num_pkts = len(pkts_len)

        markov_chain = np.zeros((Markov_BINS_LEN, Markov_BINS_TIME), dtype=float)
        mc_len = []

        if num_pkts == 0:
            return markov_chain
        elif num_pkts == 1:
            curr_pkt_len = pkts_len[0]
            length_bin = int(min(curr_pkt_len/Markov_BINS_SIZE_LEN, Markov_BINS_LEN-1))
            markov_chain[length_bin,length_bin] = 1.0
        else:
            for i, pktlen in enumerate(pkts_len):
                if i == num_pkts - 1:
                    break

                curr_pkt_len = pkts_len[i]
                next_pkt_len = pkts_len[i + 1]

                curr_length_bin = int(min(curr_pkt_len/Markov_BINS_SIZE_LEN, Markov_BINS_LEN - 1))
                next_length_bin = int(min(next_pkt_len/Markov_BINS_SIZE_LEN, Markov_BINS_LEN - 1))

                markov_chain[curr_length_bin, next_length_bin] += 1.0

        for row in markov_chain:
            row_sum = np.sum(row)
            if int(row_sum) != 0:
                r = row/row_sum
            else:
                r = np.zeros(10, dtype=float)
            for s in r:
                mc_len.append(s)

        return mc_len

    def _get_splt_time(self, pkts_time):
        '''
        Get Markov inter-arrival-time sequence feature, which is a reimplementation of Joy.
        Params:
            pkts_time(float list): packets inter-arrival-time list
        Returns:
            mc_time(float list): Markov array of pkt time
        '''

        num_pkts = len(pkts_time)

        markov_chain = np.zeros((Markov_BINS_LEN, Markov_BINS_TIME), dtype=float)
        mc_time = []

        # convert seconds to milli-seconds
        pkts_time_ms = [x*1000 for x in pkts_time]

        if num_pkts == 0:
            return markov_chain
        elif num_pkts == 1:
            curr_pkt_size = pkts_time_ms[0]
            time_bin = int(min(curr_pkt_size/Markov_BINS_SIZE_TIME, Markov_BINS_TIME-1))
            markov_chain[time_bin, time_bin] = 1.0
        else:
            for i, pktsize in enumerate(pkts_time_ms):
                if i == num_pkts-1:
                    break

                curr_pkt_time = pkts_time_ms[i]
                next_pkt_time = pkts_time_ms[i+1]

                curr_time_bin = int(min(curr_pkt_time/Markov_BINS_SIZE_TIME, Markov_BINS_TIME-1))
                next_time_bin = int(min(next_pkt_time/Markov_BINS_SIZE_TIME, Markov_BINS_TIME-1))

                markov_chain[curr_time_bin, next_time_bin] += 1.0

        for row in markov_chain:
            row_sum = np.sum(row)
            if int(row_sum) != 0:
                r = row/row_sum
            else:
                r = np.zeros(10, dtype=float)
            for s in r:
                mc_time.append(s)

        return mc_time

    def generate_bd_feat(self, pkts):
        """
        Wrapper function to generate byte distribution features from payloads
        :param pkts(Pkt list): stream packets
        :return: nothing
        """

        bd_dist, bd_std, bd_entropy = self._get_bd_feat(pkts)

        self.feat.bd_dist = bd_dist
        self.feat.bd_std = bd_std
        self.feat.bd_entropy = bd_entropy

    def _get_bd_feat(self, pkts):
        """
        Internal function to be called by get_bd_feat()
        :param pkts(Pkt list): stream packets
        :return: bd_dist(float list): byte distribution array
                bd_std(float): byte distribution standard variance
                bd entropy(float): byte distribution entropy
        """

        sum = 0.0
        bd_entropy = 0.0

        bd = np.zeros(256, dtype=int)
        for pkt in pkts:
            for b in pkt.payload:
                bd[b] += 1

        for x in list(bd):
            sum += x

        bd_dist = [x / sum for x in list(bd)]

        for x in bd_dist:
            if x > sys.float_info.epsilon:
                bd_entropy += (-x * math.log(x, 2))

        bd_std = np.std(bd_dist)

        return bd_dist, bd_std, bd_entropy
