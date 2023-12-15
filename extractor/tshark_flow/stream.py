

from extractor.tshark_flow.feat import Feat, FeatGenerator

class Pkt:
    """
    Packet represents a network packet
    """
    def __init__(self):
        self.id = 0
        self.direction = ""       # "up"(outbound) or "down"(inbound)
        self.src_ip = ""
        self.src_port = 0
        self.dest_ip = ""
        self.dest_port = 0
        self.timestamp = 0.0      # in microseconds
        self.stream_index = 0
        self.inter_arrival_time = 0.0
        self.pkt_len = 0
        self.payload_hex = ""
        self.payload = b""

class Stream:
    """
    Stream maintains packets and features
    """
    def __init__(self, pcap_name, stream_index):
        """
        Initialize a new stream
        :param pcap_name(str): pcap_path name(not path), e.g., abc.pcap
        :param stream_index(int): stream number(identical with Wireshark's stream index)
        """

        self.pcap_name= pcap_name
        self.stream_index = stream_index
        self.pkts = []
        self.feat = Feat()

    def generate_stream_features(self):
        """
        generate stream features, stored in self.feat
        :return: d(dict): feature dict
        """

        feat_generator = FeatGenerator(self)
        feat = feat_generator.generate_feats()

        d = feat.__dict__

        return d
