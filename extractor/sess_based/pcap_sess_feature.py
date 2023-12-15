from scapy.all import *
import csv
import statistics
'''
main API SessProcess()

op = SessProcess()
op.extract_sess_feature_from_pcap(pcap_path="", 
                                    csv_path=",
                                    label='0',
                                    per_print=10)
'''
class SessProcess():
    def __init__(self):
        pass
    
    def compute_features(self, packets_list, label):

        def compute_avg(list_of_values):
            if (len(list_of_values) == 0):
                return 0.0
            else:
                return float(sum(list_of_values) / len(list_of_values))

        def compute_min(list_of_values):
            if (len(list_of_values) == 0):
                return 0.0
            else:
                return float(min(list_of_values))

        def compute_max(list_of_values):
            if (len(list_of_values) == 0):
                return 0.0
            else:
                return float(max(list_of_values))

        def compute_stDev(list_of_values):
            if (len(list_of_values) == 0 or len(list_of_values) == 1):
                return 0.0
            else:
                try:
                    stat = statistics.stdev(list_of_values)
                    return float(stat)
                except:
                    return 0.0

        # Calculate the duration of the packet stream.
        def compute_duration_flow(packets_list):
            return packets_list[len(packets_list) - 1].time - packets_list[0].time

        # Calculate the size in bytes of each packet in a packet list
        def packets_bytes_lenght(packets_list):
            pkt_lenght_list = []
            for pkt in packets_list:
                pkt_lenght_list.append(float(len(pkt)))
            return pkt_lenght_list

        def packets_bytes_total(packets_list):
            flow_total_bytes = []
            for pkt in packets_list:
                flow_total_bytes.append(float(len(pkt)))
                totalbytes = sum(flow_total_bytes)
            return totalbytes 

        def compute_type(packets_list):
            first = packets_list[0]
            return first.layers()[-1]._name


        # Counts the number of packets with the tcp layer that have little or no payload
        def compute_packet_with_small_TCP_payload(packets_list, count_packet_without_payload=False):
            packets_small_payload_count = []
            pktPayloadList = compute_packet_TCP_payload_size(packets_list, count_packet_without_payload=count_packet_without_payload)
            for payload in pktPayloadList:
                if (payload <= 32):  # 32 was chosen based on the bonesi framework that simulates a botnet and sets the paylaod to 32 by default
                    packets_small_payload_count.append(1.0)
                elif (payload > 32):
                    packets_small_payload_count.append(0.0)
                elif (payload == None):
                    
                    # If it has the tcp layer and does not respect the fees increase the counter. If it doesn't have the tcp layer it doesn't increment the counter.
                    # This parameter will be weighted against the pkt numbers that the TCP layer has
                    if (count_packet_without_payload):
                        packets_small_payload_count.append(0.0)
                    else:
                        pass
            return packets_small_payload_count
        
        # Calculate the payload size of a TCP packet
        def compute_packet_TCP_payload_size(packets_list, count_packet_without_payload=False):
            payload_size_list = []
            for pkt in packets_list:
                if (pkt.haslayer("TCP")):
                    if (pkt["TCP"].payload == None):  # The packet is TCP but has no payload. It's probably a three way handshake
                        payload_size_list.append(0.0)
                    else:
                        payload_size_list.append(float(len(pkt["TCP"].payload)))
                else:
                    if (count_packet_without_payload):
                        payload_size_list.append(None)
                    else:
                        pass
            return payload_size_list

        def compute_delta_time(packets_list):
            i = 1
            delta_time_list = []
            while (i <= (len(packets_list) - 1)):
                delta_time_list.append(packets_list[i].time - packets_list[i - 1].time)
                i += 1
            return delta_time_list
        
        # Calculate active TCP flags in a packet. The array contains 1 if the flag
        # is active, 0 if it is not or the pkt is not TCP
        def compute_tcp_flags(packets_list):
            syn_counter = []
            fin_counter = []
            ack_counter = []
            psh_counter = []
            urg_counter = []
            rst_counter = []
            FIN = 0x01
            SYN = 0x02
            RST = 0x04
            PSH = 0x08
            ACK = 0x10
            URG = 0x20
            for pkt in packets_list:
                if (pkt.haslayer("TCP")):
                    F = pkt["TCP"].flags
                    if F & FIN:
                        fin_counter.append(1.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & SYN:
                        fin_counter.append(0.0)
                        syn_counter.append(1.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & RST:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(1.0)
                    elif F & PSH:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(1.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & ACK:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(1.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & URG:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(1.0)
                        rst_counter.append(0.0)
                    else:
                        pass
                else:
                    fin_counter.append(0.0)
                    syn_counter.append(0.0)
                    ack_counter.append(0.0)
                    psh_counter.append(0.0)
                    urg_counter.append(0.0)
                    rst_counter.append(0.0)
            return (syn_counter, fin_counter, ack_counter, psh_counter, urg_counter, rst_counter)

        def get_fuple(pkts):
            first = packets_list[0]
            f = first['TCP'] if first.haslayer('TCP') else first['UDP']
            return [first['IP'].src, first['IP'].dst, f.sport, f.dport]
        def compute_type(packets_list):
            first = packets_list[0]
            return first['IP'].proto

        def compute_1st_packet(packets_list):
            first = packets_list[0]
            return len(first)


        syn_lst, fin_lst, ack_lst, psh_lst, urg_lst, rst_lst = compute_tcp_flags(packets_list)
        syn_avg = compute_avg(syn_lst)
        fin_avg = compute_avg(fin_lst)
        ack_avg = compute_avg(ack_lst)
        psh_avg = compute_avg(psh_lst)
        urg_avg = compute_avg(urg_lst)
        rst_avg = compute_avg(rst_lst)
        syn_avg = sum(syn_lst)
        fin_avg = sum(fin_lst)
        ack_avg = sum(ack_lst)
        psh_avg = sum(psh_lst)
        urg_avg = sum(urg_lst)
        rst_avg = sum(rst_lst)
        
        durationFlow = compute_duration_flow(packets_list)
        avgTimeFlow = compute_avg(compute_delta_time(packets_list))
        minTimeFlow = compute_min(compute_delta_time(packets_list))
        maxTimeFlow = compute_max(compute_delta_time(packets_list))
        stdevTimeFlow = compute_stDev(compute_delta_time(packets_list))
        pktLenghtAvg = compute_avg(packets_bytes_lenght(packets_list))
        pktLenghtMin = compute_min(packets_bytes_lenght(packets_list))
        pktLenghtMax = compute_max(packets_bytes_lenght(packets_list))
        pktLengthTotal = packets_bytes_total(packets_list)
        pktLenghtStDev = compute_stDev(packets_bytes_lenght(packets_list))
        smallPktPayloadAvg = compute_avg(compute_packet_with_small_TCP_payload(packets_list, False))
        avgPayload = compute_avg(compute_packet_TCP_payload_size(packets_list, False))
        minPayload = compute_min(compute_packet_TCP_payload_size(packets_list, False))
        maxPayload = compute_max(compute_packet_TCP_payload_size(packets_list, False))
        stDevPayload = compute_stDev(compute_packet_TCP_payload_size(packets_list, False))
        length1stpkt = compute_1st_packet(packets_list)

        row = get_fuple(packets_list) + [compute_type(packets_list), syn_avg, urg_avg, fin_avg, ack_avg, psh_avg, rst_avg, durationFlow, avgTimeFlow,
                minTimeFlow, maxTimeFlow, stdevTimeFlow, pktLenghtAvg, pktLenghtMin, pktLenghtMax, pktLengthTotal, pktLenghtStDev, smallPktPayloadAvg,
                avgPayload, minPayload, maxPayload, stDevPayload, len(packets_list), label]
        return row
    
    # def compute_features ended

    def extract_sess_feature_from_pcap(self, pcap_path, csv_path, label, per_print=100):
        DEST  = csv_path
        SRC   = pcap_path
        LABEL = label

        with open(DEST, 'w', newline="") as f:
            c = csv.writer(f)

            feature_names = ["src_ip", "dst_ip", "sport", "dport", "type", "Avg_syn_flag", "Avg_urg_flag", "Avg_fin_flag", "Avg_ack_flag", "Avg_psh_flag", "Avg_rst_flag", 
                "Duration_window_flow", "Avg_delta_time", "Min_delta_time", "Max_delta_time", "StDev_delta_time",
                "Avg_pkts_lenght", "Min_pkts_lenght", "Max_pkts_lenght", "Total_pkts_Length" , "StDev_pkts_lenght", "Avg_small_payload_pkt", "Avg_payload", "Min_payload",
                "Max_payload", "StDev_payload", "Num Packets", "label"]
            
            c.writerow(feature_names)

            a = rdpcap(SRC)
            s = a.sessions()
            
            i = 0
            print(len(s.items()))
            for k,v in s.items():
                if  v[0].haslayer('IP') and (v[0].haslayer('TCP') or v[0].haslayer('UDP')):
                    t = self.compute_features(v, LABEL)
                    c.writerow(t)
                else:
                    print(f"skipping {v[0].layers()} layers")
                i += 1
                if (i-1)%per_print == 0 and i-1 != 0:
                    print('已处理 {} 个数据包'.format(i-1))
            print('已处理完成 {} 个数据包'.format(i))

        print('已处理 全部特征: {} 个, 以及 {} 个目标值'.format(len(feature_names)-1, 1))
