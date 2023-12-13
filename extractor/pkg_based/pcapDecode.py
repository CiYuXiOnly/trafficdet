
from scapy.utils import corrupt_bytes
from scapy.all import *
from scapy.all import TCP, UDP, ICMP
# protocol目录
PROTOCOL_PATH = 'extractor/pkg_based/protocol'

class PcapDecode:
    def __init__(self):
        # ETHER:读取以太网层协议配置文件
        print('%s/ETHER' % PROTOCOL_PATH)
        with open('%s/ETHER' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = {}
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]  # 将配置文件中的信息(0257:Experimental)存入dict

        # IP:读取IP层协议配置文件
        with open('%s/IP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = {}
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]  # 将配置文件中的信息(41:IPv6)存入dic

        # PORT:读取应用层协议端口配置文件
        with open('%s/PORT' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = {}
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]  # 如：21:FTP

        # TCP:读取TCP层协议配置文件
        with open('%s/TCP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = {}
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]  # 465:SMTPS

        # UDP:读取UDP层协议配置文件
        with open('%s/UDP' % PROTOCOL_PATH, 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = {}
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]  # 513:Who

    # 解析以太网层协议 ---ether_decode——ip_decode(tcp_decode or udp_decode)
    def ether_decode(self, p):
        data = {}  # 解析出的信息以dict的形式保存
        if p.haslayer("Ether"):  # scapy.haslayer,将pcap包中的信息分层，再处理
            data = self.ip_decode(p)  # 解析IP层协议
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
            data['source_ip'] = ''
            data['dest_ip'] = ''
            data['protocol'] = ''
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            data['source_port'] = ''
            data['dest_port'] = ''
        tcp_dict = self.parse_tcp_packet(p)
        udp_dict = self.parse_udp_packet(p)
        icmp_dict = self.parse_icmp_packet(p)
        data.update(tcp_dict)
        data.update(udp_dict)
        data.update(icmp_dict)

        return data

    # 解析IP层协议
    def ip_decode(self, p):
        data = {}
        if p.haslayer("IP"):  # 2048:Internet IP (IPv4) ，分IPV4和IPV6和其他协议
            ip = p.getlayer("IP")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:  # 若ip分层中的协议信息在字典中，则提取ip分层中的源地址、目的地址、协议（转换）等
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ip.src
                    data['dest_ip'] = ip.dst
                    data['protocol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ip.src
                    data['dest_ip'] = ip.dst
                    data['protocol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
        elif p.haslayer("IPv6"):  # 34525:IPv6
            ipv6 = p.getlayer("IPv6")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ipv6.src
                    data['dest_ip'] = ipv6.dst
                    data['protocol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['source_ip'] = ipv6.src
                    data['dest_ip'] = ipv6.dst
                    data['protocol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    data['source_port'] = 'UnKnow'
                    data['dest_port'] = 'UnKnow'
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['source_ip'] = p.src
                data['dest_ip'] = p.dst
                data['protocol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                data['source_port'] = 'UnKnow'
                data['dest_port'] = 'UnKnow'
                return data
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['source_ip'] = p.src
                data['dest_ip'] = p.dst
                data['protocol'] = hex(p.type)  # 若在字典中没有改协议，则以16进制的形式显示
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                data['source_port'] = 'UnKnow'
                data['dest_port'] = 'UnKnow'
                return data

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        data = {}
        tcp = p.getlayer("TCP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['source_ip'] = ip.src
        data['dest_ip'] = ip.dst
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        data['source_port'] = str(ip.sport)
        data['dest_port'] = str(ip.dport)
        if tcp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\TCP_DICT中则转换为已知
            data['protocol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['protocol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['protocol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['protocol'] = self.TCP_DICT[tcp.sport]
        else:
            data['protocol'] = "TCP"
        return data

    # 解析UDP层协议
    def udp_decode(self, p, ip):
        data = {}
        udp = p.getlayer("UDP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['source_ip'] = ip.src
        data['dest_ip'] = ip.dst
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        data['source_port'] = str(ip.sport)
        data['dest_port'] = str(ip.dport)
        if udp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\UDP_DICT中则转换为已知
            data['protocol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['protocol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['protocol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['protocol'] = self.UDP_DICT[udp.sport]
        else:
            data['protocol'] = "UDP"
        return data

    def parse_tcp_packet(self, packet):
        tcp_packet_info = {}
        if TCP in packet:
            tcp_packet = packet[TCP]
            tcp_packet_info['tcp_seq_number'] = tcp_packet.seq
            tcp_packet_info['tcp_ack_number'] = tcp_packet.ack
            tcp_packet_info['tcp_window_size'] = tcp_packet.window
            tcp_packet_info['tcp_flags'] = tcp_packet.flags
            tcp_packet_info['tcp_header_length'] = tcp_packet.dataofs
            tcp_packet_info['tcp_checksum'] = tcp_packet.chksum
            tcp_packet_info['tcp_urgent_pointer'] = tcp_packet.urgptr
            tcp_packet_info['tcp_options'] = tcp_packet.options
            tcp_packet_info['tcp_payload'] = packet.payload
        else:
            tcp_packet_info['tcp_seq_number'] = 0
            tcp_packet_info['tcp_ack_number'] = 0
            tcp_packet_info['tcp_window_size'] = 0
            tcp_packet_info['tcp_flags'] = 0
            tcp_packet_info['tcp_header_length'] = 0
            tcp_packet_info['tcp_checksum'] = 0
            tcp_packet_info['tcp_urgent_pointer'] = 0
            tcp_packet_info['tcp_options'] = 0
            tcp_packet_info['tcp_payload'] = 0
        return tcp_packet_info

    def parse_udp_packet(self, packet):
        udp_packet_info = {}
        if UDP in packet:
            udp_packet = packet[UDP]
            udp_packet_info['udp_length'] = udp_packet.len
            udp_packet_info['udp_checksum'] = udp_packet.chksum
            udp_packet_info['udp_payload'] = packet.payload
        else:
            udp_packet_info['udp_length'] = 0
            udp_packet_info['udp_checksum'] = 0
            udp_packet_info['udp_payload'] = 0
        return udp_packet_info

    def parse_icmp_packet(self, packet):
        icmp_packet_info = {}
        if ICMP in packet:
            icmp_packet = packet[ICMP]
            icmp_packet_info['icmp_type'] = icmp_packet.type
            icmp_packet_info['icmp_code'] = icmp_packet.code
            icmp_packet_info['icmp_checksum'] = icmp_packet.chksum
            icmp_packet_info['icmp_id'] = icmp_packet.id
            icmp_packet_info['icmp_seq'] = icmp_packet.seq
            icmp_packet_info['icmp_payload'] = packet.payload
        else:
            icmp_packet_info['icmp_type'] = 0
            icmp_packet_info['icmp_code'] = 0
            icmp_packet_info['icmp_checksum'] = 0
            icmp_packet_info['icmp_id'] = 0
            icmp_packet_info['icmp_seq'] = 0
            icmp_packet_info['icmp_payload'] = 0
        return icmp_packet_info