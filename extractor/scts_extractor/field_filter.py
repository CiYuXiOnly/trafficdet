'''
Description:
version: 
Author: zlx
Date: 2023-12-17 15:08:47
LastEditors: zlx
LastEditTime: 2023-12-20 13:21:46
'''
'''
筛选tshark中的提供的字段 https://www.wireshark.org/docs/dfref/

数字特征

统计特征, 比如length, avg

特殊语义字段
'''

'''
get_filtered_field_name_list决定了最终提取哪些字段
'''
def get_filtered_field_name_list():

#     lst = ["tcp.stream",
#            "ip.src",
#            "ip.dst",
#            "tcp.srcport",
#            "tcp.dstport"]
    
    lst = [
              "tcp.stream",
              "tls.handshake",
              "tls.handshake.cert_types",
              "tls.handshake.ciphersuites",
              "tls.handshake.cipher_suites_length",
              "tls.handshake.extensions_reneg_info_len",
              "tls.handshake.extensions_server_name_list_len",
              "tls.handshake.extensions_server_name_type",
              "tls.handshake.certificates_length",
              "tls.handshake.client_point_len",
              "tls.handshake.comp_methods_length",
              "tls.handshake.extensions_length",
              "tls.handshake.extensions_server_name",
              "tls.handshake.extensions_server_name_len",
              "tls.handshake.extensions_server_name_type",
              "tls.handshake.length",
              "tls.handshake.ocsp_response_len",
              "tls.handshake.session_id",
              "tls.handshake.session_ticket_length",
              "tls.handshake.sig_hash_alg",
              "tls.handshake.type",
              "tls.handshake.version",
              "tls.sct.scts_length",
              "tls.sct.sct_timestamp",
              "tls.record.content_type",
              "tls.quic.parameter.type",
              "dns.a",
              "dns.aaaa",
              "dns.cert.algorithm",
              "dns.count.answers",
              "dns.resp.ttl",
              "dns.resp.len",
              "dns.resp.type"
           ]

    return lst