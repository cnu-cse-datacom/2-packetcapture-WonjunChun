import socket
import struct


#이더넷 파싱
def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)#6자리 문자, 6자리 문자, 2자리 스트링?(총 14자리(이더넷))
    ether_src = convert_ethernet_address(ethernet_header[0:6])#0~5까진 src주소
    ether_dest = convert_ethernet_address(ethernet_header[6:12])#6~11까진 dest주소
    ip_header = "0x"+ethernet_header[12].hex()#12번째 칸에 IP헤더 들어있나?

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr


ip_next_index = 0

#ip헤더 파싱
#리스트 내에 다른 인덱스에 있는 숫자 이어서 출력하는방법? ex) [2:4]
def parsing_ip_header(data):
    ip_header = struct.unpack("!1s1s2s2s2s1s1s2s4c4c", data) #ip헤더의 dest주소까지의 범위가 20바이트이므로
    # test
    #print(ip_header[:])
    # ip_version = ip_header[0] >> 4 #첫 1바이트 중 상위 4비트가 version이므로
    ip_version = int(ip_header[0].hex(), 16)>>4
    ip_length = int(ip_header[0].hex(), 16) & 15 #첫 1바이트 중 하위 4비트가 헤더 길이이므로(0xf)
    #differentiated_service_codepoint
    #explicit_congestion_notification
    total_length = int(ip_header[2].hex(), 16)# total length는 [2~3] 바이트이므로
    identification = int(ip_header[3].hex(), 16) #[4~5]바이트가 identification
    flags = "0x" + ip_header[4].hex() # 6번째 바이트가 flag
    reserved_bit = (int(ip_header[4].hex(), 16)>>15) & 1 # flag 3비트중 상위 1비트
    not_fragments = (int(ip_header[4].hex(), 16)>>14) & 1 # flag 3비트 중 가운데 1비트
    fragments = (int(ip_header[4].hex(), 16)>>13) & 1 # flag 3비트 중 하위 1비트
    fragments_offset = int(ip_header[4].hex(), 16) & 31 #6~7 바이트 중 하위 5바이트
    time_to_live = int(ip_header[5].hex(), 16)# time to live는 8번째 바이트
    protocol = int(ip_header[6].hex(), 16) #protocol은 9번째 바이트
    header_checksum = "0x" + ip_header[7].hex() #헤더 체크섬은 10~11번째 바이트

    source_ip_address = convert_ip_address(ip_header[8:12])
    dest_ip_address = convert_ip_address(ip_header[12:16])

    global ip_next_index# = (ip_length*4) + 14 #ip헤더 길이 + 이더넷헤더 길이
    ip_next_index = (ip_length*4) + 14

    print("======ip_header======")
    print("ip_version:", ip_version)
    print("ip_length:", ip_length)
    #DSCP
    #ECN
    print("total_length:", total_length)
    print("identification:", identification)
    print("flags:", flags)
    print(">>>reserved_bit:", reserved_bit)
    print(">>>not_fragments:", not_fragments)
    print(">>>fragments:", fragments)
    print(">>>fragments_offset:", fragments_offset)
    print("Time to live:", time_to_live)
    print("protocol:", protocol)
    print("header_checksum:", header_checksum)
    print("source_ip_address:", source_ip_address)
    print("dest_ip_address:", dest_ip_address)


def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_temp = str(int(i.hex(), 16))
        ip_addr.append(ip_temp)

    ip_addr = ".".join(ip_addr)
    return ip_addr


def parsing_tcp_header(data):
    tcp_header = struct.unpack("2s2s4s4s1s1s2s2s2s", data)
    src_port = int(tcp_header[0].hex(), 16)
    dest_port = int(tcp_header[1].hex(), 16)
    seq_num = int(tcp_header[2].hex(), 16)
    ack_num = int(tcp_header[3].hex(), 16)
    header_len = int(tcp_header[4].hex())>>4
    flags = tcp_header[5].hex()
    reserved = int(tcp_header[4].hex()) & 15 # 0xf와 &연산하면 하위 4비트 추출
    nonce = reserved & 1 #reserved의 최하위 1비트
    cwr = int(tcp_header[5].hex())>>7 #TCP Flags의 최상위 1비트
    urgent = int(tcp_header[5].hex()) & 32 # TCP Flags의 좌측 3번째 비트 추출
    ack = int(tcp_header[5].hex()) & 16 # TCP Flags의 좌측 4번째 비트 추출
    push = int(tcp_header[5].hex()) & 8 # TCP Flags의 좌측 5번째 비트 추출
    reset = int(tcp_header[5].hex()) & 4 #TCP Flags의 좌측 6번째 비트 추출
    syn = int(tcp_header[5].hex()) & 2 #TCP Flags의 좌측 7번째 비트 추출
    fin = int(tcp_header[5].hex()) & 1 #TCP Flags의 최하위 비트 추출
    window_size_value = int(tcp_header[6].hex(), 16)
    checksum = int(tcp_header[7].hex(), 16)
    urgent_pointer = int(tcp_header[8].hex(), 16)

    print("=========tcp_header=========")
    print("src_port: ", src_port)
    print("dest_port: ", dest_port)
    print("seq_num: ", seq_num)
    print("ack_num: ", ack_num)
    print("header_len: ", header_len)
    print("flags: ", flags)
    print(">>>reserved: ", reserved)
    print(">>>nonce: ", nonce)
    print(">>>cwr: ", cwr)
    print(">>>urgent: ", urgent)
    print(">>>ack: ", ack)
    print(">>>push: ", push)
    print(">>>reset: ", reset)
    print(">>>syn: ", syn)
    print(">>>fin: ", fin)
    print("window_size_value: ", window_size_value)
    print("checksum: ", checksum)
    print("urgent_pointer: ", urgent_pointer)


def parsing_udp_header(data):
    udp_header = struct.unpack("2s2s2s2s", data)
    src_port = int(udp_header[0].hex(), 16)
    dst_port = int(udp_header[1].hex(), 16)
    leng = int(udp_header[2].hex(), 16)
    header_checksum = int(udp_header[3].hex(), 16)

    print("=========udp_header=========")
    print("src_port: ", src_port)
    print("dst_port: ", dst_port)
    print("leng: ", leng)
    print("header_checksum: ", header_checksum)



recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))
#socket.AF_PACKET?
#socket.SOCK_RAW : ip 밑에단도 확인(ppt 17p)
#socket.ntohs(0x800) : ipv4만 보겠다



while True:
    data = recv_socket.recvfrom(20000) #어떤 format으로 패킷 데이터를 가져오는지?
    #recv_socket.recvfrom(20000) : 생성한 소켓으로부터 조건만족하는 패킷들을 20000바이트 읽어들임
    parsing_ethernet_header(data[0][0:14])#0행의 0~13렬 데이터 파싱
    parsing_ip_header(data[0][14:34]) #ip헤더 부분 파싱

    #parsing_tcp_header(data[0][34:54]) #tcp헤더 부분 파싱
    if data[0][23] == 6:
        parsing_tcp_header(data[0][ip_next_index:ip_next_index+20])
    else:
        parsing_udp_header(data[0][ip_next_index:ip_next_index+8])
    break




