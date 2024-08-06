"""
This is a practice project that helped me learn a variety of concepts related to network programming,
such as the OSI model, TCP/IP model, Ethernet frames, IPv4 packets, Python's struct and socket libraries,
and using WSL to launch a Debian system on VSCode.
"""

from socket import socket, AF_PACKET, SOCK_RAW, ntohs
import struct


def parse_ethernet_frame(data: list[bytes]) -> tuple:
    """
    Parse an ethernet frame and return:
    - Source MAC addr
    - Destination MAC addr
    - Type
    - IPv4 packet
    """
    frame = struct.unpack("! 6s 6s H", data[:14])
    src_mac: str = ":".join([f"{byte:02x}" for byte in frame[0]])
    dst_mac: str = ":".join([f"{byte:02x}" for byte in frame[1]])
    return (src_mac, dst_mac, frame[2], data[14:])


def parse_ipv4_packet(data: list[bytes]) -> tuple:
    """
    Parse an IPv4 packet and return:
    - Version
    - Header length
    - Type of service
    - Total length
    - Identification
    - Flags
    - Fragment offset
    - TTL
    - Protocol
    - Checksum
    - Src IP Address
    - Dst IP Address
    """
    # IMPORTANT:
    ## Because of big endianness, the positions will be flipped

    # Get version and head length

    version_and_head_length: bytes = struct.unpack("! B", data[0:1])[0]
    version: bytes = version_and_head_length >> 4
    head_length: bytes = (
        version_and_head_length & 0x0F
    ) * 4  # The resulting head_length are words. Multply by 4 to get bytes

    # Get type
    type_of_service: bytes = struct.unpack("! B", data[1:2])[0]
    # type_of_service: bytes = data[1]

    # Get total length
    total_length: bytes = struct.unpack("! H", data[2:4])[0]
    # total_length: bytes = (data[2] << 8) + data[3]

    # Get ID
    identification: bytes = struct.unpack("! H", data[4:6])[0]
    # identification: bytes = (data[4] << 8) + data[5]

    flags_and_offset: bytes = struct.unpack("! H", data[6:8])[0]
    flags: bytes = flags_and_offset >> 13
    offset: bytes = flags_and_offset & 0x1F

    # # Get Flags
    # TCP_flags: bytes = data[6] >> 5 & 0x07
    # print("Flags:", TCP_flags)

    # # Get fragment offset
    # fragment_offset: bytes = (data[6] & 0x1F) << 8 + data[7]
    # print("Fragment Offset:", fragment_offset)

    # TTL
    ttl: bytes = struct.unpack("! B", data[8:9])[0]
    # ttl: bytes = data[8]

    # Protocol
    protocol: bytes = struct.unpack("! B", data[9:10])[0]
    # protocol: bytes = data[9]

    # Checksum
    checksum: bytes = struct.unpack("! H", data[10:12])[0]
    # checksum: bytes = (data[10] << 8) + data[11]

    # Src IP address
    src_ip_addr: bytes = struct.unpack("! 4B", data[12:16])
    # src_ip_addr: bytes = (data[12] << 24) + (data[13] << 16) + (data[14] << 8) + data[15]
    src_ip_addr = ".".join(map(str, src_ip_addr))

    # Dst IP address
    dst_ip_addr: bytes = struct.unpack("! 4B", data[16:20])
    # dst_ip_addr: bytes = (data[16] << 24) + (data[17] << 16) + (data[18] << 8) + data[19]
    dst_ip_addr = ".".join(map(str, dst_ip_addr))

    return (
        version,
        head_length,
        type_of_service,
        total_length,
        identification,
        flags,
        offset,
        ttl,
        protocol,
        checksum,
        src_ip_addr,
        dst_ip_addr,
    )


if __name__ == "__main__":
    raw_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while True:
        data, addr = raw_socket.recvfrom(65536)
        print("Incoming packet!")
        src_mac, dst_mac, data_type, packet = parse_ethernet_frame(data)
        print(
            "Src MAC Address:", src_mac, "Dst MAC Address:", dst_mac, "Type:", data_type
        )
        if data_type == 0x800:
            print("IPv4 packet found!")
            contents: tuple = parse_ipv4_packet(packet)
            print(
                "Version:",
                contents[0],
                "Header Length:",
                contents[1],
                "Type:",
                contents[2],
                "Total Length:",
                contents[3],
                "ID:",
                contents[4],
                "Flags:",
                contents[5],
                "Offset:",
                contents[6],
                "TTL:",
                contents[7],
                "Protocol:",
                contents[8],
                "Src IP Address:",
                contents[9],
                "Dst IP Address:",
                contents[10],
            )
