import sys
import socket
import datetime
recvfromsize = 1068
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
x = datetime.datetime.now()
y = x.strftime("%a %b %d %X PST %Y:")
def send(string):
    echoS = ('h2', 8888)
    s.sendto(bytes(string, "utf-8"), echoS)
def sendSYN(seqno, length):
    print(y + " Send; SYN; Sequence: {}; Length: {}".format(seqno, length))
    string = str("SYN\r\n" + str(seqno) + "\r\n" + str(length)+ "\r\n\r\n")
    send(string)
def sendACK(ackno, window):
    print(y + " Send; ACK; Acknowledgement: {}; Window: {}".format(ackno, window))
    string = str("ACK\r\n" + str(ackno) + "\r\n" + str(window)+ "\r\n\r\n" + "\r\r\n\r\n\r")
    send(string)
def sendDAT(seqno, length, dataToSend):
    print(y + " Send; DAT; Sequence: {}; Length = {}".format(seqno, length))
    string = str("DAT\r\n" + str(seqno) + "\r\n" + str(length) + "\r\n\r\n" + dataToSend + "\r\r\n\r\n\r")
    send(string)
def sendFIN(seqno, length):
    print(y + " Send; FIN; Sequence: {}; Length: {}".format(seqno, length))
    string = str("FIN\r\n" + str(seqno) + "\r\n" + str(length)+ "\r\n\r\n")
    send(string)
def splitPackets(recv):
    packlist = recv.split(b'\r\r\n\r\n\r')
    return packlist
def extractDets(packet):
    packets = packet.split(b'\r\n\r\n')
    header = packets[0]
    retList = []
    headerlist = header.split(b'\r\n')
    command = headerlist[0].decode()
    val1 = int(headerlist[1].decode())
    val2 = int(headerlist[2].decode())
    if command == "SYN" or "ACK" or "FIN":
        retList = [command, val1, val2]
    if command == "DAT":
        rest = packets[1]
        data = rest[0:val2]
        retList = [command, val1, val2, data]
    return retList
def grabData(data, startpoint):
    endpoint = startpoint + 1024
    dat = data[startpoint:endpoint]
    return dat
def checklist(acklist):
    count = 0
    if len(acklist) < 3:
        return 0
    else :
        for i in range(1, len(acklist)):
            if acklist[i-1] == acklist[i]:
                count += 1
                if count == 2:
                    print("Fast Retransmission ...")
                    return count
    return count
def main():
    seqno = 0
    ackno = 1
    window = 5120
    length = 0
    ackwindow = 5120
    acklist = []
    ip_address = sys.argv[1]
    port_numer = int(sys.argv[2])
    file_to_send = open(sys.argv[3], "r")
    file_to_enter = open(sys.argv[4], "wb")
    data = file_to_send.read()
    datalen = len(data)
    address = (ip_address, port_numer)
    s.bind(address)
    s.settimeout(0.5)
    sendSYN(seqno, length)
    while 1:
        try:
            recv, addr = s.recvfrom(recvfromsize)
            break
        except socket.timeout:
            sendSYN(seqno, length)
    packInfo = extractDets(recv)
    if packInfo[0] == "SYN":
        print(y + " Receive; SYN; Sequence: {} Length: {}".format(packInfo[1], packInfo[2]))
        sendACK(ackno, window)
    while 1:
        try:
            recv, addr = s.recvfrom(recvfromsize)
            break
        except socket.timeout:
            sendACK(ackno, window)
    packInfo = extractDets(recv)
    if packInfo[0] == "ACK":
        print(y + " Receive; ACK; Acknowledgement: {} Window: {}".format(packInfo[1], packInfo[2]))
    recv_wind = packInfo[2]
    expec_seqno = packInfo[1]
    seqno = 1
    datalenafterwriting = datalen
    while 1:
        if datalenafterwriting == 0:
            break
        if recv_wind > 0 and datalen > 0:
            dataToSend = grabData (data, seqno -1)
            length = len(dataToSend)
            sendDAT(seqno, length, dataToSend)
            datalen -= length
            recv_wind -= len(dataToSend)
            seqno += len(dataToSend)
        else:
            while 1:
                try:
                    recv, addr = s.recvfrom(5*recvfromsize)
                except socket.timeout:
                    print("Timeout Occurred...")
                    acklist = []
                    datalen = len(data) - ackno
                    seqno = ackno
                    recv_wind = 5120
                    ackwindow = 5120
                    break
                packetLists = splitPackets(recv)
                for packet in packetLists:
                    if len(packet) > 1:
                        packetInfo = extractDets(packet)
                        if packetInfo[0] == "DAT":
                            print(y + " Receive; DAT; Sequence: {}; Length: {}".format(packetInfo[1], packetInfo[2]))
                            if packetInfo[1] == expec_seqno:
                                ackwindow -= len(packetInfo[3])
                                ackno = packetInfo[1] + len(packetInfo[3])
                                sendACK(ackno, ackwindow)
                                file_to_enter.write(packetInfo[3])
                                datalenafterwriting -= len(packetInfo[3])
                                expec_seqno = ackno
                            else:
                                sendACK(ackno, ackwindow)
                        else:
                            print(y + " Receive; ACK; Acknowledgement: {} Window: {}".format(packetInfo[1], packetInfo[2]))
                            acklist.append(packetInfo[1])
                            result = checklist(acklist)
                            if result == 2:
                                acklist = []
                                datalen = len(data) - packetInfo[1]
                                seqno = packetInfo[1]
                                recv_wind = 5120
                                ackwindow = 5120
                                break
                            ackno = packetInfo[1]
                            if ackno == seqno:
                                acklist = []
                                recv_wind = 5120
                                ackwindow = 5120
                                break
                break
    recv, addr = s.recvfrom(recvfromsize)
    packetslist = splitPackets(recv)
    for packet in packetslist:
        if len(packet) > 1:
            info = extractDets(packet)
            if info[0] == "ACK":
                print(y + " Receive; ACK; Acknowledgement: {} Window: {}".format(info[1], info[2]))
    sendFIN(seqno, 0)
    while 1:
        try:
            recv, addr = s.recvfrom(recvfromsize)
        except socket.timeout:
            sendFIN(seqno, 0)
        packetslist = splitPackets(recv)
        for packet in packetslist:
            if len(packet)>1:
                info = extractDets(packet)
                if info[0] == "FIN":
                    print(y + " Receive; FIN; Sequence: {} Length: {}".format(info[1], info[2]))
                    sendACK(int(info[1] + 1), window)
        try:
            recv, addr = s.recvfrom(recvfromsize)
        except socket.timeout:
            sendACK(int(info[1] + 1), window)
        info = extractDets(recv)
        if info[0] == "ACK":
            print(y + " Receive; ACK; Acknowledgement: {} Window: {}".format(info[1], info[2]))
            if info[1] == len(data)+2:
                break
    s.close()
if __name__ == '__main__':
    main()