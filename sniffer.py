"""
@author: Tara Saba
"""
import socket
import struct
import signal
from matplotlib import pyplot as plt
import sys
def ipv4_header_parsing(ipdata):
    version = ipdata[0] >>4 #bitwise shift to right
    headerLengthBytes = (ipdata[0] & 15) * 4
    typeOfService = ipdata[1]
    totalLength = struct.unpack('! H',ipdata[2:4])[0]
    checksum = struct.unpack('! H',ipdata[10:12])[0]
    identification = struct.unpack('! H',ipdata[4:6])[0]
    fragmentationOffset = struct.unpack('! H',ipdata[6:8])[0] & 8191
    flags = ipdata[6] >> 5
    ttl = struct.unpack('! 8x B',ipdata[:9])[0]
    transportProtocol = struct.unpack('! 9x B',ipdata[:10])[0]
    src_ip,des_ip = struct.unpack('! 4s 4s',ipdata[12:20])
    data = ipdata[headerLengthBytes:]
    return totalLength,"0x{:04x}".format(checksum),identification,setFlags(flags) ,flags, fragmentationOffset,version, headerLengthBytes, typeOfService, ttl, transportp(transportProtocol), transportProtocol, formatIP(src_ip), formatIP(des_ip), data

def tcp_header_parsing(data):
    sourcePort= struct.unpack('! H',data[0:2])[0]
    destinationPort = struct.unpack('! H', data[2:4])[0]
    seqNumber= struct.unpack('! I', data[4:8])[0]
    ackNumber = struct.unpack('! I', data[8:12])[0]
    checksum = struct.unpack('! H', data[16:18])[0]
    headerLength = (data[12]>>4)*4
    appProtocol = application(sourcePort,destinationPort)
    return sourcePort,destinationPort,seqNumber,ackNumber,"0x{:04x}".format(checksum),headerLength,appProtocol

def udp_header_parsing(data):
    sourcePort = struct.unpack('! H', data[0:2])[0]
    destinationPort = struct.unpack('! H', data[2:4])[0]
    length = struct.unpack('! H', data[4:6])[0]
    checksum = struct.unpack('! H', data[6:8])[0]
    appProtocol = application(sourcePort, destinationPort)
    return sourcePort,destinationPort,length,"0x{:04x}".format(checksum),appProtocol

def application(source,destination):
    if source == 21 or source == 20 or destination ==20 or destination ==21 :
        app="FTP"
    if source == 67 or source == 68 or destination ==67 or destination ==68 :
        app="DHCP"
    elif source == 53 or  destination ==53 :
        app="DNS"
    elif source == 80 or  destination ==80 :
        app="HTTP"
    elif source == 443 or  destination ==443 :
        app="SSL"
    elif source<1024 or destination<1024:
        app="other"
    elif source>1023 and destination>1023:
        app="No Protocol"
    return app
def setFlags(flags):
    fg = hex(flags)
    flagsString =str(fg)
    if flags==2:
        flagsString = flagsString+" (Don't Fragment)"
    elif flags==1:
        flagsString = flagsString + " (More Fragments)"
    return flagsString
def transportp(transportProtocol):
    if str(transportProtocol)=='1':
        tp='ICMP'
    elif str(transportProtocol)=='2':
        tp='IGMP'
    elif str(transportProtocol)=='6':
        tp='TCP'
    elif str(transportProtocol) =='17':
        tp='UDP'
    else:
        tp = transportProtocol
    return tp
def formatIP(address):
    ddn =".".join(map(str,address))
    return ddn
def ethernet_head(raw_data):
    #unpack the first 14 bytes
    destination, source, proto = struct.unpack('! 6s 6s H', raw_data[:14]) #6 for destination, 6 for source, rest for prototype
    return formatMac(destination), formatMac(source), socket.htons(proto), raw_data[14:] #htons big endian/little endian
def formatMac(addressBytes):
    humanReadable = map('{:02x}'.format,addressBytes) #hex
    mac =":".join(humanReadable).upper()
    return mac

def keyboardInterruptHandler(signal, frame):
  if first==0:
    reportFile= open("stats.txt","w+")
    reportFile.write("******** SNIFFER STATS ********\n")
    reportFile.write("Number of fragmented packets: {}\n".format(len(fragmentationSet)))
    #print(set(fragmentationSet))
    reportFile.write("*******************************\n")
    sort = sorted(sourceDictionary.items(), key=lambda x: x[1], reverse=True)
    for src in sort:
        reportFile.write("SOURCE: {}\t\t\t\tNumber of sent packets:{}\n".format(src[0], src[1]))
    reportFile.write("*******************************\n")
    for pro in protocolDictionary.keys():
        reportFile.write("The number of *{}* packets: {}\n".format(pro, protocolDictionary[pro]))
    reportFile.write("*******************************\n")
    reportFile.write("Minimum total packet length: {}\n".format(min(lengthList)))
    reportFile.write("Maximum total packet length: {}\n".format(max(lengthList)))
    reportFile.write("Average total packet length: {}\n".format(round(sum(lengthList)/len(lengthList),2)))
    reportFile.write("*******************************\n")
    for pro in appDictionary.keys():
        if pro!="No Protocol":
            reportFile.write("The number of *{}* packets: {}\n".format(pro, appDictionary[pro]))
    reportFile.write("*******************************\n")

    psort = sorted(portDictionary.items(), key=lambda x: x[1], reverse=True)
    for po in psort:
        if po[1]==psort[0][1]:
            reportFile.write("Port with maximum packet interchange: {}\t\t\t\tNumber of interchanged packets: {}\n".format(po[0],po[1]))
    reportFile.close()
    labels1= []
    sizes1 = []
    for l in protocolDictionary.keys():
        if protocolDictionary[l]!=0:
            labels1.append(l)
            sizes1.append(protocolDictionary[l]/ sum(protocolDictionary.values()))
    fig, axs = plt.subplots(1,2, figsize=(10,5))
    fig.canvas.set_window_title('Protocols Pie Charts')
    explode1=[]
    for l in labels1:
        if l=="UDP":
            explode1.append(0.1)
        else:
            explode1.append(0)
    axs[0].pie(sizes1, labels=list(labels1),explode=explode1, autopct='%1.1f%%',shadow=True,startangle=90)
    axs[0].legend(bbox_to_anchor=(1,0), loc="lower right")
    axs[0].set_title("Transport Layer Protocols")
    labels2 = []
    sizes2 = []
    for l in appDictionary.keys():
        if appDictionary[l] != 0:
            labels2.append(l)
            sizes2.append(appDictionary[l] / sum(appDictionary.values()))

    # for ps in appDictionary.values():
    #     if ps != 0:
    #         sizes2.append(ps / sum(appDictionary.values()))
    explode2 = []
    for l in labels2:
         if l == "DNS":
             explode2.append(0.1)
         else:
             explode2.append(0)
    axs[1].pie(sizes2, labels=list(labels2), explode=explode2,autopct='%1.1f%%',shadow=True,startangle=90)
    plt.axis('equal')
    axs[1].set_title("Application Layer Protocols")
    axs[1].legend(bbox_to_anchor=(1,0), loc="lower right")
    plt.show()
    # print(sourceDictionary)
    # sort=sorted(sourceDictionary.items(),key=lambda x: x[1],reverse=True)
    # for src in sort:
    #     print("source: {}, number:{}".format(src[0],src[1]))
    # print(protocolDictionary)


  sys.exit(0)

def dictionaryCounter(dictionary,key):
    try:
        dictionary[key]+=1
    except:
        dictionary[key]=1
def main():
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    packetCounter=1
    global fragmentationSet
    global protocolDictionary
    global sourceDictionary
    global lengthList
    global appDictionary
    global portDictionary
    global first
    first=1
    fragmentationSet=set({})
    protocolDictionary ={"TCP" : 0, "UDP": 0, "ICMP": 0}
    appDictionary={}
    sourceDictionary={}
    portDictionary={}
    lengthList=[]
    print("Welcome to Taratt packet sniffer!")
    print("To start sniffing enter \"sniff\" and to quit enter ctrl ^C")
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    command = input()
    while command!="sniff":
        print("Invalid input please try again!")
        command=input()
    first=0

    if command=='sniff':
        while True:
            raw_data, address = rawSocket.recvfrom(65535)
            destinationMac, sourceMac, protocol, payload = ethernet_head(raw_data)
            print("-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
            print('#{}\nEthernet Frame:'.format(packetCounter))
            print('Source MAC: {}, Destination Mac: {}, Network Protocol: {}'.format(sourceMac, destinationMac, protocol))
            if protocol==8:
                 totalIpLength, ipchecksum,id,ipFlagstr ,ipflags, fragmentationOffset, version, headerLengthBytes, typeOfService, ttl, transportProtocolstr,transportProtocol, src_ip, des_ip, data = ipv4_header_parsing(payload)
                 print( 'IPv4 Packet:')
                 print('Source IP: {}, Destination IP: {}, Transport layer protocol: {}'.format(src_ip,des_ip,transportProtocolstr))
                 print('IP Version: {}, Header length: {}, Total length: {}, TTL= {}, Checksum: {}'.format(version, headerLengthBytes,totalIpLength, ttl,ipchecksum))
                 print('Identification: {} ({}), Fragmentation offset: {}, Flags: {}'.format(hex(id), id, fragmentationOffset,ipFlagstr))
                 if ipflags == 1:
                    fragmentationSet.add((src_ip,id))
                 dictionaryCounter(protocolDictionary,transportProtocolstr)
                 dictionaryCounter(sourceDictionary,src_ip)
                 lengthList.append(totalIpLength)
                 if transportProtocolstr=="TCP":
                     sourcePortTCP, destinationPortTCP, seqNumber, ackNumber, checksumTCP, headerTCP,appTCP =tcp_header_parsing(data)
                     print('TCP Segment:')
                     print('Source port: {}, Destination port: {}, Checksum: {}, Header length: {}'.format(sourcePortTCP,destinationPortTCP,checksumTCP,headerTCP))
                     if appTCP=="No Protocol":
                        print('Sequence number: {}, Acknowledgement number: {}'.format(seqNumber,ackNumber))
                     else:
                         print('Sequence number: {}, Acknowledgement number: {}, Application layer protocol: {}'.format(seqNumber, ackNumber,appTCP))
                     dictionaryCounter(appDictionary,appTCP)
                     dictionaryCounter(portDictionary,sourcePortTCP)
                     dictionaryCounter(portDictionary,destinationPortTCP)
                 elif transportProtocolstr=="UDP":
                     sourcePortUDP, destinationPortUDP, lengthUDP, checksumUDP ,appUDP= udp_header_parsing(data)
                     print('UDP Segment:')
                     print('Source port: {}, Destination port: {}'.format(sourcePortUDP,destinationPortUDP))
                     if appUDP=="No Protocol":
                        print('Length: {}, Checksum: {}'.format(lengthUDP,checksumUDP))
                     else:
                        print('Length: {}, Checksum: {}, Application layer protocol: {}'.format(lengthUDP, checksumUDP,appUDP))
                     dictionaryCounter(appDictionary, appUDP)
                     dictionaryCounter(portDictionary, sourcePortUDP)
                     dictionaryCounter(portDictionary, destinationPortUDP)
            packetCounter+=1


if __name__ == '__main__':
         main()
