#include "sniffer.h"

sniffer::sniffer(QObject *parent) : QObject(parent){
    isStop = false;
    totalLength = 0;
    arpPackets = 0;
    ipPackets = 0;
    tcpPackets = 0;
    udpPackets = 0;
    icmpPackets = 0;
    totalPackets = 0;
}

void sniffer::setFlag(bool flag)
{
    isStop = flag;
}

void sniffer::sniff()
{
    struct ether_header* eth; 	//Ethernet structure
    struct ether_arp* arp;	  	//Arp structure
    struct ip* ip;			  	//ip structure
    struct icmp* icmp;		  	//Icmp structure
    struct tcphdr* tcp;		  	//tcp structure
    struct udphdr* udp;		  	//udp sturcture
    int s;					  	//socket descriptor
    int len;				  	//data length received
    char buff[MAXSIZE];		  	//buffer
    char* p;				  	//initial pointer
    char* p0;				  	//packet pointer

    //打开socket套接字
    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }
    qDebug() << "start";

    while(!isStop){
        if ((len = read(s, buff, MAXSIZE)) < 0){
            perror("read");
            exit(EXIT_FAILURE);
        }
        totalLength += len;
        dt = QDateTime::currentDateTime();

        totalPackets++;    //数据包的个数
        p = p0 = buff;
        eth = (struct ether_header*)p;
        p = p + sizeof(struct ether_header);
        emit print_ethernet(eth);

        //for ARP
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
            arp = (struct ether_arp*)p;
            emit print_arp(arp);
            arpPackets++;
        }
        //for IP
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP){
            ip = (struct ip*)p;
            p = p + ((int)(ip->ip_hl) << 2);
            emit print_ip(ip);
            ipPackets++;

            switch (ip->ip_p){
                case IPPROTO_TCP:
                    tcp = (struct tcphdr*)p;
                    p = p + ((int)(tcp->th_off) << 2);
                    emit print_tcp(tcp);
                    tcpPackets++;
                    break;

                case IPPROTO_UDP:
                    udp = (struct udphdr*)p;
                    p = p + sizeof(struct udphdr);
                    emit print_udp(udp);
                    udpPackets++;
                    break;

                case IPPROTO_ICMP:
                    icmp = (struct icmp*)p;
                    p = p + sizeof(struct icmp);
                    emit print_icmp(icmp);
                    icmpPackets++;
                    break;

                default:
                    printf("Protocol unknown\n");
                    break;
            }
        }
        emit dump_packet((unsigned char*)p0, len);
        emit insertData(dt.toString("yyyy/MM/dd hh:mm:ss"), len);
        emit insertHosts();
    }
    close(s);
    qDebug() << "end";

}

