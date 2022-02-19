#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QThread>
#include <QDebug>
#include <QDateTime>
#include "dataprocess.h"

class sniffer : public QObject
{
    Q_OBJECT
public:
    explicit sniffer(QObject *parent = nullptr);
    void setFlag(bool);
    int totalLength;
    int totalPackets;
    int ipPackets;
    int tcpPackets;
    int udpPackets;
    int arpPackets;
    int icmpPackets;

public slots:
    void sniff();

signals:
    void print_ethernet(struct ether_header* eth);
    void print_arp(struct ether_arp* arp);
    void print_ip(struct ip* ip);
    void print_tcp(struct tcphdr* tcp);
    void print_udp(struct udphdr* udp);
    void print_icmp(struct icmp* icmp);
    void dump_packet(unsigned char* buff, int len);
    void insertData(QString ctime, int len);
    void insertHosts();

private:
    bool isStop;
    QDateTime dt;
};

#endif // SNIFFER_H
