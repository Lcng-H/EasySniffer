#ifndef DATAPROCESS_H
#define DATAPROCESS_H

#include <QObject>
#include <QThread>
#include <QDebug>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlQueryModel>
#include <QSqlError>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/if.h>

#define MAXSIZE 4096

class DataProcess : public QObject
{
    Q_OBJECT
public:
    explicit DataProcess(QObject *parent = nullptr);
    void print_ethernet(struct ether_header* eth);
    void print_arp(struct ether_arp* arp);
    void print_ip(struct ip* ip);
    void print_tcp(struct tcphdr* tcp);
    void print_udp(struct udphdr* udp);
    void print_icmp(struct icmp* icmp);
    void dump_packet(unsigned char* buff, int len);	//将从 Ethernet 报头的初始地址到 FCS 之前的值使用十六进制整数和 ASCII 码来表示。
    char *mac_ntoa(u_char* d);
    char *tcp_ftoa(int flag);
    char *ip_ttoa(int flag); //ip_tos to char
    char *ip_ftoa(int flag);
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");

    void insertDate(QString time, int len);
    void insertHosts();
    void sendQueryFunction();
    void sendModel();
    void closeDB();

signals:
    void updateView_packet(QSqlQueryModel *model);
    void updateView_hosts(QSqlQueryModel *model);
    void sendQuery(QSqlQuery query);
    void sendQueryModel(QSqlQueryModel *model);

private:
    QString sip = "";
    QString dip = "";
    QString smac = "";
    QString dmac = "";
    int sport = 0;
    int dport = 0;
    QString protocol = "";
    QString packet_info = "";

//    QSqlQuery *query = new QSqlQuery;
//    QSqlQuery *query2 = new QSqlQuery;
//    QSqlQueryModel *model = new QSqlQueryModel;
//    QSqlQueryModel *model2 = new QSqlQueryModel;
};

#endif // DATAPROCESS_H
