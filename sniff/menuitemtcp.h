#ifndef MENUITEMTCP_H
#define MENUITEMTCP_H

#include <QDialog>
#include <QButtonGroup>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define IP_HEADER_LEN sizeof(struct ip)
#define TCP_HEADER_LEN sizeof(struct tcphdr)
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
#define UDP_HEADER_LEN sizeof(struct udphdr)
#define IP_UDP_HEADER_LEN IP_HEADER_LEN + UDP_HEADER_LEN

namespace Ui {
class MenuItemTCP;
}

class MenuItemTCP : public QDialog
{
    Q_OBJECT

public:
    explicit MenuItemTCP(QWidget *parent = nullptr);
    ~MenuItemTCP();

private slots:
    void on_pushButton_send_clicked();

private:
    Ui::MenuItemTCP *ui;
    QButtonGroup *bg = new QButtonGroup;
    void error_exit(const char *error_message);
    struct udphdr *fill_udp_header(int src_port, int dst_port);
    struct tcphdr *fill_tcp_header(int src_port, int dst_port, int *flag, int th_seq, int th_ack);
    struct ip *fill_ip_header(const char *src_ip, const char *dst_ip,int ip_packet_len,int packet_type);
};

#endif // MENUITEMTCP_H
