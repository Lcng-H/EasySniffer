#include "menuitemtcp.h"
#include "ui_menuitemtcp.h"
#include <QValidator>
#include <QDebug>
#include <QMessageBox>

MenuItemTCP::MenuItemTCP(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MenuItemTCP)
{
    ui->setupUi(this);
    ui->radioButton_tcp->setChecked(true);
    QRegExp regx("[0-9]+$");
    QValidator* validator = new QRegExpValidator(regx);
    ui->lineEdit_sport_t->setValidator(validator);
    ui->lineEdit_dport_t->setValidator(validator);
    ui->lineEdit_sport_u->setValidator(validator);
    ui->lineEdit_dport_u->setValidator(validator);
    ui->lineEdit_win->setValidator(validator);

    bg->addButton(ui->radioButton_tcp, 0);
    bg->addButton(ui->radioButton_udp, 1);

    connect(ui->radioButton_tcp, &QRadioButton::clicked, [=](){
        ui->stackedWidget->setCurrentIndex(0);
    });
    connect(ui->radioButton_udp, &QRadioButton::clicked, [=](){
        ui->stackedWidget->setCurrentIndex(1);
    });
}

MenuItemTCP::~MenuItemTCP(){
    delete ui;
}


void MenuItemTCP::error_exit(const char *error_message){
    perror(error_message);
    exit(1);
}


ip *MenuItemTCP::fill_ip_header(const char *src_ip, const char *dst_ip,int ip_packet_len,int packet_type){
    struct ip *ip_header;
    ip_header = (struct ip *)malloc(IP_HEADER_LEN);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = sizeof(struct ip) / 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(ip_packet_len);
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = MAXTTL;
    if(packet_type==0){
        ip_header->ip_p = IPPROTO_TCP;
    }
    else if (packet_type==1)
    {
        ip_header->ip_p = IPPROTO_UDP;
    }

    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = inet_addr(src_ip);
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);

    return ip_header;
}


tcphdr *MenuItemTCP::fill_tcp_header(int src_port, int dst_port, int *flag, int th_seq, int th_ack){
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *)malloc(TCP_HEADER_LEN);
    tcp_header->source = htons(src_port);
    tcp_header->dest = htons(dst_port);
    tcp_header->doff = sizeof(struct tcphdr) / 4;

    tcp_header->th_seq = th_seq;
    tcp_header->th_ack = th_ack;

    tcp_header->syn = flag[0];
    tcp_header->fin = flag[1];
    tcp_header->rst = flag[2];
    tcp_header->psh = flag[3];
    tcp_header->ack = flag[4];
    tcp_header->urg = flag[5];

    tcp_header->window = 4096;
    tcp_header->check = 0;
    return tcp_header;
}


udphdr *MenuItemTCP::fill_udp_header(int src_port, int dst_port){
  struct udphdr *udp_header;
  udp_header = (struct udphdr *)malloc(UDP_HEADER_LEN);
  udp_header->source = htons(src_port);
  udp_header->dest = htons(dst_port);
  udp_header->check = 0;

  return udp_header;
}


void MenuItemTCP::on_pushButton_send_clicked(){
    int id = bg->checkedId();
    if( id == 0){
        //设置ip & port & flag
//        const char *src_ip = ui->lineEdit_sip_t->text().toLocal8Bit().constData();
        int src_port = ui->lineEdit_sport_t->text().toInt();
//        const char *dst_ip = ui->lineEdit_dip_t->text().toLocal8Bit().constData();
        int dst_port = ui->lineEdit_dport_t->text().toInt();
//        const char *data = ui->textEdit->toPlainText().toLocal8Bit().constData();
        int flag[6] = {0};
        flag[0] = ui->checkBox_syn->isChecked();
        flag[1] = ui->checkBox_fin->isChecked();
        flag[2] = ui->checkBox_rst->isChecked();
        flag[3] = ui->checkBox_psh->isChecked();
        flag[4] = ui->checkBox_ack->isChecked();
        flag[5] = ui->checkBox_urg->isChecked();

        struct ip *ip_header;
        struct tcphdr *tcp_header;
        struct sockaddr_in dst_addr;
        socklen_t sock_addrlen = sizeof(struct sockaddr_in);

        int data_len = strlen(ui->textEdit->toPlainText().toLocal8Bit().constData());
        int ip_packet_len = IP_TCP_HEADER_LEN + data_len;
        char buf[ip_packet_len];
        int sockfd, ret_len, on = 1;

        bzero(&dst_addr, sock_addrlen);
        dst_addr.sin_family = PF_INET;
        dst_addr.sin_addr.s_addr = inet_addr(ui->lineEdit_dip_t->text().toLocal8Bit().constData());
        dst_addr.sin_port = htons(dst_port);

        if(-1 == (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)))
            error_exit("socket error");

        if(-1 == setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
            error_exit("setsocketopt error");

        ip_header = fill_ip_header(ui->lineEdit_sip_t->text().toLocal8Bit().constData(), ui->lineEdit_dip_t->text().toLocal8Bit().constData(), ip_packet_len,0);
        tcp_header = fill_tcp_header(src_port, dst_port, flag, 10, 9);

        bzero(buf, ip_packet_len);
        memcpy(buf, ip_header, IP_HEADER_LEN);
        memcpy(buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
        memcpy(buf + IP_TCP_HEADER_LEN, ui->textEdit->toPlainText().toLocal8Bit().constData(), data_len);

        ret_len = sendto(sockfd, buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
        if(ret_len > 0)
            QMessageBox::information(this, "通知", "TCP发送成功");
        else
            QMessageBox::information(this, "通知", "TCP发送失败");

        ::close(sockfd);
        free(ip_header);
        free(tcp_header);
    }
    else if( id == 1){
        //设置ip & port & flag
//        const char *src_ip = ui->lineEdit_sip_u->text().toLocal8Bit().constData();
        int src_port = ui->lineEdit_sport_u->text().toInt();
//        const char *dst_ip = ui->lineEdit_dip_u->text().toLocal8Bit().constData();
        int dst_port = ui->lineEdit_dport_u->text().toInt();
//        const char *data = ui->textEdit->toPlainText().toLocal8Bit().constData();

        struct ip *ip_header;
        struct udphdr *udp_header;
        struct sockaddr_in dst_addr;
        socklen_t sock_addrlen = sizeof(struct sockaddr_in);

        int data_len = strlen(ui->textEdit->toPlainText().toLocal8Bit().constData());
        int ip_packet_len = IP_UDP_HEADER_LEN + data_len;
        char buf[ip_packet_len];
        int sockfd, ret_len, on = 1;

        bzero(&dst_addr, sock_addrlen);
        dst_addr.sin_family = PF_INET;
        dst_addr.sin_addr.s_addr = inet_addr(ui->lineEdit_dip_u->text().toLocal8Bit().constData());
        dst_addr.sin_port = htons(dst_port);

        if(-1 == (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)))
        error_exit("socket error");

        if(-1 == setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
        error_exit("setsocketopt error");

        ip_header = fill_ip_header(ui->lineEdit_sip_u->text().toLocal8Bit().constData(), ui->lineEdit_dip_u->text().toLocal8Bit().constData(), ip_packet_len,1);
        udp_header = fill_udp_header(src_port, dst_port);

        bzero(buf, ip_packet_len);
        memcpy(buf, ip_header, IP_HEADER_LEN);
        memcpy(buf + IP_HEADER_LEN, udp_header, UDP_HEADER_LEN);
        memcpy(buf + IP_UDP_HEADER_LEN, ui->textEdit->toPlainText().toLocal8Bit().constData(), data_len);

        ret_len = sendto(sockfd, buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
        if(ret_len > 0)
            QMessageBox::information(this, "通知", "UDP发送成功");
        else
            QMessageBox::information(this, "通知", "UDP发送失败");

        ::close(sockfd);
        free(ip_header);
        free(udp_header);
    }
}

