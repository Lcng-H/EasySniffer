#include "dataprocess.h"

DataProcess::DataProcess(QObject *parent) : QObject(parent){

    //数据库的创建
    db.setDatabaseName("dump.db");
    if( !db.open() ){
        qDebug() << db.lastError().text();
        return;
    }else{
        qDebug() << "Open Success";
    }

    QSqlQuery query(db);

    //表的删除
    if (! query.exec("drop table if exists packets;")){
        qDebug() << "删除packets表失败";
    }
    if (! query.exec("drop table if exists hosts;")){
        qDebug() << "删除hosts表失败";
    }

    //表的创建
    QString sqlCreate = QString("create table packets(id integer primary key autoincrement,"
                                "time varchar(20),"
                                "length int,"
                                "sip varchar(20),"
                                "sport int,"
                                "smac varchar(20),"
                                "dip varchar(20),"
                                "dport int,"
                                "dmac varchar(20),"
                                "protocol varchar(20),"
                                "packet_info TEXT);");
    if (! query.exec(sqlCreate)){
        qDebug() << "创建packets表失败";
    }
    QString sqlCreateHosts = QString("create table hosts(id integer primary key autoincrement,"
                                "mac varchar(20));");
    if (! query.exec(sqlCreateHosts)){
        qDebug() << "创建hosts表失败";
    }
}

void DataProcess::print_ethernet(ether_header *eth){
    sip = "";
    dip = "";
    smac = "";
    dmac = "";
    sport = 0;
    dport = 0;
    dmac = mac_ntoa(eth->ether_dhost);
    smac = mac_ntoa(eth->ether_shost);
    protocol = "Ethernet";
    packet_info = "";

    int type = ntohs(eth->ether_type);
    if (type <= 1500){
        packet_info.append("IEEE 802.3 Ethernet Frame:\n");
    }
    else{
        packet_info.append("\nEthernet Frame:\n");
    }
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Destination MAC address: %17s |\n", mac_ntoa(eth->ether_dhost)));
    packet_info.append(QString::asprintf("| Source MAC address: %17s      |\n", mac_ntoa(eth->ether_shost)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");

    if (type < 1500){
        packet_info.append(QString::asprintf("| length: %5u   |\n", type));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
    }
    else{
        packet_info.append(QString::asprintf("| Ethernet Type: 0x%04x  |\n", type));
        if (type == 0X0200){
            packet_info.append("| Ethernet Type: xerox PUP |\n");
            packet_info.append("|------------------------------------------------------------------------------------|\n");
        }
        else if (type == ETHERTYPE_IP){ //0x0800
            packet_info.append("| Ethernet Type: IP |\n");
            packet_info.append("|------------------------------------------------------------------------------------|\n");
        }
        else if (type == ETHERTYPE_ARP){ //0x0806
            packet_info.append("| Ethernet Type:arp |\n");
            packet_info.append("|------------------------------------------------------------------------------------|\n");
        }
        else if (type == ETHERTYPE_REVARP){ //0X8035
            packet_info.append("| Ethernet Type: REVARP |\n");
            packet_info.append("|------------------------------------------------------------------------------------|\n");
        }
        else{
            packet_info.append("| Ethernet Type: unknown |\n");
            packet_info.append("|------------------------------------------------------------------------------------|\n");
        }
    }
}

void DataProcess::print_arp(ether_arp *arp){
    protocol = "ARP";
    sip = inet_ntoa(*(struct in_addr*)&arp->arp_spa);
    dip = inet_ntoa(*(struct in_addr*)&arp->arp_tha);

    static char* arp_operation[] = {
            "Undefine",
            "(ARP Request)",
            "(ARP Reply)",
            "(RARP Request)",
            "(RARP Reply)"
        };

        int op = ntohs(arp->ea_hdr.ar_op);
        if (op <= 0 || op > 5){
            op = 0;
        }
        packet_info.append("\nProtocol:ARP\n");
        packet_info.append("|------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| Hardaddr Type: %2u % -11s | Protocol: 0x%04x %-9s |\n",
            ntohs(arp->ea_hdr.ar_hrd),
            (ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER) ? "(ETHERNET)" : "( NOT OTHER)",
            ntohs(arp->ea_hdr.ar_pro),
            (ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) ? "(IP)" : "(NOT IP)"));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| MAC addrlen:%3u | Protocol Addrlen %2u | op: %4d %16s |\n",
            arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln, ntohs(arp->ea_hdr.ar_op), arp_operation[op]));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| Sourc MAC address %17s |\n", mac_ntoa(arp->arp_sha)));
        packet_info.append("-------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| Destination MAC address %17s |\n", mac_ntoa(arp->arp_tha)));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| Source IP address %15s |\n", inet_ntoa(*(struct in_addr*)&arp->arp_spa)));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
        packet_info.append(QString::asprintf("| Destination IP address %15s |\n", inet_ntoa(*(struct in_addr*)&arp->arp_tha)));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
}

void DataProcess::print_ip(ip *ip){
    protocol = "IP";
    sip = inet_ntoa(*(struct in_addr*)&(ip->ip_src));
    dip = inet_ntoa(*(struct in_addr*)&(ip->ip_dst));

    packet_info.append("\nProtocol:IP\n");
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| IV:%1u | HL: %2u | TOS:%8s | Total_len: %10u |\n", ip->ip_v, ip->ip_hl, ip_ttoa(ip->ip_tos), ntohs(ip->ip_len)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Identifier:%5u | Flag(R D M):%3s | Off_set:%5u |\n", ntohs(ip->ip_id), ip_ftoa(ntohs(ip->ip_off)), ntohs(ip->ip_off & IP_OFFMASK))); //IP_OFFMASK = 0x1fff
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| TTL:%3u | Pro:%3u | Header checksum: %5u |\n", ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Soure IP Address: %15s |\n", inet_ntoa(*(struct in_addr*)&(ip->ip_src))));
    packet_info.append(QString::asprintf("| Destination IP Address:%15s |\n", inet_ntoa(*(struct in_addr*)&(ip->ip_dst))));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
}

void DataProcess::print_tcp(tcphdr *tcp){
    protocol = "TCP";
    sport = ntohs(tcp->th_sport);
    dport = ntohs(tcp->th_dport);

    packet_info.append("\nProtocol:TCP\n");
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Source Port: %5u | Destination Port: %5u |\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Seq_num: %10lu |\n", (u_long)ntohl(tcp->th_seq)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Ack_numb: %10lu |\n", (u_long)ntohl(tcp->th_ack)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Off_len: %2u | Reserved | F:%6s | Win_size: %5u |\n", tcp->th_off, tcp_ftoa(tcp->th_flags), ntohs(tcp->th_win)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Checksum: %5u | Urg_pointer: %5u |\n", ntohs(tcp->th_sum), ntohs(tcp->th_urp)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
}

void DataProcess::print_udp(udphdr *udp){
    protocol = "UDP";
    sport = ntohs(udp->uh_sport);
    dport = ntohs(udp->uh_dport);

    packet_info.append("\nProtocol: UDP\n");
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Source Port: %5u | Destination Port: %5u |\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Length:%5u | Checksum: %5u |\n", ntohs(udp->uh_ulen), ntohs(udp->uh_sum)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
}

void DataProcess::print_icmp(icmp *icmp){
    protocol = "ICMP";

    static char* type_name[] = {
        "Echo Reply",
        "Undefine",
        "Undefine",
        "Destination Unreachable",
        "Source Quench",
        "Redirect(change route)",
        "Undefine",
        "Undefine",
        "Echo Reqest",
        "Undefine",
        "Undefine",
        "Timeout",
        "Parameter Problem",
        "Timestamp Request",
        "Timestamp Reply",
        "Inforamation Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply",
        "Unknown"
    };

    int type = icmp->icmp_type;
    if ((type < 0) || (type > 18)){
        type = 19;
    }
    packet_info.append(QString::asprintf("\nProtocol:ICMP ----- %s \n", type_name[type]));
    packet_info.append("|------------------------------------------------------------------------------------|\n");
    packet_info.append(QString::asprintf("| Type:%3u | Code:%3u | CheckSum:%5u |\n", icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum)));
    packet_info.append("|------------------------------------------------------------------------------------|\n");

    if (icmp->icmp_type == 0 || icmp->icmp_type == 8){
        packet_info.append(QString::asprintf("| Identification: %5u | Seq_num %5u |\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq)));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
    }
    else if (icmp->icmp_type == 3){
        if (icmp->icmp_code == 4){
            packet_info.append(QString::asprintf("| void  %5u | Next_mtu %5u |\n", ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu)));
            packet_info.append("|--------------------------------------------------------------------------------|\n");
        }
        else{
            packet_info.append(QString::asprintf("| Unused %10u |\n", (u_long)ntohl(icmp->icmp_void)));
            packet_info.append("|--------------------------------------------------------------------------------|\n");
        }
    }
    else if (icmp->icmp_type == 5){
        packet_info.append(QString::asprintf("| Router IP Address: %15s |\n", inet_ntoa(*(struct in_addr*)&(icmp->icmp_gwaddr))));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
    }
    else if (icmp->icmp_type == 11){
        packet_info.append(QString::asprintf("| Unused: %10lu |\n", (u_long)ntohl(icmp->icmp_void)));
        packet_info.append("|------------------------------------------------------------------------------------|\n");
    }

    if (icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11){
        print_ip((struct ip*)(((char*)icmp) + 8));
    }
}

void DataProcess::dump_packet(unsigned char *buff, int len){
    int i, j;
    printf("\nFrame Dump: \n");
    packet_info.append("\nFrame Dump: \n");

    for (i = 0; i < len; i += 16){
        for (j = i; j < i + 16 && j < len; j++){
            printf("%02x", buff[j]);
            packet_info.append(QString::asprintf("%02x", buff[j]));
            if (j % 2 == 1){
                printf(" ");
                packet_info.append(" ");
            }
        }
        if ((j == len) && (len % 16 != 0)){
            for (j = 0; j < 40 - (len % 16) * 2.5; j++){
                printf(" ");
                packet_info.append(" ");
            }
            printf(";");
            packet_info.append(";");
        }

        for (j = i; j < i + 16 && j < len; j++){
            if ((buff[j] >= 0x20) && (buff[j] <= 0x7e)){
                printf("%c",(buff[j]));
//                packet_info.append(QString(buff[j]));
            }
            else{
                printf(".");
//                packet_info.append(".");
            }
        }
        printf("\n");
        packet_info.append("\n");
    }
}

char *DataProcess::mac_ntoa(u_char *d){
    static char str[50];
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

char *DataProcess::tcp_ftoa(int flag){
    static int f[] = {
            'U',
            'A',
            'P',
            'R',
            'S',
            'F'
    };
    static char str[17];
    u_int mask = 1 << 5; //0x20;
    int i;
    for (i = 0; i < 6; i++){
        if (((flag << i) & mask) != 0){
            str[i] = f[i];
        }
        else{
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}

char *DataProcess::ip_ttoa(int flag){
    static int f[] = { '1', '1', '1', 'D', 'T', 'R', 'C', 'X' };
    static char str[17];
    u_int mask = 0x80;
    int i;
    for (i = 0; i < 8; i++){
        if (((flag << i) & mask) != 0){
            str[i] = f[i];
        }
        else{
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}

char *DataProcess::ip_ftoa(int flag){
    static int f[] = { 'R', 'D', 'M' };
    static char str[17];
    u_int mask = 0x8000;
    int i;
    for (i = 0; i < 3; i++){
        if (((flag << i) & mask) != 0){
            str[i] = f[i];
        }
        else{
            str[i] = '0';
        }
    }
    str[i] = '\0';
    return str;
}

void DataProcess::insertDate(QString time, int len){
    QString insert = QString("insert into packets(time, length, sip, sport, smac, dip, dport, dmac, protocol, packet_info) values('%1', '%2', '%3', '%4', '%5', '%6', '%7', '%8', '%9', '%10');").arg(time).arg(len).arg(sip).arg(sport)
                            .arg(smac).arg(dip).arg(dport).arg(dmac).arg(protocol).arg(packet_info);
    QSqlQuery query(db);
    if( !query.exec(insert)){
        qDebug() << "插入错误";
        qDebug() << db.lastError().text();
    }
    QSqlQueryModel *model = new QSqlQueryModel;
    emit updateView_packet(model);
    query.clear();
}

void DataProcess::insertHosts(){
    QSqlQuery query(db);
    if( !query.exec(QString("insert into hosts(mac) values('%1');").arg(smac)) ){
        qDebug() << "插入smac错误";
        qDebug() << db.lastError().text();
    }
    if( !query.exec(QString("insert into hosts(mac) values('%1');").arg(dmac)) ){
        qDebug() << "插入dmac错误";
        qDebug() << db.lastError().text();
    }
    QSqlQueryModel *model = new QSqlQueryModel;
    emit updateView_hosts(model);
    query.clear();
}

void DataProcess::sendQueryFunction(){
    QSqlQuery query(db);
    emit sendQuery(query);
}

void DataProcess::sendModel(){
    QSqlQueryModel *model = new QSqlQueryModel;
    emit sendQueryModel(model);
}

void DataProcess::closeDB(){
    db.close();
}


