#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->tableView_packet->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableView_packet->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView_hosts->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget_tally->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->tableView_hosts->horizontalHeader()->setStretchLastSection(true);
    ui->tableView_packet->horizontalHeader()->setStretchLastSection(true);
    ui->tableView_packet->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView_hosts->setStyleSheet("selection-background-color:lightblue;");
    ui->tableView_packet->setStyleSheet("selection-background-color:lightblue;");

    QRegExp regx("[0-9]+$");
    QValidator* validator = new QRegExpValidator(regx);
    ui->lineEdit_sport->setValidator(validator);
    ui->lineEdit_dport->setValidator(validator);

    s.moveToThread(&m_thread);
    dp.moveToThread(&data_thread);
    connect(this, &MainWindow::startSniff, &s, &sniffer::sniff);
    connect(&s, &sniffer::print_ethernet, &dp, &DataProcess::print_ethernet);
    connect(&s, &sniffer::print_arp, &dp, &DataProcess::print_arp);
    connect(&s, &sniffer::print_ip, &dp, &DataProcess::print_ip);
    connect(&s, &sniffer::print_tcp, &dp, &DataProcess::print_tcp);
    connect(&s, &sniffer::print_udp, &dp, &DataProcess::print_udp);
    connect(&s, &sniffer::print_icmp, &dp, &DataProcess::print_icmp);
    connect(&s, &sniffer::dump_packet, &dp, &DataProcess::dump_packet);
    connect(&s, &sniffer::insertData, &dp, &DataProcess::insertDate);
    connect(&s, &sniffer::insertHosts, &dp, &DataProcess::insertHosts);

    //更新数据库
    connect(&dp, &DataProcess::updateView_packet, this, [=](QSqlQueryModel *model){
        model->setQuery("Select id, time, length, sip, sport, smac, dip, dport, dmac, protocol from packets;");
        model->setHeaderData(0, Qt::Horizontal, "ID");
        model->setHeaderData(1, Qt::Horizontal, "时间戳");
        model->setHeaderData(2, Qt::Horizontal, "长度");
        model->setHeaderData(3, Qt::Horizontal, "源IP");
        model->setHeaderData(4, Qt::Horizontal, "源端口号");
        model->setHeaderData(5, Qt::Horizontal, "源MAC");
        model->setHeaderData(6, Qt::Horizontal, "目的IP");
        model->setHeaderData(7, Qt::Horizontal, "目的端口号");
        model->setHeaderData(8, Qt::Horizontal, "目的MAC");
        model->setHeaderData(9, Qt::Horizontal, "协议");
        ui->tableView_packet->setModel(model);
    }, Qt::BlockingQueuedConnection);
    connect(&dp, &DataProcess::updateView_hosts, this, [=](QSqlQueryModel *model){
        model->setQuery("select * from hosts group by mac;");
        model->setHeaderData(0, Qt::Horizontal, "ID");
        model->setHeaderData(1, Qt::Horizontal, "MAC地址");
        ui->tableView_hosts->setModel(model);
    }, Qt::BlockingQueuedConnection);
}

MainWindow::~MainWindow(){
    delete ui;
    dp.closeDB();
}


void MainWindow::on_Btn_start_clicked(){
    if(m_thread.isRunning())
        return;
    m_thread.start();
    data_thread.start();
    s.setFlag(false);
    emit startSniff();

    mytime = QDateTime::currentDateTime();
    time1 = mytime.toString("yyyy/MM/dd hh:mm:ss");
    second1 = QDateTime::currentSecsSinceEpoch();
}

void MainWindow::on_Btn_end_clicked(){
    mytime = QDateTime::currentDateTime();
    time2 = mytime.toString("yyyy/MM/dd hh:mm:ss");
    second2 = QDateTime::currentSecsSinceEpoch();

    s.setFlag(true);
    m_thread.quit();
    data_thread.quit();
}


void MainWindow::on_tableView_packet_doubleClicked(const QModelIndex &index){
    //index.row()从0开始
    QSqlQuery query(dp.db);
//    dp.sendQueryFunction();
//    connect(&dp, &DataProcess::sendQuery, [=](QSqlQuery query){

    //用于获取主键id
    QAbstractItemModel* m = (QAbstractItemModel*)index.model();
    QModelIndex x = m->index(index.row(),0);
    int id = x.data().toString().toInt();
    query.exec(QString("select packet_info from packets where id='%1';").arg(id));
    QString packet_info = "";
    if(query.first())
        packet_info = query.value(0).toString();
    dlg->setText(packet_info);
    dlg->show();
//    });
}


void MainWindow::on_pushButton_tally_clicked(){
    if( !m_thread.isFinished() ){
        QMessageBox::warning(this, "警告", "请先停止嗅探");
    }else{
        procTime = second2-second1;
        ui->tableWidget_tally->setColumnCount(2);
        ui->tableWidget_tally->setRowCount(11);
        ui->tableWidget_tally->setHorizontalHeaderLabels(QStringList()<<"类别"<<"值");
        ui->tableWidget_tally->horizontalHeader()->setStretchLastSection(true);
        ui->tableWidget_tally->setStyleSheet("selection-background-color:lightblue;");

        QStringList nameList;
        nameList << "开始时间" << "结束时间" << "整体时间(s/秒)" << "总大小(Bit)" << "总速率(Bit/s)"
                 << "以太网包数量" << "ARP包数量" << "IP包数量" << "TCP包数量" << "UDP包数量" << "ICMP包数量";
        QStringList valueList;
        valueList << time1 << time2 << QString::number(procTime) << QString::number(s.totalLength) << QString::number(s.totalLength/procTime)
                  << QString::number(s.totalPackets) << QString::number(s.arpPackets) << QString::number(s.ipPackets) << QString::number(s.tcpPackets) << QString::number(s.udpPackets) << QString::number(s.icmpPackets);
        for(int i=0; i<ui->tableWidget_tally->rowCount(); i++){
            int col = 0;
            ui->tableWidget_tally->setItem(i, col++, new QTableWidgetItem(nameList[i]));
            ui->tableWidget_tally->setItem(i, col++, new QTableWidgetItem(valueList[i]));
        }
    }
}


void MainWindow::on_pushButton_choice_clicked(){
    QString sip = ui->lineEdit_sip->text();
    QString dip = ui->lineEdit_dip->text();
    QString smac = ui->lineEdit_smac->text();
    QString dmac = ui->lineEdit_dmac->text();
    int sport = ui->lineEdit_sport->text().toInt();
    int dport = ui->lineEdit_dport->text().toInt();

    QString query = QString("select * from packets ");
    if(!sip.isEmpty()||!dip.isEmpty()||!smac.isEmpty()||!dmac.isEmpty()||sport||dport||ui->checkBox_ip->isChecked()||ui->checkBox_udp_ether->isChecked()||ui->checkBox_arp->isChecked()||ui->checkBox_tcp->isChecked()||ui->checkBox_udp->isChecked()||ui->checkBox_icmp->isChecked()){
        query.append("where ");
        if(ui->checkBox_ip->isChecked()||ui->checkBox_udp_ether->isChecked()||ui->checkBox_arp->isChecked()||ui->checkBox_tcp->isChecked()||ui->checkBox_udp->isChecked()||ui->checkBox_icmp->isChecked()){
            query.append("( ");
            if(ui->checkBox_arp->isChecked())
                query.append("protocol = 'ARP' or ");
            if(ui->checkBox_tcp->isChecked())
                query.append("protocol = 'TCP' or ");
            if(ui->checkBox_udp->isChecked())
                query.append("protocol = 'UDP' or ");
            if(ui->checkBox_icmp->isChecked())
                query.append("protocol = 'ICMP' or ");
            if(ui->checkBox_ip->isChecked())
                query.append("protocol = 'IP' or protocol = 'TCP' or protocol = 'UDP' or ");
            if(ui->checkBox_udp_ether->isChecked())
                query.append("protocol = 'Ethernet' or ");
            query.append("0) and ");
        }

        if(!sip.isEmpty())
            query += "sip = '" +sip+ "' and ";
        if(!dip.isEmpty())
            query += "dip = '" +dip+ "' and ";
        if(!smac.isEmpty())
            query += "smac = '" +smac+ "' and ";
        if(!dmac.isEmpty())
            query += "dmac = '" +dmac+ "' and ";
        if(sport)
            query += "sport = " +QString::number(sport)+ " and ";
        if(dport)
            query += "dport = " +QString::number(dport)+ " and ";
        query.append("1");
    }
    query.append(";");
    dp.sendModel();
    connect(&dp, &DataProcess::sendQueryModel, this, [=](QSqlQueryModel *model){
        model->setQuery(query);
        model->setHeaderData(0, Qt::Horizontal, "ID");
        model->setHeaderData(1, Qt::Horizontal, "时间戳");
        model->setHeaderData(2, Qt::Horizontal, "长度");
        model->setHeaderData(3, Qt::Horizontal, "源IP");
        model->setHeaderData(4, Qt::Horizontal, "源端口号");
        model->setHeaderData(5, Qt::Horizontal, "源MAC");
        model->setHeaderData(6, Qt::Horizontal, "目的IP");
        model->setHeaderData(7, Qt::Horizontal, "目的端口号");
        model->setHeaderData(8, Qt::Horizontal, "目的MAC");
        model->setHeaderData(9, Qt::Horizontal, "协议");
        ui->tableView_packet->setModel(model);
    });
}


void MainWindow::on_menuItem_TCP_triggered(){
    menuItem->show();
}

