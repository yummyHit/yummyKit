#include "scanning.h"
#include "ui_scanning.h"
#include <iostream>
#include <fstream>

QString scan_ip;
QStringList rt_ip_list, rt_len, rt_macPack;
u_char *rt_packet_infov;
pcap_t *rt_d_pcap;

bool thread_stop;

scanning::scanning(QWidget *parent) : QDialog(parent), ui(new Ui::scanning) {
    ui->setupUi(this);
    std::ifstream fin;
    char buf[10];

    system("route -n | grep UG | awk \'{ print $2 }\' > ./nbtscan_log.txt");
    system("ls -l | grep nbtscan_log.txt | awk \'{ print $5 }\' > ./nbtscan_check.txt");

    fin.open("./nbtscan_check.txt");
    while(fin >> buf) {}
    fin.close();
    if(!strcmp(buf, "0")) {
        ui->StartBtn->setEnabled(false);
        ui->StopBtn->setEnabled(false);
        ui->SelectBtn->setEnabled(false);
        ui->scanning_text->setText("You are not connect to Network. Click \'Help\' Button.");
    }
    else {
        fin.open("./nbtscan_log.txt");
        while(fin >> buf) {}
        fin.close();
        scan_ip.append(buf);
        ui->scanning_text->setText("Your router ip address is " + scan_ip);

        simod = new QStandardItemModel(0, 2, this);
        simod->setHorizontalHeaderItem(0, new QStandardItem(QString("IP Address")));
        simod->setHorizontalHeaderItem(1, new QStandardItem(QString("Host Name")));
        ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
        ui->tableView->setModel(simod);
    }
    ui->scanning_text->setEnabled(false);
    system("sudo rm ./nbtscan_check.txt ./nbtscan_log.txt");
}

scanning::~scanning() {
    delete ui;
}

void scanning::on_StartBtn_clicked() {
    thread_stop = false;
    QChar check = *(scan_ip.unicode());
    if(check.isNull() || !check.isDigit()) QMessageBox::warning(this, "Warning!!", "If you don't know how to use it,\nyou can click 'Help' button.");
    else if(!sys_ip.isEmpty() && th->isRunning()) QMessageBox::warning(this, "Warning!!", "Scanning is already running!!\nIf you want new scan, first click stop button.\nAnd click start button.");
    else {
        sys_ip = scan_ip;
        if(sys.isEmpty()) {
            sys.append("arp -d ");
            sys.append(sys_ip);
            th = new routing_thread();
        }
        else th = new routing_thread();
        th->set_sys(sys, sys_ip);
        th->start();
        connect(th, SIGNAL(setList(QStringList)), this, SLOT(rt_getList(QStringList)));
        connect(th, SIGNAL(setLength(QStringList)), this, SLOT(rt_getLength(QStringList)));
        connect(th, SIGNAL(setMacPacket(QStringList)), this, SLOT(rt_getMacPacket(QStringList)));
        connect(th, SIGNAL(packet_info(u_char*)), this, SLOT(rt_getPacket_info(u_char*)));
        connect(th, SIGNAL(dump_pcap(pcap_t*)), this, SLOT(rt_getDump_pcap(pcap_t*)));
        connect(th->host_name, SIGNAL(setHostName(QStringList)), this, SLOT(rt_getHostName(QStringList)));
    }
}

void scanning::on_StopBtn_clicked() {
    stopThread();
}

void scanning::on_HelpBtn_clicked() {
    if(!ui->StartBtn->isEnabled())QMessageBox::warning(this, "Failed!!", "Your network isn't connected by network!!\nYou must connect a network!!");
    else QMessageBox::information(this, "Help", "If you don't know how about router's IP address, follow it.\n1. Open a terminal\n2. Insert 'route'\n3. Default Gateway is your router's IP address");
}

void scanning::on_SelectBtn_clicked() {
    if(!ui->tableView->currentIndex().isValid()) QMessageBox::information(this, "Warning", "You must select 1 IP address at least.\nIf you don't know how to use it, please click help button.");
    else if(!thread_stop) QMessageBox::information(this, "Warning", "Scanning is running!!\nIf you want select button, first click stop button.\nOr wait a second. Then you can click select button.");
    else {
        stopThread();
        emit rt_setMacPacket(rt_macPack);
        emit rt_packet_info(rt_packet_infov);
        emit rt_dump_pcap(rt_d_pcap);
        emit rt_setList(rt_ip_list, ui->tableView->currentIndex().row());
        emit rt_setLength(rt_len);
        this->close();
    }
}

void scanning::on_CancelBtn_clicked() {
    stopThread();
    emit rt_cancel(true);
    this->close();
}

void scanning::rt_getList(QStringList pack_list) {
    rt_ip_list = pack_list;
    for(int i = 0; i < rt_ip_list.length(); i++) {
        md_ip = new QStandardItem(rt_ip_list.at(i));
        simod->setItem(i, 0, md_ip);
    }
}

void scanning::rt_getHostName(QStringList host_list) {
    for(int i = 0; i < host_list.length(); i++) {
        md_host = new QStandardItem(host_list.at(i));
        simod->setItem(i, 1, md_host);
    }
}

void scanning::rt_getLength(QStringList len_list) {
    if(len_list.at(0) == "root_squash") {
        QMessageBox::information(this, "Failed!!", "You must open yummyKit program with root.\nPlease re-run yummyKit with root account!!");
        thread_stop = true;
    }
    else rt_len = len_list;
}

void scanning::rt_getMacPacket(QStringList mac_list) {
    rt_macPack = mac_list;
}

void scanning::rt_getPacket_info(u_char *packet) {
    rt_packet_infov = packet;
}

void scanning::rt_getDump_pcap(pcap_t *p) {
    rt_d_pcap = p;
    thread_stop = true;
    QMessageBox::information(this, "Success!!", "IP Scan is finish successfully!!");
}

void scanning::stopThread() {
    if(!thread_stop) {
        thread_stop = true;
        th->set_stop(thread_stop);
        system(sys.toStdString().c_str());
        system("arp -a >/dev/null");
    }
}
