#include "scanning.h"
#include "ui_scanning.h"

QStringList rt_ip_list, rt_len, rt_macPack;
u_char *rt_packet_infov;
pcap_t *rt_d_pcap;

bool thread_stop;

scanning::scanning(QWidget *parent) : QDialog(parent), ui(new Ui::scanning) {
    ui->setupUi(this);
}

scanning::~scanning() {
    delete ui;
}

void scanning::on_StartBtn_clicked() {
    thread_stop = false;
    if(ui->scanning_text->text() == "Input your Router's IP Address" || ui->scanning_text->text().isEmpty()) QMessageBox::warning(this, "Warning!!", "If you don't know how to use it,\nyou can click 'Help' button.");
    else {
        sys_ip = ui->scanning_text->text();
        if(sys.isEmpty()) {
            sys.append("arp -d ");
            sys.append(sys_ip);
            th = new routing_thread();
        }
        else th = new routing_thread();
        th->set_sys(sys, sys_ip);
        th->start();
        md = new QStringListModel();
        connect(th, SIGNAL(setList(QStringList)), this, SLOT(rt_getList(QStringList)));
    }
}

void scanning::on_StopBtn_clicked() {
    connect(th, SIGNAL(setLength(QStringList)), this, SLOT(rt_getLength(QStringList)));
    connect(th, SIGNAL(setMacPacket(QStringList)), this, SLOT(rt_getMacPacket(QStringList)));
    connect(th, SIGNAL(packet_info(u_char*)), this, SLOT(rt_getPacket_info(u_char*)));
    connect(th, SIGNAL(dump_pcap(pcap_t*)), this, SLOT(rt_getDump_pcap(pcap_t*)));
    stopThread();
}

void scanning::on_HelpBtn_clicked() {
    QMessageBox::information(this, "Help", "If you don't know how about router's IP address, follow it.\n1. Open a terminal\n2. Insert 'route'\n3. Default Gateway is your router's IP address");
}

void scanning::on_SelectBtn_clicked() {
    if(!ui->listView->currentIndex().isValid() || !thread_stop) QMessageBox::information(this, "Warning", "You must select 1 IP address at least.\nIf you don't know how to use it, please click help button.");
    else {
        stopThread();
        emit rt_setMacPacket(rt_macPack);
        emit rt_packet_info(rt_packet_infov);
        emit rt_dump_pcap(rt_d_pcap);
        emit rt_setList(rt_ip_list, ui->listView->currentIndex().row());
        emit rt_setLength(rt_len);
        this->close();
    }
}

void scanning::on_CancelBtn_clicked() {
    stopThread();
    this->close();
}

void scanning::rt_getList(QStringList pack_list) {
    rt_ip_list = pack_list;
    md->setStringList(rt_ip_list);
    ui->listView->setModel(md);
}

void scanning::rt_getLength(QStringList len_list) {
    rt_len = len_list;
}

void scanning::rt_getMacPacket(QStringList mac_list) {
    rt_macPack = mac_list;
}

void scanning::rt_getPacket_info(u_char *packet) {
    rt_packet_infov = packet;
}

void scanning::rt_getDump_pcap(pcap_t *p) {
    rt_d_pcap = p;
    QMessageBox::information(this, "Success!!", "IP Scan is finish successfully!!");
}

void scanning::stopThread() {
    if(!thread_stop) {
        thread_stop = true;
        th->set_stop(thread_stop);
        system(sys.toStdString().c_str());
        system("arp >/dev/null");
    }
}
