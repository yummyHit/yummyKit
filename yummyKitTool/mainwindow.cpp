#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtCore>
#include <QtWidgets>
#include <pcap.h>

QStringList ip_list, len, macPack;
u_char *packet_infov;
pcap_t *d_pcap;
int row_index;
bool rt_cancelBtn = false;

QString routing_ip, main_my_ip;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
//    ui->listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::run() {

}

void MainWindow::on_actionIP_Scan_triggered() {
    if(routing_ip.isEmpty() && !rt_cancelBtn) rt = new scanning(this);
    main_model = new QStringListModel();
    connect(rt, SIGNAL(rt_setList(QStringList, int)), this, SLOT(main_getList(QStringList, int)));
    connect(rt, SIGNAL(rt_setLength(QStringList)), this, SLOT(main_getLength(QStringList)));
    connect(rt, SIGNAL(rt_setMacPacket(QStringList)), this, SLOT(main_getMacPacket(QStringList)));
    connect(rt, SIGNAL(rt_packet_info(u_char*)), this, SLOT(main_getPacket_info(u_char*)));
    connect(rt, SIGNAL(rt_dump_pcap(pcap_t*)), this, SLOT(main_getDump_pcap(pcap_t*)));
    connect(rt, SIGNAL(rt_cancel(bool)), this, SLOT(main_getCancel(bool)));
    rt->exec();
}

void MainWindow::on_actionFalsify_Packet_triggered()
{
    if(!macPack.isEmpty()) {
        falsify *pkt = new falsify(this);
        pkt->pkt_getAll(ui->listView->currentIndex().data().toString(), routing_ip, main_my_ip, len.at(row_index-1), macPack.at(0), macPack.at(1), macPack.at(row_index), packet_infov, d_pcap);
        pkt->exec();
    }
    else QMessageBox::warning(this, "Dangerous!!", "First, you must execute routing.");
}

void MainWindow::main_getList(QStringList pack_list, int rt_index) {
    ip_list.clear();
    routing_ip = pack_list.at(0);
    main_my_ip = pack_list.at(1);
    row_index = rt_index;
    ip_list.append(pack_list.at(row_index));
    main_model->setStringList(ip_list);
    ui->listView->setModel(main_model);
}

void MainWindow::main_getLength(QStringList len_list) {
    len = len_list;
}

void MainWindow::main_getMacPacket(QStringList mac_list) {
    macPack = mac_list;
}

void MainWindow::main_getPacket_info(u_char *packet) {
    packet_infov = packet;
}

void MainWindow::main_getDump_pcap(pcap_t *p) {
    d_pcap = p;
    QMessageBox::information(this, "Success!!", "Select a Packet successfully!!\nYou can try spoofing!!");
}

void MainWindow::main_getCancel(bool c) {
    rt_cancelBtn = c;
}
