#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtCore>
#include <QtWidgets>

QStringList mainIPList, mainLen, mainMacList;
u_char *mainPacket;
pcap_t *mainPcap;
pcap_if_t *mainDevs;
int row_index;
bool scanStopBtn = false;

QString routing_ip, main_my_ip;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
	ui->setupUi(this);
//	ui->listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

MainWindow::~MainWindow() {
	delete ui;
}

void MainWindow::on_actionIP_Scan_triggered() {
	if(routing_ip.isEmpty() && !scanStopBtn) scan = new scanning(this);
	main_model = new QStringListModel();
	connect(scan, SIGNAL(scanSetIPList(QStringList, int)), this, SLOT(mainGetIPList(QStringList, int)));
	connect(scan, SIGNAL(scanSetLength(QStringList)), this, SLOT(mainGetLength(QStringList)));
	connect(scan, SIGNAL(scanSetMacList(QStringList)), this, SLOT(mainGetMacList(QStringList)));
	connect(scan, SIGNAL(scanSetPacket(u_char*)), this, SLOT(mainGetPacket(u_char*)));
	if(mainPcap == NULL) connect(scan, SIGNAL(scanSetPcap(pcap_t*)), this, SLOT(mainGetPcap(pcap_t*)));
	connect(scan, SIGNAL(scanSetDevName(pcap_if_t*)), this, SLOT(mainGetDevName(pcap_if_t*)));
	connect(scan, SIGNAL(scanSetStop(bool)), this, SLOT(mainGetStop(bool)));
	scan->exec();
}

void MainWindow::on_actionFalsify_Packet_triggered()
{
	if(!mainMacList.isEmpty()) {
		falsify *pkt = new falsify(this);
		pkt->pktGetInfo(ui->listView->currentIndex().data().toString(), routing_ip, main_my_ip, mainLen.at(row_index-1), mainMacList.at(0), mainMacList.at(1), mainMacList.at(row_index), mainPacket, mainPcap, mainDevs);
		pkt->exec();
	}
	else QMessageBox::warning(this, "Dangerous!!", "First, you must execute routing.");
}

void MainWindow::mainGetIPList(QStringList pack_list, int scan_index) {
	mainIPList.clear();
	routing_ip = pack_list.at(0);
	main_my_ip = pack_list.at(1);
	row_index = scan_index;
	mainIPList.append(pack_list.at(row_index));
	main_model->setStringList(mainIPList);
	ui->listView->setModel(main_model);
}

void MainWindow::mainGetLength(QStringList len_list) {
	mainLen = len_list;
}

void MainWindow::mainGetMacList(QStringList mac_list) {
	mainMacList = mac_list;
}

void MainWindow::mainGetPacket(u_char *packet) {
	mainPacket = packet;
}

void MainWindow::mainGetPcap(pcap_t *pcap) {
	mainPcap = pcap;
	QMessageBox::information(this, "Success!!", "Select a Packet successfully!!\nYou can try spoofing!!");
}

void MainWindow::mainGetDevName(pcap_if_t *devs) {
	mainDevs = devs;
}

void MainWindow::mainGetStop(bool c) {
	scanStopBtn = c;
}

void MainWindow::on_actionWiFi_Cracking_triggered() {
	wc = new wifi_cracking(this);
	wc->exec();
}
