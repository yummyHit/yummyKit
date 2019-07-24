#include "falsify.h"
#include "ui_falsify.h"

falsify::falsify(QWidget *parent) : QDialog(parent), ui(new Ui::falsify) {
	ui->setupUi(this);
}

falsify::~falsify() {
	delete ui;
}

void falsify::on_SpoofBtn_clicked() {
	if(ui->routerMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Router's Mac Empty!! Retry..");
	else if(ui->myMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "My's Mac Empty!! Retry..");
	else if(ui->targetMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Target's Mac Empty!! Retry..");
	else if(ui->srcAddressEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Input Your IP Address.\nsuch as XXX.XXX.XXX.XXX");
	else if(ui->dstAddressEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Target's IP Address Empty!! Retry..");
	else {
		spoof = new spoofUrl();
		spoof->spoofGetInfo(falsifyGetVictimIP, falsifyGetVictimMac, falsifyGetRouterIP, falsifyGetRouterMac, falsifyGetAtkMac, falsifyGetLen, falsifyPacket, falsifyPcap, falsifyDevs);
		spoof->exec();
	}
}

void falsify::on_CancelBtn_clicked() {
	falsify::close();
}

void falsify::pktGetInfo(QString a, QString b, QString c, QString d, QString e, QString f, QString g, u_char *h, pcap_t *i, pcap_if_t *j) {
	falsifyGetVictimIP = a;
	falsifyGetRouterIP = b;
	falsifyGetAtkIP = c;
	falsifyGetLen = d;
	falsifyGetRouterMac = e;
	falsifyGetAtkMac = f;
	falsifyGetVictimMac = g;
	falsifyPacket = h;
	falsifyPcap = i;
	falsifyDevs = j;
	ui->srcAddressEdit->setText(falsifyGetAtkIP);
	ui->dstAddressEdit->setText(falsifyGetVictimIP);
	ui->routerMacEdit->setText(falsifyGetRouterMac);
	ui->myMacEdit->setText(falsifyGetAtkMac);
	ui->targetMacEdit->setText(falsifyGetVictimMac);
}
