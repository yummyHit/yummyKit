#ifndef FALSIFY_H
#define FALSIFY_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include "mainwindow.h"
#include "spoofurl.h"
#include "common_func.h"

namespace Ui {
class falsify;
}

class falsify : public QDialog
{
	Q_OBJECT

public:
	explicit falsify(QWidget *parent = 0);
	~falsify();

	void pktGetInfo(QString, QString, QString, QString, QString, QString, QString, u_char*, pcap_t*, pcap_if_t*);

	spoofUrl *spoof;

private slots:
	void on_SpoofBtn_clicked();
	void on_CancelBtn_clicked();

private:
	Ui::falsify *ui;
	QString falsifyGetVictimIP, falsifyGetVictimMac, falsifyGetAtkIP, falsifyGetAtkMac, falsifyGetRouterIP, falsifyGetRouterMac, falsifyGetLen;
	u_char *falsifyPacket;
	pcap_t *falsifyPcap;
	pcap_if_t *falsifyDevs;
};

#endif // FALSIFY_H
