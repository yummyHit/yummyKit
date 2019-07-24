#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtCore>
#include <QtWidgets>
#include "falsify.h"
#include "scanning.h"
#include "wifi_cracking.h"
#include "common_func.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = 0);
	~MainWindow();

public slots:
	void mainGetIPList(QStringList, int);
	void mainGetLength(QStringList);
	void mainGetMacList(QStringList);
	void mainGetPacket(u_char*);
	void mainGetPcap(pcap_t*);
	void mainGetDevName(pcap_if_t*);
	void mainGetStop(bool);

private slots:
	void on_actionIP_Scan_triggered();
	void on_actionFalsify_Packet_triggered();
	void on_actionWiFi_Cracking_triggered();

private:
	Ui::MainWindow *ui;
	QProgressBar *pb;
	QLabel *lbl;
	scanning *scan;
	wifi_cracking *wc;
	QStringListModel *main_model;
};

#endif // MAINWINDOW_H
