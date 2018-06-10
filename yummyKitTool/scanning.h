#ifndef SCANNING_H
#define SCANNING_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include <QThread>
#include "common_func.h"
#include "get_gateway.h"
#include "scanning_thread.h"

namespace Ui {
class scanning;
}

class scanning : public QDialog
{
    Q_OBJECT

public:
    explicit scanning(QWidget *parent = 0);
    ~scanning();

    scanning_thread *scanThread;

private slots:
    void on_StartBtn_clicked();
    void on_StopBtn_clicked();
    void on_HelpBtn_clicked();
    void on_SelectBtn_clicked();
    void on_CancelBtn_clicked();

public slots:
    void scanGetIPList(QString);
    void scanGetHostList(QStringList);
    void scanGetLength(QStringList);
    void scanGetMacList(QString);
    void scanGetPacket(u_char*);
    void scanGetPcap(pcap_t*);

signals:
    void scanSetIPList(QStringList, int);
    void scanSetLength(QStringList);
    void scanSetMacList(QStringList);
    void scanSetPacket(u_char*);
    void scanSetPcap(pcap_t*);
    void scanSetDevName(pcap_if_t*);
    void scanSetStop(bool);

private:
    Ui::scanning *ui;
    QStandardItemModel *simod;
    QStandardItem *md_ip, *md_host;
    QString sys, sys_ip;
    bool start_cnt;
    void stopThread();
    void findDevs();
};

#endif // SCANNING_H
