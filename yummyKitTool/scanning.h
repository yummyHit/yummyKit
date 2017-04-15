#ifndef SCANNING_H
#define SCANNING_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include <QThread>
#include <pcap.h>
#include "routing_thread.h"

namespace Ui {
class scanning;
}

class scanning : public QDialog
{
    Q_OBJECT

public:
    explicit scanning(QWidget *parent = 0);
    ~scanning();

    routing_thread *th;
    int rt_index;

private slots:
    void on_StartBtn_clicked();

    void on_StopBtn_clicked();

    void on_HelpBtn_clicked();

    void on_SelectBtn_clicked();

    void on_CancelBtn_clicked();

public slots:
    void rt_getList(QStringList);
    void rt_getLength(QStringList);
    void rt_getMacPacket(QStringList);
    void rt_getPacket_info(u_char*);
    void rt_getDump_pcap(pcap_t*);

signals:
    void rt_setList(QStringList, int);
    void rt_setLength(QStringList);
    void rt_setMacPacket(QStringList);
    void rt_packet_info(u_char*);
    void rt_dump_pcap(pcap_t*);

private:
    Ui::scanning *ui;
    QStringListModel *md;
    QString sys, sys_ip;
    void stopThread();
};

#endif // SCANNING_H
