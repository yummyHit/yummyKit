#ifndef SCANNING_THREAD_H
#define SCANNING_THREAD_H

#include <QThread>
#include <QtCore>
#include <QtWidgets>
#include <pcap.h>
#include "hostname.h"

class scanning_thread : public QThread
{
    Q_OBJECT
public:
    explicit scanning_thread(QObject *parent = 0);
    void run();
    void scanThreadSetStop(bool);
    void scanThreadSetSys(QString, QString, int, pcap_if_t*);

    hostname *host_name;

signals:
    void scanThreadSetIPList(QString);
    void scanThreadSetLength(QStringList);
    void scanThreadSetMacList(QString);
    void scanThreadPacket(u_char*);
    void scanThreadPcap(pcap_t*);
};

#endif // SCANNING_THREAD_H
