#ifndef ROUTING_THREAD_H
#define ROUTING_THREAD_H

#include <QThread>
#include <QtCore>
#include <QtWidgets>
#include <pcap.h>
#include "hostname.h"

class routing_thread : public QThread
{
    Q_OBJECT
public:
    explicit routing_thread(QObject *parent = 0);
    void run();
    void set_stop(bool);
    void set_sys(QString, QString);

    hostname *host_name;

signals:
    void setList(QStringList);
    void setLength(QStringList);
    void setMacPacket(QStringList);
    void packet_info(u_char*);
    void dump_pcap(pcap_t*);
};

#endif
