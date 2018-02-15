#ifndef RELAY_SPOOF_H
#define RELAY_SPOOF_H

#include <QThread>
#include <QtWidgets>
#include <QtCore>
#include "common_func.h"

class relay_spoof : public QThread
{
    Q_OBJECT
public:
    explicit relay_spoof(QObject *parent = 0);
    void run();

    void relayGetMacInfo(QString, QString, QString, pcap_if_t*);
    bool spoofStop;

signals:
    void relay_urlList(QStringList);
    void relay_dataList(QStringList);
    void spoof_packet(u_char *);
    void relay_spoofFin(bool);

private:
    QString relayAtkMac, relayRouterMac, relayVictimMac;
};

#endif // RELAY_SPOOF_H
