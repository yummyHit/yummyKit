#ifndef RELAY_SPOOF_H
#define RELAY_SPOOF_H

#include <QThread>
#include <QtWidgets>
#include <QtCore>
#include <pcap.h>

class relay_spoof : public QThread
{
    Q_OBJECT
public:
    explicit relay_spoof(QObject *parent = 0);
    void run();

    void mac_get(QString, QString, QString);
    bool get_stop;

signals:
    void urlList(QStringList);
    void data_list(QStringList);
    void spoof_packet(u_char *);
    void spoof_fin(bool);

private:
    QString my_mac, router_mac, victim_mac;
};

#endif // RELAY_SPOOF_H
