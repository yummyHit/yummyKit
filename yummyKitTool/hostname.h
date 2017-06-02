#ifndef HOSTNAME_H
#define HOSTNAME_H

#include <QThread>
#include <QtCore>
#include <QtWidgets>
#include <pcap.h>

class hostname : public QThread
{
    Q_OBJECT
public:
    explicit hostname(QObject *parent = 0);
    void run();
    void hostStop(bool);
    void getArgu(u_char*);

    bool host_stop;
signals:
    void setHostName(QStringList);
};

#endif // HOSTNAME_H
