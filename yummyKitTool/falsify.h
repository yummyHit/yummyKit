#ifndef FALSIFY_H
#define FALSIFY_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include "mainwindow.h"
#include "spoofurl.h"

namespace Ui {
class falsify;
}

class falsify : public QDialog
{
    Q_OBJECT

public:
    explicit falsify(QWidget *parent = 0);
    ~falsify();

    void pkt_getAll(QString, QString, QString, QString, QString, QString, QString, u_char*, pcap_t*);

    spoofUrl *spoof;

private slots:
    void on_SpoofBtn_clicked();

    void on_CancelBtn_clicked();

private:
    Ui::falsify *ui;
    QString getIP, getMyIP, getRouterIP, getLen, getRouterMac, getMyMac, getVictimMac;
    u_char *pkt;
    pcap_t *dump_p;
};

#endif // FALSIFY_H
