#include "falsify.h"
#include "ui_falsify.h"

falsify::falsify(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::falsify)
{
    ui->setupUi(this);
}

falsify::~falsify()
{
    delete ui;
}

void falsify::on_SpoofBtn_clicked()
{
    if(ui->routerMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Router's Mac Empty!! Retry..");
    else if(ui->myMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "My's Mac Empty!! Retry..");
    else if(ui->targetMacEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Target's Mac Empty!! Retry..");
    else if(ui->srcAddressEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Input Your IP Address.\nsuch as XXX.XXX.XXX.XXX");
    else if(ui->dstAddressEdit->text().isEmpty()) QMessageBox::warning(this, "Warning !!", "Target's IP Address Empty!! Retry..");
    else {
        spoof = new spoofUrl();
        spoof->spoof_getAll(getIP, getRouterIP, getLen, getRouterMac, getMyMac, getVictimMac, pkt, dump_p);
        spoof->exec();
    }
}

void falsify::on_CancelBtn_clicked()
{
    falsify::close();
}

void falsify::pkt_getAll(QString a, QString b, QString c, QString d, QString e, QString f, QString g, u_char *h, pcap_t *i) {
    getIP = a;
    getRouterIP = b;
    getMyIP = c;
    getLen = d;
    getRouterMac = e;
    getMyMac = f;
    getVictimMac = g;
    pkt = h;
    dump_p = i;
    ui->srcAddressEdit->setText(getMyIP);
    ui->dstAddressEdit->setText(getIP);
    ui->routerMacEdit->setText(getRouterMac);
    ui->myMacEdit->setText(getMyMac);
    ui->targetMacEdit->setText(getVictimMac);
}
