#include "wifi_cracking.h"
#include "ui_wifi_cracking.h"

wifi_cracking::wifi_cracking(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::wifi_cracking)
{
    ui->setupUi(this);
}

wifi_cracking::~wifi_cracking()
{
    delete ui;
}

void wifi_cracking::on_StartBtn_clicked()
{

}

void wifi_cracking::on_StopBtn_clicked()
{

}

void wifi_cracking::on_HelpBtn_clicked()
{
    QMessageBox::information(this, "Help", "This is WiFi cracking tool.\nIf you don't have Wireless Interface Card, You must\nequip Wireless Network Card, and you install driver.");
}

void wifi_cracking::on_SelectBtn_clicked()
{

}

void wifi_cracking::on_CancelBtn_clicked()
{

}
