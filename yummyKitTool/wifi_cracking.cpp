#include "wifi_cracking.h"
#include "ui_wifi_cracking.h"
#include <iostream>
#include <fstream>

wifi_cracking::wifi_cracking(QWidget *parent) : QDialog(parent), ui(new Ui::wifi_cracking) {
    ui->setupUi(this);
    std::ifstream fin;
    char buf[10];

    system("lshw -class network | grep Wireless | awk \'{ print $2 }\' > ./wifi_log.txt");
    system("ls -l | grep wifi_log.txt | awk \'{ print $5 }\' > ./wifi_check.txt");

    fin.open("./wifi_check.txt");
    while(fin >> buf) {}
    fin.close();
    if(!strcmp(buf, "0")) {
        ui->StartBtn->setEnabled(false);
        ui->StopBtn->setEnabled(false);
        ui->SelectBtn->setEnabled(false);
        ui->cracking_text->setText("You have not Network Interface Card. Click \'Help\' Button.");
    }
    else {
        // iwlist and iwconfig tool install button(QMessageBox)
        // iwlist -> listview, store at ESSID, BSSID, CHANNEL etc
    }
    system("sudo rm ./wifi_check.txt ./wifi_log.txt");
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
    if(!ui->StartBtn->isEnabled()) QMessageBox::warning(this, "Help", "You don't have Wireless Interface Card!!\nYou must equip Wireless Network Card, and you install driver.");
    else QMessageBox::information(this, "Help", "This is WiFi cracking tool.\n1. You must select WiFi Name.\n2. And you click Start Button.\nWhen you clicked button, cracking will be run.");
}

void wifi_cracking::on_SelectBtn_clicked()
{

}

void wifi_cracking::on_CancelBtn_clicked()
{
    this->close();
}
