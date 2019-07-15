#define HAVE_REMOTE

#include "scanning.h"
#include "ui_scanning.h"

QString scanIP;
QStringList scanIPList, scanLen, scanMacList;
u_char *scanPacket;
pcap_t *scanPcap;
pcap_if_t *devs;

bool scan_stop;

scanning::scanning(QWidget *parent) : QDialog(parent), ui(new Ui::scanning) {
    ui->setupUi(this);
    get_gateway route;
    char buf[20] = {0,};

//    popen_used("route -n | grep -i ug | awk '{ print $2 }'", buf, sizeof(buf));
    popen_used("id | awk '{print $1}' | cut -d '=' -f2- | awk -F\\( '{print $1}'", buf, sizeof(buf));
    if(strncmp(buf, "0", 1)) {
        QMessageBox::critical(this, "UID Error!!", "Your UID is not 0.\nYou must open yummyKit program with UID 0 account!!");
        exit(1);
    }

    route.get_route_ip(buf, sizeof(buf));
    if(strlen(buf) <= 1) {
        ui->StartBtn->setEnabled(false);
        ui->scanning_text->setText("You are not connect to Network. Click \'Help\' Button.");
    }
    else if(!this->start_cnt){
        scanIP.append(buf);
        ui->scanning_text->setText("Your router ip address is " + scanIP);

        simod = new QStandardItemModel(0, 2, this);
        simod->setHorizontalHeaderItem(0, new QStandardItem(QString("Index")));
        simod->setHorizontalHeaderItem(1, new QStandardItem(QString("Network Interfaces")));
        ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
        ui->tableView->setModel(simod);
    }

    ui->scanning_text->setEnabled(false);
    ui->SelectBtn->setEnabled(false);
    ui->StopBtn->setEnabled(false);

    if(ui->StartBtn->isEnabled() && !this->start_cnt) findDevs();
}

scanning::~scanning() {
    delete ui;
}

void scanning::on_StartBtn_clicked() {
    scan_stop = false;
    int if_num = 1;
    QChar check = *(scanIP.unicode());

    if(check.isNull() || !check.isDigit()) QMessageBox::warning(this, "Warning!!", "If you don't know how to use it,\nyou can click 'Help' button.");
    else if(!sys_ip.isEmpty() && scanThread->isRunning()) QMessageBox::warning(this, "Warning!!", "Scanning is already running!!\nIf you want new scan, first click stop button.\nAnd click start button.");
    else {
        if(!ui->tableView->currentIndex().isValid() && !this->start_cnt) {
            QMessageBox::warning(this, "Warning!!", "You must select 1 Network Interface at least.\nIf you don't want to select it, click \"Start\" button again.");
//            this->start_cnt = true;
            return;
        }
        else if(!this->start_cnt) if_num = ui->tableView->currentIndex().row() + 1;

        sys_ip = scanIP;
        if(sys.isEmpty()) {
            sys.append("arp -d ");
            sys.append(sys_ip);
            sys.append(" >/dev/null 2>&1");
            scanThread = new scanning_thread();
        }
        else {
            this->start_cnt = true;
            scanThread = new scanning_thread();
        }

        scanThread->scanThreadSetSys(sys, sys_ip, if_num, devs);
        if(!this->start_cnt) {
            simod->clear();
            simod->setHorizontalHeaderItem(0, new QStandardItem(QString("IP Address")));
            simod->setHorizontalHeaderItem(1, new QStandardItem(QString("Host Name")));
        }

        scanThread->start();
        ui->StopBtn->setEnabled(true);
        ui->StartBtn->setEnabled(false);

        connect(scanThread, SIGNAL(scanThreadSetIPList(QString)), this, SLOT(scanGetIPList(QString)));
        connect(scanThread, SIGNAL(scanThreadSetLength(QStringList)), this, SLOT(scanGetLength(QStringList)));
        connect(scanThread, SIGNAL(scanThreadSetMacList(QString)), this, SLOT(scanGetMacList(QString)));
        connect(scanThread, SIGNAL(scanThreadPacket(u_char*)), this, SLOT(scanGetPacket(u_char*)));
        connect(scanThread, SIGNAL(scanThreadPcap(pcap_t*)), this, SLOT(scanGetPcap(pcap_t*)));
        connect(scanThread->host_name, SIGNAL(hostnameSetHostList(QStringList)), this, SLOT(scanGetHostList(QStringList)));
    }
}

void scanning::on_StopBtn_clicked() {
    stopThread();
}

void scanning::on_HelpBtn_clicked() {
    if(!ui->StartBtn->isEnabled()) QMessageBox::warning(this, "Failed!!", "Your network isn't connected by network!!\nYou must connect a network!!");
    else if(sys.isEmpty()) QMessageBox::information(this, "Help", "You must select your network interface and click start button.\nIf you don't know what it is, click \"Start\" Button.");
    else QMessageBox::information(this, "Help", "Select ip or host name in table.\nIf you don't know what you want to address, check target ip on terminal.");
}

void scanning::on_SelectBtn_clicked() {
    if(!ui->tableView->currentIndex().isValid() || (!scan_stop && sys_ip.isEmpty())) QMessageBox::information(this, "Warning", "You must select 1 IP address at least.\nIf you don't know how to use it, please click help button.");
    else if(!scan_stop) QMessageBox::information(this, "Warning", "Scanning is running!!\nIf you want select button, first click stop button.\nOr wait a second. Then you can click select button.");
    else {
        stopThread();
        emit scanSetMacList(scanMacList);
        emit scanSetPacket(scanPacket);
        emit scanSetPcap(scanPcap);
        emit scanSetDevName(devs);
        emit scanSetIPList(scanIPList, ui->tableView->currentIndex().row());
        emit scanSetLength(scanLen);
        this->close();
    }
}

void scanning::on_CancelBtn_clicked() {
    stopThread();
    emit scanSetStop(true);
    this->close();
}

void scanning::scanGetIPList(QString pack_list) {
    scanIPList << pack_list;
    if(this->start_cnt && !scanIPList.isEmpty()) {
        for(int i = md_ip->rowCount(); i < scanIPList.length(); i++) {
            md_ip = new QStandardItem(scanIPList.at(i));
            simod->setItem(i, 0, md_ip);
        }
    }
    else {
        for(int i = 0; i < scanIPList.length(); i++) {
            md_ip = new QStandardItem(scanIPList.at(i));
            simod->setItem(i, 0, md_ip);
        }
    }
}

void scanning::scanGetHostList(QStringList host_list) {
    if(this->start_cnt) {
        for(int i = md_host->rowCount(); i < host_list.length(); i++) {
            md_host = new QStandardItem(host_list.at(i));
            simod->setItem(i, 1, md_host);
        }
    }
    else {
        for(int i = 0; i < host_list.length(); i++) {
            md_host = new QStandardItem(host_list.at(i));
            simod->setItem(i, 1, md_host);
        }
    }
}

void scanning::scanGetLength(QStringList len_list) {
    if(len_list.at(0) == "Host_Error") {
        QMessageBox::critical(this, "Failed!!", "nbtscan package install Error.\nPlease contact the developer. Thank you.");
        scan_stop = true;
    }
    else if(len_list.at(0) == "root_squash") {
        QMessageBox::critical(this, "Failed!!", "You must open yummyKit program with root.\nPlease re-run yummyKit with root account!!");
        scan_stop = true;
    }
    else scanLen = len_list;
}

void scanning::scanGetMacList(QString mac_list) {
    scanMacList << mac_list;
}

void scanning::scanGetPacket(u_char *packet) {
    scanPacket = packet;
}

void scanning::scanGetPcap(pcap_t *p) {
    scanPcap = p;
    scan_stop = true;
    this->start_cnt = true;
    QMessageBox::information(this, "Success!!", "IP Scan is finish successfully!!");
    ui->SelectBtn->setEnabled(true);
    ui->StartBtn->setEnabled(true);
}

void scanning::stopThread() {
    if(!scan_stop) {
        scan_stop = true;
        scanThread->scanThreadSetStop(scan_stop);
        system(sys.toStdString().c_str());
		usleep(50000);
		system("ping 8.8.8.8 -c 1 >/dev/null 2>&1");
		usleep(50000);
        system("arp -a >/dev/null 2>&1");
    }
    ui->StopBtn->setEnabled(false);
}

void scanning::findDevs() {
    pcap_if_t *tmp;
    char errbuf[256];
    int i = 0;
    if(pcap_findalldevs(&devs, errbuf) == -1) QMessageBox::warning(this, "Warning!!", "Check your Network Interface Card!!");
    else for(tmp = devs; tmp; tmp = tmp->next) {
        md_host = new QStandardItem(QString::fromStdString(tmp->name));
        simod->setItem(i, 0, new QStandardItem(QString::number(i + 1)));
        simod->setItem(i++, 1, md_host);
    }
}
