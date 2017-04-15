#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtCore>
#include <QtWidgets>
#include <QThread>
#include "falsify.h"
#include "scanning.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void run();

public slots:
    void main_getList(QStringList, int);
    void main_getLength(QStringList);
    void main_getMacPacket(QStringList);
    void main_getPacket_info(u_char*);
    void main_getDump_pcap(pcap_t*);

private slots:
    void on_actionIP_Scan_triggered();

    void on_actionFalsify_Packet_triggered();

private:
    Ui::MainWindow *ui;
    QProgressBar *pb;
    QLabel *lbl;
    scanning *rt;
    QStringListModel *main_model;
};

#endif // MAINWINDOW_H
