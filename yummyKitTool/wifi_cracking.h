#ifndef WIFI_CRACKING_H
#define WIFI_CRACKING_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include <QThread>

namespace Ui {
class wifi_cracking;
}

class wifi_cracking : public QDialog
{
    Q_OBJECT

public:
    explicit wifi_cracking(QWidget *parent = 0);
    ~wifi_cracking();

private slots:
    void on_StartBtn_clicked();

    void on_StopBtn_clicked();

    void on_HelpBtn_clicked();

    void on_SelectBtn_clicked();

    void on_CancelBtn_clicked();

private:
    Ui::wifi_cracking *ui;
};

#endif // WIFI_CRACKING_H
