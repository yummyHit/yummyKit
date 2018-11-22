#include "bruteforce.h"
#include "ui_bruteforce.h"

bruteforce::bruteforce(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::bruteforce)
{
    ui->setupUi(this);
}

bruteforce::~bruteforce()
{
    delete ui;
}
