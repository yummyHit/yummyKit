#ifndef BRUTEFORCE_H
#define BRUTEFORCE_H

#include <QDialog>

namespace Ui {
class bruteforce;
}

class bruteforce : public QDialog
{
	Q_OBJECT

public:
	explicit bruteforce(QWidget *parent = 0);
	~bruteforce();

private:
	Ui::bruteforce *ui;
};

#endif // BRUTEFORCE_H
