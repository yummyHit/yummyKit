#ifndef HOSTNAME_H
#define HOSTNAME_H

#include <QThread>
#include <QtCore>
#include <QtWidgets>
#include "common_func.h"

class hostname : public QThread
{
	Q_OBJECT
public:
	explicit hostname(QObject *parent = 0);
	void run();
	void hostStop(bool);
	void getArgu(u_char*, bool);

	bool host_stop, start_flag, host_err;
signals:
	void hostnameSetHostList(QStringList);

private:
	int idx;
};

#endif // HOSTNAME_H
