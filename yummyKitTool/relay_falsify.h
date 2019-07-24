#ifndef RELAY_FALSIFY_H
#define RELAY_FALSIFY_H

#include <QThread>
#include <QtCore>
#include "common_func.h"

class relay_falsify : public QThread
{
	Q_OBJECT
public:
	explicit relay_falsify(QObject *parent = 0);
	void run();
	bool falsifyStop;

	void relayGetInfo(QString, QString, QString, QString, QString, QString, u_char*, pcap_t*);
};

#endif // RELAY_FALSIFY_H
