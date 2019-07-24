#ifndef SPOOFURL_H
#define SPOOFURL_H

#include <QDialog>
#include <QtCore>
#include <QtWidgets>
#include "common_func.h"
#include "relay_falsify.h"
#include "relay_spoof.h"

namespace Ui {
class spoofUrl;
}

class spoofUrl : public QDialog
{
	Q_OBJECT

public:
	explicit spoofUrl(QWidget *parent = 0);
	~spoofUrl();

	void spoofGetInfo(QString, QString, QString, QString, QString, QString, u_char*, pcap_t*, pcap_if_t*);

	relay_falsify *relayFalsify;
	relay_spoof *relaySpoof;

private slots:
	void on_GoUrlBtn_clicked();
	void on_StopBtn_clicked();
	void on_CancelBtn_clicked();

public slots:
	void spoof_getUrl(QStringList);
	void spoof_postUrl(QStringList);
	void spoof_getFin(bool);

private:
	Ui::spoofUrl *ui;
	QStringListModel *spoof_md;
	void allStop();
};

#endif // SPOOFURL_H
