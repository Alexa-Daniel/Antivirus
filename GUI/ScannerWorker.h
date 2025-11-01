#pragma once

#include <QObject>
#include <QString>
#include <set>
#include <string>
#include "..\Antivirus\Antivirus.h";
#include "..\Include\BloomFilter.hpp"

class ScannerWorker : public QObject
{
	Q_OBJECT;

public:
	explicit ScannerWorker(QObject* parent = nullptr);
	~ScannerWorker();

public slots:
	void scan(QString path, std::set<std::string>& extensions, BloomFilter& bf);

signals:
	//void addToHistory(QString historyEntry);
	void addToLog(QString logMsg);
	void foundMalware(QString path);
	void finishedScan();
};