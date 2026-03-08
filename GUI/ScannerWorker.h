#pragma once

#include <QObject>
#include <QString>
#include <QElapsedTimer>
#include <set>
#include <string>
#include <atomic>
#include "..\Antivirus\Antivirus.h";
#include "..\Include\BloomFilter.hpp"

class ScannerWorker : public QObject
{
	Q_OBJECT;

public:
	explicit ScannerWorker(QObject* parent = nullptr);
	~ScannerWorker();

private:
	std::atomic<int> filesScanned;
	std::atomic<int> malwareFound;
	QElapsedTimer updateTimer, timer;

public slots:
	void scan(QString path, std::set<std::string>& extensions, BloomFilter& bf);

signals:
	//void addToHistory(QString historyEntry);
	void addToLog(QString logMsg);
	void foundMalware(QString path);
	void finishedScan();
	void updateStatus(QString statusMessage);
};