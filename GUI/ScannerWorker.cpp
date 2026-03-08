#include <QObject>
#include <QString>
#include <QElapsedTimer>
#include <QTime>
#include <set>
#include <string>
#include <filesystem>
#include "ScannerWorker.h"
#include "..\Antivirus\Antivirus.h"
#include "..\Include\BloomFilter.hpp"

using namespace std;

ScannerWorker::ScannerWorker(QObject* parent) : QObject(parent) {}
ScannerWorker::~ScannerWorker() {}

void ScannerWorker::scan(QString path, set<string>& extensions, BloomFilter& bf)
{
	emit addToLog(QString("Started scanning: %1").arg(path));
	//emit addToHistory(path);

	initializeTrie();

	string string_path = path.toStdString();
	filesystem::path fs_path(string_path);

	filesScanned.store(0);
	malwareFound.store(0);
	timer.start();
	updateTimer.start();

	try
	{
		auto onDetection = [this](const Detection& d)
		{
			QString msg;
			if (d.type == Detection::Type::Signature)
				msg = QString("[Signature - SHA256]: %1").arg(QString::fromStdString(d.path.generic_string()));
			else
				msg = QString("[Heuristic]: %1 (Score: %2)").arg(QString::fromStdString(d.path.generic_string())).arg(d.score);

			malwareFound.fetch_add(1);
			emit foundMalware(msg);
		};

		auto onProgress = [this](uint64_t scanned)
		{
			filesScanned.store(static_cast<int>(scanned));
			emit updateStatus(QString("Scanned %1 files...").arg(scanned));
		};

		passFilesThreaded(string_path, extensions, bf, 0, onDetection, onProgress);
	}
	catch (exception& e)
	{
		emit addToLog(QString("[FATAL]: Scan stopped: %1").arg(e.what()));
		//cerr << "[ERROR]: Didn't receive a valid path\n";
	}

	qint64 timeInMs = timer.elapsed();
	QTime time(0, 0, 0);
	time = time.addMSecs(timeInMs);
	QString formattedTime = time.toString("hh:mm:ss");
	emit updateStatus(QString("Scanned %1 files. Found %2 threats. Time taken: %3")
		.arg(filesScanned.load())
		.arg(malwareFound.load())
		.arg(formattedTime));
	emit addToLog(QString("Finished the scan"));
	emit finishedScan();
}