#include <QObject>
#include <QString>
#include <QElapsedTimer>
#include <QTime>
#include <set>
#include <string>
#include <filesystem>
#include "ScannerWorker.h"
#include "..\Antivirus\Antivirus.h";
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

	filesScanned = 0;
	malwareFound = 0;
	timer.start();
	updateTimer.start();

	try
	{
		filesystem::directory_options ops = filesystem::directory_options::skip_permission_denied;
		for (const filesystem::directory_entry& entry : filesystem::recursive_directory_iterator(fs_path, ops))
		{
			filesScanned++;

			if (updateTimer.elapsed() > 500)
			{
				emit updateStatus(QString("Scanned %1 files...").arg(filesScanned));
				//emit addToLog(QString("Scanned %1 files").arg(filesScanned));
				updateTimer.restart();
			}
			try
			{
				if (entry.is_regular_file())
				{
					string ext = entry.path().extension().string();
					transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

					if (extensions.count(ext))
					{
						if (isFileTrusted(entry.path()))
						{
							continue;
						}
						string bucketName;
						vector<uint8_t> fileHash = createHash(entry.path(), bucketName);

						//emit addToLog(QString("[Checking]: %1").arg(QString::fromStdString(entry.path().generic_string())));

						if (fileHash.empty())
						{
							emit addToLog(QString("[Skipped]: Failed to create the hash for file: %1").arg(QString::fromStdString(entry.path().generic_string())));
							continue;
						}

						if (!bf.check(fileHash.data(), fileHash.size()))
						{
							int score = getHeuristicScore(entry.path());
							//emit addToLog(QString("Score: %1 for file %2").arg(score).arg(QString::fromStdString(entry.path().generic_string())));
							if (score >= 100)
							{
								malwareFound++;
								emit foundMalware(QString("[Heuristic]: %1 (Score: %2)").arg(QString::fromStdString(entry.path().generic_string())).arg(score));
							}
							//cout << "File: " << entry.path() << ": Not malware - from Bloom Filter\n";
							//emit addToLog(QString("[Clean]: Not malware (Bloom Filter check)"));
							continue;
						}
						if (checkHash(bucketName, fileHash))
						{
							malwareFound++;
							emit foundMalware(QString("[Signature - SHA256]: %1").arg(QString::fromStdString(entry.path().generic_string())));
							//cout << "Malware found: " << "\n";
						}
						//ifstream bucket(bucketName, ios::binary | ios::ate);

						//cout << entry.path().string() << '\n';
					}
				}
			}
			catch (exception& fileErr)
			{
				emit addToLog(QString("[Skipped]: Error: %1").arg(fileErr.what()));
			}
		}
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
		.arg(filesScanned)
		.arg(malwareFound)
		.arg(formattedTime));
	emit addToLog(QString("Finished the scan"));
	emit finishedScan();
}