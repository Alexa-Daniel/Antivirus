#include <QObject>
#include <QString>
#include <QElapsedTimer>
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

	string string_path = path.toStdString();
	filesystem::path fs_path(string_path);

	int filesChecked = 0;
	QElapsedTimer timer;
	timer.start();

	try
	{
		for (const filesystem::directory_entry& entry : filesystem::recursive_directory_iterator(fs_path))
		{
			filesChecked++;

			if (timer.elapsed() > 500)
			{
				emit addToLog(QString("Scanned %1 files").arg(filesChecked));
				timer.restart();
			}
			try
			{
				if (entry.is_regular_file())
				{
					string ext = entry.path().extension().string();
					transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

					if (extensions.count(ext))
					{
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
							//cout << "File: " << entry.path() << ": Not malware - from Bloom Filter\n";
							//emit addToLog(QString("[Clean]: Not malware (Bloom Filter check)"));
							continue;
						}
						if (!fileHash.empty())
						{
							emit addToLog(QString("[Checking]: %1").arg(QString::fromStdString(entry.path().generic_string())));
							//cout << "File: " << entry.path() << ": ";
							if (checkHash(bucketName, fileHash))
							{
								//threatsFound++;
								emit foundMalware(QString("[WARNING]: Malware found from SHA256 check"));
								//cout << "Malware found: " << "\n";
							}
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

	emit addToLog(QString("Scanned %1 files.").arg(filesChecked));
	emit addToLog(QString("Finished the scan"));
	emit finishedScan();
}