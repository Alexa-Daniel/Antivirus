#include "stdafx.h"
#include "gui.h"
#include "ScannerWorker.h"
#include "..\Include\BloomFilter.hpp"
#include "..\Antivirus\Antivirus.h"
#include <QThread>
#include <QFileDialog>
#include <QMessageBox>

GUI::GUI(QWidget* parent)
	: QWidget(parent)
{
	ui.setupUi(this);

	setWindowTitle("Antivirus");
	setWindowIcon(QIcon(":/bug.png"));

	extensions = { ".exe", ".dll", ".js", ".msi", ".bat", ".cmd", ".vbs", ".scr", ".vbs", ".ps1", ".docm", ".xlsm", ".pptm", ".txt" };
	bf = new BloomFilter();
	loadBloomFilter(*bf);

	initializeTrie();

	threatsFound = 0;

	connect(ui.browseButton, &QPushButton::clicked, this, &GUI::browseButtonClick);
	connect(ui.scanButton, &QPushButton::clicked, this, &GUI::scanButtonClick);
}

GUI::~GUI()
{
	delete bf;
}

void GUI::loadBloomFilter(BloomFilter& bf)
{
	std::ifstream file("..\\hash_db\\bloom_filter.bin", std::ios::binary);
	if (file.is_open())
	{
		bf.load(file);
		file.close();
		addToLog(QString("[Info]: Loaded the Bloom Filter succesfully"));
	}
	else
	{
		//cerr << "[ERROR]: Could not load bloom_filter.bin!\n";
		addToLog(QString("[Error]: Couldn't load the Bloom Filter. Continuing with the SHA256 verification only"));
	}
}

void GUI::browseButtonClick()
{
	QString path = QFileDialog::getExistingDirectory(this, "Select Directory to Scan");
	if (!path.isEmpty())
	{
		ui.linePath->setText(path);
	}
}

void GUI::scanButtonClick()
{
	QString path = ui.linePath->text();
	if (path.isEmpty())
	{
		QMessageBox::warning(this, "Error", "Please select a path to scan.");
		return;
	}

	historyEntry = path;
	threatsFound = 0;

	QThread* thread = new QThread;
	ScannerWorker* sw = new ScannerWorker();
	sw->moveToThread(thread);

	//connect(sw, &ScannerWorker::addToHistory, this, &GUI::addToHistory);
	connect(sw, &ScannerWorker::addToLog, this, &GUI::addToLog);
	connect(sw, &ScannerWorker::foundMalware, this, &GUI::foundMalware);
	connect(sw, &ScannerWorker::finishedScan, this, &GUI::finishedScan);

	connect(thread, &QThread::started, sw, [=]()
		{
			sw->scan(path, extensions, *bf);
		});

	connect(sw, &ScannerWorker::finishedScan, thread, &QThread::quit);

	connect(thread, &QThread::finished, sw, &ScannerWorker::deleteLater);
	connect(thread, &QThread::finished, thread, &QThread::deleteLater);

	ui.browseButton->setEnabled(false);
	ui.scanButton->setEnabled(false);

	thread->start();
}

//void GUI::addToHistory(QString historyEntry)
//{
//	ui.listHistory->addItem(historyEntry);
//	ui.listHistory->scrollToBottom();
//}

void GUI::addToLog(QString message)
{
	ui.logWidget->addItem(message);
	ui.logWidget->scrollToBottom();
}

void GUI::foundMalware(QString path)
{
	threatsFound++;
	QListWidgetItem* item = new QListWidgetItem(QString("%1").arg(path));
	item->setForeground(Qt::red);
	ui.logWidget->addItem(item);
	ui.logWidget->scrollToBottom();
}

void GUI::finishedScan()
{
	historyEntry.append(QString(" - found %1 threats").arg(threatsFound));
	QListWidgetItem* item = new QListWidgetItem(historyEntry);
	if (threatsFound)
	{
		item->setForeground(Qt::red);
	}
	else
	{
		item->setForeground(Qt::green);
	}

	ui.listHistory->addItem(item);
	ui.scanButton->setEnabled(true);
	ui.browseButton->setEnabled(true);
}


