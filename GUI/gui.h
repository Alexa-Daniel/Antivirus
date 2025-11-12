#pragma once

#include <QtWidgets/QWidget>
#include "ui_gui.h"
#include <set>
#include <string>

class BloomFilter;
class ScannerWorker;

class GUI : public QWidget
{
    Q_OBJECT

public:
    explicit GUI(QWidget* parent = nullptr);
    ~GUI();

private:
    Ui::GUIClass ui;
    BloomFilter* bf;
    std::set<std::string> extensions;
    QString historyEntry;
    int threatsFound;

    void loadBloomFilter(BloomFilter& filter);

private slots:
    void browseButtonClick();
    void scanButtonClick();

    void addToLog(QString msg);
    void onUpdateStatus(QString message);
    void foundMalware(QString path);
    void finishedScan();
    //void addToHistory(QString historyEntry);
};

