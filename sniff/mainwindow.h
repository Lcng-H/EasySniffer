#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QDebug>
#include <QDialog>
#include "sniffer.h"
#include "dataprocess.h"
#include "dialog.h"
#include "menuitemtcp.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QThread m_thread;
    QThread data_thread;
    sniffer s;
    DataProcess dp;
    Dialog *dlg = new Dialog(this);
    QDateTime mytime;
    QString time1, time2;
    int second1, second2, procTime;
    MenuItemTCP *menuItem = new MenuItemTCP(this);

signals:
    void startSniff();

private slots:
    void on_Btn_start_clicked();
    void on_Btn_end_clicked();
    void on_tableView_packet_doubleClicked(const QModelIndex &index);
    void on_pushButton_tally_clicked();
    void on_pushButton_choice_clicked();
    void on_menuItem_TCP_triggered();
};
#endif // MAINWINDOW_H
