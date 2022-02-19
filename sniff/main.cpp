#include "mainwindow.h"

#include <QApplication>
#include <QFont>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    //设置全局字体
    QFont font  = a.font();
    font.setPointSize(12);
    a.setFont(font);

    MainWindow w;
    w.setWindowTitle("嗅探工具");
    w.show();
    return a.exec();
}
