#include "dialog.h"
#include "ui_dialog.h"
#include <QFont>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);

}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::setText(QString text)
{
    ui->textEdit->setText(text);
}
