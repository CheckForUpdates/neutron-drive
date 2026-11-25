#pragma once

#include <QWidget>
#include <QLabel>
#include <QProgressBar>

class QuotaWidget : public QWidget {
    Q_OBJECT
public:
    explicit QuotaWidget(QWidget *parent = nullptr);

    void updateQuota(quint64 usedBytes, quint64 totalBytes, double percent);

private:
    QLabel *m_lblTitle;
    QLabel *m_lblQuota;
    QProgressBar *m_bar;
};
