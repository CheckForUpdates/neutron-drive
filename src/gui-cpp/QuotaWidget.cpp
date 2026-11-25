#include "QuotaWidget.hpp"
#include <QVBoxLayout>
#include <QFont>

QuotaWidget::QuotaWidget(QWidget *parent)
    : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 8, 16, 8);
    layout->setSpacing(4);

    m_lblTitle = new QLabel("Neutron Drive Storage", this);
    QFont font = m_lblTitle->font();
    font.setBold(true);
    m_lblTitle->setFont(font);
    layout->addWidget(m_lblTitle);

    m_lblQuota = new QLabel("Checking storage...", this);
    m_lblQuota->setStyleSheet("color: #666; font-size: 11px;");
    layout->addWidget(m_lblQuota);

    m_bar = new QProgressBar(this);
    m_bar->setFixedHeight(6);
    m_bar->setTextVisible(false);
    m_bar->setRange(0, 100);
    m_bar->setValue(0);
    m_bar->setStyleSheet(
        "QProgressBar {"
        "    background-color: #e0e0e0;"
        "    border: none;"
        "    border-radius: 3px;"
        "}"
        "QProgressBar::chunk {"
        "    background-color: #0e7490;"
        "    border-radius: 3px;"
        "}"
    );
    layout->addWidget(m_bar);
}

void QuotaWidget::updateQuota(quint64 usedBytes, quint64 totalBytes, double percent) {
    if (totalBytes == 0) {
        if (usedBytes == 0) {
            m_lblQuota->setText("0 B used");
        } else if (usedBytes < 1024) {
            m_lblQuota->setText(QString("%1 B used").arg(usedBytes));
        } else if (usedBytes < 1024ULL * 1024ULL) {
            double usedKb = static_cast<double>(usedBytes) / 1024.0;
            m_lblQuota->setText(QString("%1 KB used").arg(usedKb, 0, 'f', 2));
        } else {
            double usedMb = static_cast<double>(usedBytes) / (1024.0 * 1024.0);
            if (usedMb >= 1024.0) {
                double usedGb = usedMb / 1024.0;
                m_lblQuota->setText(QString("%1 GB used").arg(usedGb, 0, 'f', 2));
            } else {
                m_lblQuota->setText(QString("%1 MB used").arg(usedMb, 0, 'f', 2));
            }
        }
        m_bar->setVisible(false);
        return;
    }

    m_bar->setVisible(true);

    double usedGb = static_cast<double>(usedBytes) / (1024.0 * 1024.0 * 1024.0);
    double totalGb = static_cast<double>(totalBytes) / (1024.0 * 1024.0 * 1024.0);

    m_lblQuota->setText(QString("%1 GB of %2 GB used")
        .arg(usedGb, 0, 'f', 2)
        .arg(totalGb, 0, 'f', 2));

    int val = static_cast<int>(qBound(0.0, percent, 100.0));
    m_bar->setValue(val);
}
