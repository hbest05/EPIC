/**
 * TofuStore.cpp — see TofuStore.hpp.
 *
 * Fingerprints are computed with QCryptographicHash (QtCore) so the pinning
 * path pulls in no crypto dependency beyond Qt itself.
 */

#include "TofuStore.hpp"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QSaveFile>
#include <QtCore/QStandardPaths>

QString TofuStore::storeFilePath() const
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/tofu_pins.json");
}

QString TofuStore::computeFingerprint(const QByteArray& ikPubRaw)
{
    return QString::fromUtf8(
        QCryptographicHash::hash(ikPubRaw, QCryptographicHash::Sha256).toHex());
}

void TofuStore::load() const
{
    if (m_loaded) return;
    m_loaded = true;

    QFile f(storeFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    m_pins = QJsonDocument::fromJson(f.readAll()).object();
    f.close();
}

void TofuStore::save() const
{
    QSaveFile f(storeFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) return;
    f.write(QJsonDocument(m_pins).toJson(QJsonDocument::Compact));
    f.commit();
}

QString TofuStore::pinnedFingerprint(const QString& username) const
{
    load();
    return m_pins.value(username).toObject()
                 .value(QStringLiteral("ik_fingerprint")).toString();
}

TofuStore::PinResult TofuStore::checkAndPin(const QString& username,
                                            const QByteArray& ikPubRaw)
{
    load();

    const QString fp = computeFingerprint(ikPubRaw);
    const QString existing = m_pins.value(username).toObject()
                                   .value(QStringLiteral("ik_fingerprint")).toString();

    if (existing.isEmpty()) {
        QJsonObject entry;
        entry.insert(QStringLiteral("ik_fingerprint"), fp);
        entry.insert(QStringLiteral("pinned_at"),
                     QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
        m_pins.insert(username, entry);
        save();
        return PinResult::FirstUse;
    }

    return (existing == fp) ? PinResult::Match : PinResult::Mismatch;
}
