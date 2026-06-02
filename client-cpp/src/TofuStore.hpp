#pragma once

/**
 * TofuStore.hpp — Trust-On-First-Use identity-key pinning.
 *
 * On the first conversation with a peer we record a SHA-256 fingerprint of
 * their raw X25519 identity key. On every later session setup we re-check the
 * freshly fetched key against that pin: a change means the server handed us a
 * different identity key than before — the classic man-in-the-middle signal —
 * and the caller blocks the message.
 *
 * Pins are persisted as JSON at QStandardPaths::AppDataLocation/tofu_pins.json,
 * loaded lazily on first use and written back atomically. UI-thread only; no
 * locking is performed.
 */

#include <QtCore/QByteArray>
#include <QtCore/QJsonObject>
#include <QtCore/QString>

class TofuStore
{
public:
    enum class PinResult { FirstUse, Match, Mismatch };

    /** Compare username's identity key against the stored pin. On first use the
     *  key is pinned and FirstUse is returned; a matching key returns Match; a
     *  differing key returns Mismatch and leaves the existing pin untouched. */
    PinResult checkAndPin(const QString& username, const QByteArray& ikPubRaw);

    /** The hex fingerprint pinned for username, or an empty string if none. */
    QString pinnedFingerprint(const QString& username) const;

    /** Lowercase hex SHA-256 of the raw X25519 identity-key bytes. */
    static QString computeFingerprint(const QByteArray& ikPubRaw);

private:
    QString storeFilePath() const;
    void load() const;   // lazy; populates m_pins on first access
    void save() const;   // atomic write via QSaveFile

    mutable bool        m_loaded = false;
    mutable QJsonObject m_pins;  // username -> { ik_fingerprint, pinned_at }
};
