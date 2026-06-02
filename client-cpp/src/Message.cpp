/**
 * Message.cpp — Message is a value-type data holder.
 *
 * Most accessors are defined inline in Message.hpp. The JSON serialisation
 * helpers live here so they can be reused by the REST/storage layers.
 */

#include "Message.hpp"

#include <QJsonObject>

QJsonObject Message::toJson() const
{
    QJsonObject obj;
    obj["id"] = m_id;
    obj["sender"] = m_senderUsername;
    obj["recipient"] = m_recipientUsername;
    obj["direction"] = (m_direction == Direction::Sent) ? QStringLiteral("sent")
                                                         : QStringLiteral("received");
    obj["plaintext"] = m_plaintext;
    obj["created_at"] = m_createdAt.toString(Qt::ISODate);
    obj["blockchain_confirmed"] = m_blockchainConfirmed;
    obj["tx_hash"] = m_txHash;
    return obj;
}

Message Message::fromJson(const QJsonObject& obj)
{
    Message msg;
    msg.m_id = obj["id"].toString();
    msg.m_senderUsername = obj["sender"].toString();
    msg.m_recipientUsername = obj["recipient"].toString();
    msg.m_direction = (obj["direction"].toString() == QStringLiteral("sent"))
                          ? Direction::Sent
                          : Direction::Received;
    msg.m_plaintext = obj["plaintext"].toString();
    msg.m_createdAt = QDateTime::fromString(obj["created_at"].toString(), Qt::ISODate);
    msg.m_blockchainConfirmed = obj["blockchain_confirmed"].toBool();
    msg.m_txHash = obj["tx_hash"].toString();
    return msg;
}
