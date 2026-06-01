/**
 * MessageItemDelegate.cpp — implementation of the message-thread item delegate.
 */

#include "MessageItemDelegate.hpp"

#include <QtCore/QModelIndex>
#include <QtCore/QPoint>
#include <QtGui/QColor>
#include <QtGui/QPainter>
#include <QtGui/QPen>
#include <QtWidgets/QStyle>
#include <QtWidgets/QStyleOptionViewItem>

namespace {

constexpr int kCircleZoneWidth = 28; // px on the left for the selection circle hit target
constexpr int kCircleRadius    =  7; // outer circle radius (scales with typical row height)
constexpr int kDotRadius       =  3; // inner dot radius when selected

} // namespace

MessageItemDelegate::MessageItemDelegate(const bool* selectionMode, QObject* parent)
    : QStyledItemDelegate(parent), m_selectionMode(selectionMode)
{
}

void MessageItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
                                const QModelIndex& index) const
{
    QStyledItemDelegate::paint(painter, option, index);

    if (*m_selectionMode) {
        // Circle centred in the left kCircleZoneWidth strip
        const int cy = option.rect.center().y();
        const int cx = option.rect.left() + kCircleZoneWidth / 2;
        const bool sel = option.state & QStyle::State_Selected;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        if (sel) {
            painter->setBrush(QColor(QStringLiteral("#0084ff")));
            painter->setPen(Qt::NoPen);
            painter->drawEllipse(QPoint(cx, cy), kCircleRadius, kCircleRadius);
            painter->setBrush(Qt::white);
            painter->setPen(Qt::NoPen);
            painter->drawEllipse(QPoint(cx, cy), kDotRadius, kDotRadius);
        } else {
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(QColor(QStringLiteral("#bbbbbb")), 1.5));
            painter->drawEllipse(QPoint(cx, cy), kCircleRadius, kCircleRadius);
        }
        painter->restore();
    } else {
        if (option.state & (QStyle::State_Selected | QStyle::State_MouseOver)) {
            painter->save();
            painter->setPen((option.state & QStyle::State_Selected)
                            ? option.palette.highlightedText().color()
                            : option.palette.placeholderText().color());
            painter->drawText(option.rect.adjusted(0, 0, -8, 0),
                              Qt::AlignRight | Qt::AlignVCenter,
                              QStringLiteral("⋮"));
            painter->restore();
        }
    }
}
