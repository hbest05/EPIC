#pragma once

/**
 * MessageItemDelegate.hpp — custom item delegate for the message thread list.
 *
 * Paints per-row selection affordances on top of the default item rendering:
 *   - In selection mode, a left-edge circle (filled with an inner dot when the
 *     row is selected).
 *   - Otherwise, a right-edge "⋮" overflow marker on hovered/selected rows.
 *
 * The active selection-mode flag is observed through a pointer owned by
 * MainWindow, so the delegate repaints correctly as the mode toggles.
 */

#include <QtWidgets/QStyledItemDelegate>

class MessageItemDelegate : public QStyledItemDelegate
{
public:
    MessageItemDelegate(const bool* selectionMode, QObject* parent);

    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;

private:
    const bool* m_selectionMode;
};
