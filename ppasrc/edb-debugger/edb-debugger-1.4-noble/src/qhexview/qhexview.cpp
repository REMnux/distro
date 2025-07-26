/*
Copyright (C) 2006 - 2013 Evan Teran
                          eteran@alum.rit.edu

Copyright (C) 2010        Hugues Bruant
                          hugues.bruant@gmail.com

This file can be used under one of two licenses.

1. The GNU Public License, version 2.0, in COPYING-gpl2
2. A BSD-Style License, in COPYING-bsd2.

The license chosen is at the discretion of the user of this software.
*/

#include "qhexview.h"

#include <QApplication>
#include <QClipboard>
#include <QDebug>
#include <QFontDialog>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QScrollBar>
#include <QStringBuilder>
#include <QTextStream>
#include <QtEndian>
#include <QtGlobal>

#include <cctype>
#include <climits>
#include <cmath>
#include <memory>

namespace {

/**
 * determines if a character has a printable ascii symbol
 *
 * @brief is_printable
 * @param ch
 * @return
 */
constexpr bool is_printable(uint8_t ch) {

	// if it's standard ascii use isprint/isspace, otherwise go with our observations
	if (ch < 0x80) {
		return std::isprint(ch) || std::isspace(ch);
	} else {
		return (ch & 0xff) >= 0xa0;
	}
}

/**
 * convenience function used to add a checkable menu item to the context menu
 *
 * @brief add_toggle_action_to_menu
 * @param menu
 * @param caption
 * @param checked
 * @param func
 * @return
 */
template <class Func>
QAction *add_toggle_action_to_menu(QMenu *menu, const QString &caption, bool checked, Func func) {
	auto action = new QAction(caption, menu);
	action->setCheckable(true);
	action->setChecked(checked);
	menu->addAction(action);
	QObject::connect(action, &QAction::toggled, func);
	return action;
}

}

/**
 * @brief QHexView::QHexView
 * @param parent
 */
QHexView::QHexView(QWidget *parent)
	: QAbstractScrollArea(parent) {

#if QT_POINTER_SIZE == 4
	addressSize_ = Address32;
#else
	addressSize_ = Address64;
#endif

	// default to a simple monospace font
	setFont(QFont("Monospace", 8));
	setShowAddressSeparator(true);
}

/**
 * @brief QHexView::setShowAddressSeparator
 * @param value
 */
void QHexView::setShowAddressSeparator(bool value) {
	showAddressSeparator_ = value;
	updateScrollbars();
}

/**
 * @brief QHexView::formatAddress
 * @param address
 * @return
 */
QString QHexView::formatAddress(address_t address) {

	static char buffer[32];

	switch (addressSize_) {
	case Address32: {
		const uint16_t hi = (address >> 16) & 0xffff;
		const uint16_t lo = (address & 0xffff);

		if (showAddressSeparator_) {
			qsnprintf(buffer, sizeof(buffer), "%04x:%04x", hi, lo);
		} else {
			qsnprintf(buffer, sizeof(buffer), "%04x%04x", hi, lo);
		}
	}
		return QString::fromLocal8Bit(buffer);
	case Address64: {
		const uint32_t hi = (address >> 32) & 0xffffffff;
		const uint32_t lo = (address & 0xffffffff);

		if (hideLeadingAddressZeros_) {
			if (showAddressSeparator_) {
				qsnprintf(buffer, sizeof(buffer), "%04x:%08x", (hi & 0xffff), lo);
			} else {
				qsnprintf(buffer, sizeof(buffer), "%04x%08x", (hi & 0xffff), lo);
			}
		} else {
			if (showAddressSeparator_) {
				qsnprintf(buffer, sizeof(buffer), "%08x:%08x", hi, lo);
			} else {
				qsnprintf(buffer, sizeof(buffer), "%08x%08x", hi, lo);
			}
		}
	}
		return QString::fromLocal8Bit(buffer);
	}

	return QString();
}

/**
 * @brief QHexView::repaint
 */
void QHexView::repaint() {
	viewport()->repaint();
}

/**
 * @brief QHexView::dataSize
 * @return how much data we are viewing
 */
int64_t QHexView::dataSize() const {
	return data_ ? data_->size() : 0;
}

/**
 *
 * @brief QHexView::setHideLeadingAddressZeros
 * @param value
 */
void QHexView::setHideLeadingAddressZeros(bool value) {
	hideLeadingAddressZeros_ = value;
}

/**
 *
 * @brief QHexView::hideLeadingAddressZeros
 */
bool QHexView::hideLeadingAddressZeros() const {
	return hideLeadingAddressZeros_;
}

/**
 * overloaded version of setFont, calculates font metrics for later
 *
 * @brief QHexView::setFont
 * @param f
 */
void QHexView::setFont(const QFont &f) {

	QFont font(f);
	font.setStyleStrategy(QFont::ForceIntegerMetrics);

	// recalculate all of our metrics/offsets
	const QFontMetrics fm(font);
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
	fontWidth_ = fm.horizontalAdvance('X');
#else
	fontWidth_   = fm.width('X');
#endif

	fontHeight_ = fm.height();

	updateScrollbars();

	// TODO(eteran): assert that we are using a fixed font & find out if we care?
	QAbstractScrollArea::setFont(font);
}

/**
 * creates the 'standard' context menu for the widget
 *
 * @brief QHexView::createStandardContextMenu
 * @return
 */
QMenu *QHexView::createStandardContextMenu() {

	auto menu = new QMenu(this);

	menu->addAction(tr("Set &Font"), this, SLOT(mnuSetFont()));
	menu->addSeparator();

	add_toggle_action_to_menu(menu, tr("Show A&ddress"), showAddress_, [this](bool value) {
		setShowAddress(value);
	});

	add_toggle_action_to_menu(menu, tr("Show &Hex"), showHex_, [this](bool value) {
		setShowHexDump(value);
	});

	add_toggle_action_to_menu(menu, tr("Show &Ascii"), showAscii_, [this](bool value) {
		setShowAsciiDump(value);
	});

	if (commentServer_) {
		add_toggle_action_to_menu(menu, tr("Show &Comments"), showComments_, [this](bool value) {
			setShowComments(value);
		});
	}

	if (userCanSetWordWidth_ || userCanSetRowWidth_) {
		menu->addSeparator();
	}

	if (userCanSetWordWidth_) {
		auto wordMenu = new QMenu(tr("Set Word Width"), menu);
		add_toggle_action_to_menu(wordMenu, tr("1 Byte"), wordWidth_ == 1, [this]() {
			setWordWidth(1);
		});

		add_toggle_action_to_menu(wordMenu, tr("2 Bytes"), wordWidth_ == 2, [this]() {
			setWordWidth(2);
		});

		add_toggle_action_to_menu(wordMenu, tr("4 Bytes"), wordWidth_ == 4, [this]() {
			setWordWidth(4);
		});

		add_toggle_action_to_menu(wordMenu, tr("8 Bytes"), wordWidth_ == 8, [this]() {
			setWordWidth(8);
		});

		menu->addMenu(wordMenu);
	}

	if (userCanSetRowWidth_) {
		auto rowMenu = new QMenu(tr("Set Row Width"), menu);
		add_toggle_action_to_menu(rowMenu, tr("1 Word"), rowWidth_ == 1, [this]() {
			setRowWidth(1);
		});

		add_toggle_action_to_menu(rowMenu, tr("2 Words"), rowWidth_ == 2, [this]() {
			setRowWidth(2);
		});

		add_toggle_action_to_menu(rowMenu, tr("4 Words"), rowWidth_ == 4, [this]() {
			setRowWidth(4);
		});

		add_toggle_action_to_menu(rowMenu, tr("8 Words"), rowWidth_ == 8, [this]() {
			setRowWidth(8);
		});

		add_toggle_action_to_menu(rowMenu, tr("16 Words"), rowWidth_ == 16, [this]() {
			setRowWidth(16);
		});

		menu->addMenu(rowMenu);
	}

	menu->addSeparator();
	menu->addAction(tr("&Copy Selection To Clipboard"), this, SLOT(mnuCopy()));
	menu->addAction(tr("&Copy Address To Clipboard"), this, SLOT(mnuAddrCopy()));
	return menu;
}

/**
 * default context menu event, simply shows standard menu
 *
 * @brief QHexView::contextMenuEvent
 * @param event
 */
void QHexView::contextMenuEvent(QContextMenuEvent *event) {
	QMenu *const menu = createStandardContextMenu();
	menu->exec(event->globalPos());
	delete menu;
}

/**
 * @brief QHexView::normalizedOffset
 * @return
 */
int64_t QHexView::normalizedOffset() const {

	int64_t offset = static_cast<int64_t>(verticalScrollBar()->value()) * bytesPerRow();

	if (origin_ != 0) {
		if (offset > 0) {
			offset += origin_;
			offset -= bytesPerRow();
		}
	}

	return offset;
}

/**
 * @brief QHexView::mnuCopy
 */
void QHexView::mnuCopy() {
	if (hasSelectedText()) {

		QString s;
		QTextStream ss(&s);

		// current actual offset (in bytes)
		const int chars_per_row = bytesPerRow();
		int64_t offset          = normalizedOffset();

		const int64_t end       = std::max(selectionStart_, selectionEnd_);
		const int64_t start     = std::min(selectionStart_, selectionEnd_);
		const int64_t data_size = dataSize();

		// offset now refers to the first visible byte
		while (offset < end) {

			if ((offset + chars_per_row) > start) {

				data_->seek(offset);
				const QByteArray row_data = data_->read(chars_per_row);

				if (!row_data.isEmpty()) {
					if (showAddress_) {
						const address_t address_rva = addressOffset_ + offset;
						const QString addressBuffer = formatAddress(address_rva);
						ss << addressBuffer << '|';
					}

					if (showHex_) {
						drawHexDumpToBuffer(ss, offset, data_size, row_data);
						ss << "|";
					}

					if (showAscii_) {
						drawAsciiDumpToBuffer(ss, offset, data_size, row_data);
						ss << "|";
					}

					if (showComments_ && commentServer_) {
						drawCommentsToBuffer(ss, offset, data_size);
					}
				}

				ss << "\n";
			}
			offset += chars_per_row;
		}

		QApplication::clipboard()->setText(s);

		// TODO(eteran): do we want to trample the X11-selection too?
		QApplication::clipboard()->setText(s, QClipboard::Selection);
	}
}

/**
 * Copy the starting address of the selected bytes
 *
 * @brief QHexView::mnuAddrCopy
 */
void QHexView::mnuAddrCopy() {
	if (hasSelectedText()) {

		auto s = QString("0x%1").arg(selectedBytesAddress(), 0, 16);
		QApplication::clipboard()->setText(s);

		// TODO(eteran): do we want to trample the X11-selection too?
		QApplication::clipboard()->setText(s, QClipboard::Selection);
	}
}

/**
 * slot used to set the font of the widget based on dialog selector
 *
 * @brief QHexView::mnuSetFont
 */
void QHexView::mnuSetFont() {
	setFont(QFontDialog::getFont(nullptr, font(), this));
}

/**
 * clears all data from the view
 *
 * @brief QHexView::clear
 */
void QHexView::clear() {
	data_ = nullptr;
	viewport()->update();
}

/**
 * @brief QHexView::hasSelectedText
 * @return true if any text is selected
 */
bool QHexView::hasSelectedText() const {
	return !(selectionStart_ == -1 || selectionEnd_ == -1);
}

/**
 * @brief QHexView::isInViewableArea
 * @param index
 * @return true if the word at the given index is in the viewable area
 */
bool QHexView::isInViewableArea(int64_t index) const {

	const int64_t firstViewableWord = static_cast<int64_t>(verticalScrollBar()->value()) * rowWidth_;
	const int64_t viewableLines     = viewport()->height() / fontHeight_;
	const int64_t viewableWords     = viewableLines * rowWidth_;
	const int64_t lastViewableWord  = firstViewableWord + viewableWords;

	return index >= firstViewableWord && index < lastViewableWord;
}

/**
 * @brief QHexView::keyPressEvent
 * @param event
 */
void QHexView::keyPressEvent(QKeyEvent *event) {

	if (event == QKeySequence::SelectAll) {
		selectAll();
		viewport()->update();
	} else if (event == QKeySequence::MoveToStartOfDocument) {
		scrollTo(0);
	} else if (event == QKeySequence::MoveToEndOfDocument) {
		scrollTo(dataSize() - bytesPerRow());
	} else if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Down) {
		int64_t offset = normalizedOffset();
		if (offset + 1 < dataSize()) {
			scrollTo(offset + 1);
		}
	} else if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Up) {
		int64_t offset = normalizedOffset();
		if (offset > 0) {
			scrollTo(offset - 1);
		}
	} else if (event->modifiers() & Qt::ShiftModifier && hasSelectedText()) {
		// Attempting to match the highlighting behavior of common text
		// editors where highlighting to the left or up will keep the
		// first character (byte in our case) highlighted while also
		// extending back or up.
		auto dir = event->key();
		switch (dir) {
		case Qt::Key_Right:
			if (selectionStart_ == selectionEnd_) {
				selectionStart_ -= wordWidth_;
			}
			if (selectionEnd_ / wordWidth_ < dataSize()) {
				selectionEnd_ += wordWidth_;
			}
			break;
		case Qt::Key_Left:
			if ((selectionEnd_ - wordWidth_) == selectionStart_) {
				selectionStart_ += wordWidth_;
				selectionEnd_ -= wordWidth_;
			}
			if (selectionEnd_ / wordWidth_ > 0) {
				selectionEnd_ -= wordWidth_;
			}
			break;
		case Qt::Key_Down:
			selectionEnd_ += rowWidth_;
			selectionEnd_ = std::min(selectionEnd_, dataSize() * wordWidth_);
			break;
		case Qt::Key_Up:
			if ((selectionEnd_ - wordWidth_) == selectionStart_) {
				selectionStart_ += wordWidth_;
			}
			selectionEnd_ -= rowWidth_;
			if (selectionEnd_ <= 0) {
				selectionEnd_ = 0;
			}
			break;
		default:
			break;
		}
		viewport()->update();
	} else {
		QAbstractScrollArea::keyPressEvent(event);
	}
}

/**
 * @brief QHexView::line3
 * @return the x coordinate of the 3rd line
 */
int QHexView::line3() const {
	if (showAscii_) {
		const int elements = bytesPerRow();
		return asciiDumpLeft() + (elements * fontWidth_) + (fontWidth_ / 2);
	} else {
		return line2();
	}
}

/**
 * @brief QHexView::line2
 * @return the x coordinate of the 2nd line
 */
int QHexView::line2() const {
	if (showHex_) {
		const int elements = rowWidth_ * (charsPerWord() + 1) - 1;
		return hexDumpLeft() + (elements * fontWidth_) + (fontWidth_ / 2);
	} else {
		return line1();
	}
}

/**
 * @brief QHexView::line1
 * @return the x coordinate of the 1st line
 */
int QHexView::line1() const {
	if (showAddress_) {
		const int elements = addressLength();
		return (elements * fontWidth_) + (fontWidth_ / 2);
	} else {
		return 0;
	}
}

/**
 * @brief QHexView::hexDumpLeft
 * @return the x coordinate of the hex-dump field left edge
 */
int QHexView::hexDumpLeft() const {
	return line1() + (fontWidth_ / 2);
}

/**
 * @brief QHexView::asciiDumpLeft
 * @return the x coordinate of the ascii-dump field left edge
 */
int QHexView::asciiDumpLeft() const {
	return line2() + (fontWidth_ / 2);
}

/**
 * @brief QHexView::commentLeft
 * @return the x coordinate of the comment field left edge
 */
int QHexView::commentLeft() const {
	return line3() + (fontWidth_ / 2);
}

/**
 * @brief QHexView::charsPerWord
 * @return how many characters each word takes up
 */
int QHexView::charsPerWord() const {
	return wordWidth_ * 2;
}

/**
 * @brief QHexView::addressLen
 * @return the lenth in characters the address will take up
 */
int QHexView::addressLength() const {
	if (hideLeadingAddressZeros_ && addressSize_ == Address64) {
		const int addressLength = ((addressSize_ * CHAR_BIT) / 4) - 4;
		return addressLength + (showAddressSeparator_ ? 1 : 0);
	}
	const int addressLength = (addressSize_ * CHAR_BIT) / 4;
	return addressLength + (showAddressSeparator_ ? 1 : 0);
}

/**
 * ecalculates scrollbar maximum value base on lines total and lines viewable
 *
 * @brief QHexView::updateScrollbars
 */
void QHexView::updateScrollbars() {
	const int64_t sz = dataSize();
	const int bpr    = bytesPerRow();

	const int maxval = sz / bpr + ((sz % bpr) ? 1 : 0) - viewport()->height() / fontHeight_;

	verticalScrollBar()->setMaximum(std::max(0, maxval));
	horizontalScrollBar()->setMaximum(std::max(0, ((line3() - viewport()->width()) / fontWidth_)));
}

/**
 * scrolls view to given byte offset
 *
 * @brief QHexView::scrollTo
 * @param offset
 */
void QHexView::scrollTo(address_t offset) {

	const int bpr     = bytesPerRow();
	origin_           = offset % bpr;
	address_t address = offset / bpr;

	updateScrollbars();

	if (origin_ != 0) {
		++address;
	}

	verticalScrollBar()->setValue(address);
	viewport()->update();
}

/**
 * sets if we are to display the address column
 *
 * @brief QHexView::setShowAddress
 * @param show
 */
void QHexView::setShowAddress(bool show) {
	showAddress_ = show;
	updateScrollbars();
	viewport()->update();
}

/**
 * sets if we are to display the hex-dump column
 *
 * @brief QHexView::setShowHexDump
 * @param show
 */
void QHexView::setShowHexDump(bool show) {
	showHex_ = show;
	updateScrollbars();
	viewport()->update();
}

/**
 * sets if we are to display the comments column
 *
 * @brief QHexView::setShowComments
 * @param show
 */
void QHexView::setShowComments(bool show) {
	showComments_ = show;
	updateScrollbars();
	viewport()->update();
}

/**
 * sets if we are to display the ascii-dump column
 *
 * @brief QHexView::setShowAsciiDump
 * @param show
 */
void QHexView::setShowAsciiDump(bool show) {
	showAscii_ = show;
	updateScrollbars();
	viewport()->update();
}

/**
 * sets the row width (units is words)
 *
 * @brief QHexView::setRowWidth
 * @param rowWidth
 */
void QHexView::setRowWidth(int rowWidth) {
	Q_ASSERT(rowWidth >= 0);
	rowWidth_ = rowWidth;
	updateScrollbars();
	viewport()->update();
}

/**
 * sets how many bytes represent a word
 *
 * @brief QHexView::setWordWidth
 * @param wordWidth
 */
void QHexView::setWordWidth(int wordWidth) {
	Q_ASSERT(wordWidth >= 0);
	wordWidth_ = wordWidth;
	updateScrollbars();
	viewport()->update();
}

/**
 * @brief QHexView::bytesPerRow
 * @return
 */
int QHexView::bytesPerRow() const {
	return rowWidth_ * wordWidth_;
}

/**
 * @brief QHexView::pixelToWord
 * @param x
 * @param y
 * @return
 */
int64_t QHexView::pixelToWord(int x, int y) const {
	int64_t word = -1;

	switch (highlighting_) {
	case Highlighting::Data:
#if 0
		// Make pixels outside the word correspond to the nearest word, not to the right-hand one
        x -= fontWidth_ / 2;
#endif
		// the right edge of a box is kinda quirky, so we pretend there is one
		// extra character there
		x = qBound(line1(), x, static_cast<int>(line2() + fontWidth_));

		// the selection is in the data view portion
		x -= line1();

		// scale x/y down to character from pixels
		x = x / fontWidth_ + (fmod(x, fontWidth_) >= fontWidth_ / 2 ? 1 : 0);
		y /= fontHeight_;

		// make x relative to rendering mode of the bytes
		x /= (charsPerWord() + 1);
		break;
	case Highlighting::Ascii:
		x = qBound(asciiDumpLeft(), x, line3());

		// the selection is in the ascii view portion
		x -= asciiDumpLeft();

		// scale x/y down to character from pixels
		x /= fontWidth_;
		y /= fontHeight_;

		// make x relative to rendering mode of the bytes
		x /= wordWidth_;
		break;
	default:
		Q_ASSERT(0);
		break;
	}

	// starting offset in bytes
	int64_t start_offset = normalizedOffset();

	// convert byte offset to word offset, rounding up
	start_offset /= static_cast<unsigned int>(wordWidth_);

	if ((origin_ % wordWidth_) != 0) {
		start_offset += 1;
	}

	word = ((y * rowWidth_) + x) + start_offset;

	return word;
}

/**
 * @brief QHexView::updateToolTip
 */
void QHexView::updateToolTip() {
	if (selectedBytesSize() <= 0) {
		return;
	}

	auto sb               = selectedBytes();
	const address_t start = selectedBytesAddress();
	const address_t end   = selectedBytesAddress() + sb.size();

	uchar *data     = reinterpret_cast<uchar *>(sb.data());
	QString tooltip = QString("<p style='white-space:pre'>") //prevent word wrap
					  % QString("<b>Range: </b>") % formatAddress(start) % " - " % formatAddress(end);
	if (sb.size() == sizeof(quint32))
		tooltip += QString("<br><b>UInt32:</b> ") % QString::number(qFromLittleEndian<quint32>(data)) % QString("<br><b>Int32:</b> ") % QString::number(qFromLittleEndian<qint32>(data));
	if (sb.size() == sizeof(quint64))
		tooltip += QString("<br><b>UInt64:</b> ") % QString::number(qFromLittleEndian<quint64>(data)) % QString("<br><b>Int64</b> ") % QString::number(qFromLittleEndian<qint64>(data));
	tooltip += "</p>";

	setToolTip(tooltip);
}

/**
 * @brief QHexView::mouseDoubleClickEvent
 * @param event
 */
void QHexView::mouseDoubleClickEvent(QMouseEvent *event) {
	if (event->button() == Qt::LeftButton) {
		const int x = event->x() + horizontalScrollBar()->value() * fontWidth_;
		const int y = event->y();
		if (x >= line1() && x < line2()) {

			highlighting_ = Highlighting::Data;

			const int64_t offset = pixelToWord(x, y);
			int64_t byte_offset  = offset * wordWidth_;
			if (origin_) {
				if (origin_ % wordWidth_) {
					byte_offset -= wordWidth_ - (origin_ % wordWidth_);
				}
			}

			selectionStart_ = byte_offset;
			selectionEnd_   = selectionStart_ + wordWidth_;
			viewport()->update();
		} else if (x < line1()) {
			highlighting_ = Highlighting::Data;

			const int64_t offset = pixelToWord(line1(), y);
			int64_t byte_offset  = offset * wordWidth_;
			if (origin_) {
				if (origin_ % wordWidth_) {
					byte_offset -= wordWidth_ - (origin_ % wordWidth_);
				}
			}

			const int chars_per_row = bytesPerRow();

			selectionStart_ = byte_offset;
			selectionEnd_   = byte_offset + chars_per_row;
			viewport()->update();
		}
	}

	updateToolTip();
}

/**
 * @brief QHexView::mousePressEvent
 * @param event
 */
void QHexView::mousePressEvent(QMouseEvent *event) {

	if (event->button() == Qt::LeftButton) {
		const int x = event->x() + horizontalScrollBar()->value() * fontWidth_;
		const int y = event->y();

		if (x < line2()) {
			highlighting_ = Highlighting::Data;
		} else {
			highlighting_ = Highlighting::Ascii;
		}

		const int64_t offset = pixelToWord(x, y);
		int64_t byte_offset  = offset * wordWidth_;
		if (origin_) {
			if (origin_ % wordWidth_) {
				byte_offset -= wordWidth_ - (origin_ % wordWidth_);
			}
		}

		if (offset < dataSize()) {
			if (hasSelectedText() && (event->modifiers() & Qt::ShiftModifier)) {
				selectionEnd_ = byte_offset;
			} else {
				selectionStart_ = byte_offset;
				selectionEnd_   = selectionStart_ + wordWidth_;
			}
		} else {
			selectionStart_ = selectionEnd_ = -1;
		}
		viewport()->update();
	}
	if (event->button() == Qt::RightButton) {
	}

	updateToolTip();
}

/**
 * @brief QHexView::mouseMoveEvent
 * @param event
 */
void QHexView::mouseMoveEvent(QMouseEvent *event) {
	if (highlighting_ != Highlighting::None) {
		const int x = event->x() + horizontalScrollBar()->value() * fontWidth_;
		const int y = event->y();

		const int64_t offset = pixelToWord(x, y);

		if (selectionStart_ != -1) {
			if (offset == -1) {
				selectionEnd_ = rowWidth_;
			} else {

				int64_t byte_offset = (offset * wordWidth_);

				if (origin_) {
					if (origin_ % wordWidth_) {
						byte_offset -= wordWidth_ - (origin_ % wordWidth_);
					}
				}
				selectionEnd_ = byte_offset;
				if (selectionEnd_ == selectionStart_) {
					selectionEnd_ += wordWidth_;
				}
			}

			if (selectionEnd_ < 0) {
				selectionEnd_ = 0;
			}

			if (!isInViewableArea(selectionEnd_)) {
				ensureVisible(selectionEnd_);
			}
		}
		viewport()->update();
		updateToolTip();
	}
}

/**
 * @brief QHexView::mouseReleaseEvent
 * @param event
 */
void QHexView::mouseReleaseEvent(QMouseEvent *event) {
	if (event->button() == Qt::LeftButton) {
		highlighting_ = Highlighting::None;
	}
}

/**
 * @brief QHexView::ensureVisible
 * @param index
 */
void QHexView::ensureVisible(int64_t index) {
	Q_UNUSED(index)
}

/**
 * @brief QHexView::setData
 * @param d
 */
void QHexView::setData(QIODevice *d) {
	if (d->isSequential() || !d->size()) {
		internalBuffer_ = std::make_unique<QBuffer>();
		internalBuffer_->setData(d->readAll());
		internalBuffer_->open(QBuffer::ReadOnly);
		data_ = internalBuffer_.get();
	} else {
		data_ = d;
	}

	if (data_->size() > Q_INT64_C(0xffffffff)) {
		addressSize_ = Address64;
	}

	deselect();
	updateScrollbars();
	viewport()->update();
}

/**
 * @brief QHexView::resizeEvent
 */
void QHexView::resizeEvent(QResizeEvent *) {
	updateScrollbars();
}

/**
 * @brief QHexView::setAddressOffset
 * @param offset
 */
void QHexView::setAddressOffset(address_t offset) {
	addressOffset_ = offset;
}

/**
 * @brief QHexView::isSelected
 * @param index
 * @return
 */
bool QHexView::isSelected(int64_t index) const {

	bool ret = false;
	if (index < dataSize()) {
		if (selectionStart_ != selectionEnd_) {
			if (selectionStart_ < selectionEnd_) {
				ret = (index >= selectionStart_ && index < selectionEnd_);
			} else {
				ret = (index >= selectionEnd_ && index < selectionStart_);
			}
		}
	}
	return ret;
}

/**
 * @brief QHexView::drawComments
 * @param painter
 * @param offset
 * @param row
 * @param size
 */
void QHexView::drawComments(QPainter &painter, int64_t offset, int row, int64_t size) const {

	Q_UNUSED(size)

	painter.setPen(palette().color(QPalette::Text));

	const address_t address = addressOffset_ + offset;
	const QString comment   = commentServer_->comment(address, wordWidth_);

	painter.drawText(
		commentLeft(),
		row,
		comment.length() * fontWidth_,
		fontHeight_,
		Qt::AlignTop,
		comment);
}

/**
 * @brief QHexView::drawAsciiDumpToBuffer
 * @param stream
 * @param offset
 * @param size
 * @param row_data
 */
void QHexView::drawAsciiDumpToBuffer(QTextStream &stream, int64_t offset, int64_t size, const QByteArray &row_data) const {
	// i is the byte index
	const int chars_per_row = bytesPerRow();
	for (int i = 0; i < chars_per_row; ++i) {
		const int64_t index = offset + i;
		if (index < size) {
			if (isSelected(index)) {
				const auto ch        = static_cast<uint8_t>(row_data[i]);
				const bool printable = is_printable(ch) && ch != '\f' && ch != '\t' && ch != '\r' && ch != '\n' && ch < 0x80;
				const char byteBuffer(printable ? ch : unprintableChar_);
				stream << byteBuffer;
			} else {
				stream << ' ';
			}
		} else {
			break;
		}
	}
}

/**
 * @brief QHexView::drawCommentsToBuffer
 * @param stream
 * @param offset
 * @param size
 */
void QHexView::drawCommentsToBuffer(QTextStream &stream, int64_t offset, int64_t size) const {
	Q_UNUSED(size)
	const address_t address = addressOffset_ + offset;
	const QString comment   = commentServer_->comment(address, wordWidth_);
	stream << comment;
}

/**
 * formats bytes in a way that's suitable for rendering in a hexdump having
 * this as a separate function serves two purposes.
 * #1 no code duplication between the buffer and QPainter versions
 * #2 this encourages NRVO of the return value more than an integrated
 *
 * @brief QHexView::formatBytes
 * @param row_data
 * @param index
 * @return
 */
QString QHexView::formatBytes(const QByteArray &row_data, int index) const {

	char byte_buffer[32];

	static constexpr char hexbytes[] = "000102030405060708090a0b0c0d0e0f"
									   "101112131415161718191a1b1c1d1e1f"
									   "202122232425262728292a2b2c2d2e2f"
									   "303132333435363738393a3b3c3d3e3f"
									   "404142434445464748494a4b4c4d4e4f"
									   "505152535455565758595a5b5c5d5e5f"
									   "606162636465666768696a6b6c6d6e6f"
									   "707172737475767778797a7b7c7d7e7f"
									   "808182838485868788898a8b8c8d8e8f"
									   "909192939495969798999a9b9c9d9e9f"
									   "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
									   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
									   "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
									   "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
									   "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
									   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

	switch (wordWidth_) {
	case 1:
		memcpy(&byte_buffer[0], &hexbytes[(row_data[index + 0] & 0xff) * 2], 2);
		break;
	case 2:
		memcpy(&byte_buffer[0], &hexbytes[(row_data[index + 1] & 0xff) * 2], 2);
		memcpy(&byte_buffer[2], &hexbytes[(row_data[index + 0] & 0xff) * 2], 2);
		break;
	case 4:
		memcpy(&byte_buffer[0], &hexbytes[(row_data[index + 3] & 0xff) * 2], 2);
		memcpy(&byte_buffer[2], &hexbytes[(row_data[index + 2] & 0xff) * 2], 2);
		memcpy(&byte_buffer[4], &hexbytes[(row_data[index + 1] & 0xff) * 2], 2);
		memcpy(&byte_buffer[6], &hexbytes[(row_data[index + 0] & 0xff) * 2], 2);
		break;
	case 8:
		memcpy(&byte_buffer[0], &hexbytes[(row_data[index + 7] & 0xff) * 2], 2);
		memcpy(&byte_buffer[2], &hexbytes[(row_data[index + 6] & 0xff) * 2], 2);
		memcpy(&byte_buffer[4], &hexbytes[(row_data[index + 5] & 0xff) * 2], 2);
		memcpy(&byte_buffer[6], &hexbytes[(row_data[index + 4] & 0xff) * 2], 2);
		memcpy(&byte_buffer[8], &hexbytes[(row_data[index + 3] & 0xff) * 2], 2);
		memcpy(&byte_buffer[10], &hexbytes[(row_data[index + 2] & 0xff) * 2], 2);
		memcpy(&byte_buffer[12], &hexbytes[(row_data[index + 1] & 0xff) * 2], 2);
		memcpy(&byte_buffer[14], &hexbytes[(row_data[index + 0] & 0xff) * 2], 2);
		break;
	}

	byte_buffer[wordWidth_ * 2] = '\0';

	return QString::fromLatin1(byte_buffer);
}

/**
 * @brief QHexView::drawHexDumpToBuffer
 * @param stream
 * @param offset
 * @param size
 * @param row_data
 */
void QHexView::drawHexDumpToBuffer(QTextStream &stream, int64_t offset, int64_t size, const QByteArray &row_data) const {

	Q_UNUSED(size)

	// i is the word we are currently rendering
	for (int i = 0; i < rowWidth_; ++i) {

		// index of first byte of current 'word'
		const int64_t index = offset + (i * wordWidth_);

		// equal <=, not < because we want to test the END of the word we
		// about to render, not the start, it's allowed to end at the very last
		// byte
		if (index + wordWidth_ <= size) {
			const QString byteBuffer = formatBytes(row_data, i * wordWidth_);

			if (isSelected(index)) {
				stream << byteBuffer;
			} else {
				stream << QString(byteBuffer.length(), ' ');
			}

			if (i != (rowWidth_ - 1)) {
				stream << ' ';
			}
		} else {
			break;
		}
	}
}

/**
 * @brief QHexView::drawHexDump
 * @param painter
 * @param offset
 * @param row
 * @param size
 * @param word_count
 * @param row_data
 */
void QHexView::drawHexDump(QPainter &painter, int64_t offset, int row, int64_t size, int *word_count, const QByteArray &row_data) const {
	const int hex_dump_left = hexDumpLeft();

	// i is the word we are currently rendering
	for (int i = 0; i < rowWidth_; ++i) {

		// index of first byte of current 'word'
		const int64_t index = offset + (i * wordWidth_);

		// equal <=, not < because we want to test the END of the word we
		// about to render, not the start, it's allowed to end at the very last
		// byte
		if (index + wordWidth_ <= size) {

			const QString byteBuffer = formatBytes(row_data, i * wordWidth_);

			const int drawLeft  = hex_dump_left + (i * (charsPerWord() + 1) * fontWidth_);
			const int drawWidth = charsPerWord() * fontWidth_;

			if (isSelected(index)) {

				const QPalette::ColorGroup group = hasFocus() ? QPalette::Active : QPalette::Inactive;

				painter.fillRect(
					QRectF(
						drawLeft,
						row,
						drawWidth,
						fontHeight_),
					palette().color(group, QPalette::Highlight));

				// should be highlight the space between us and the next word?
				if (i != (rowWidth_ - 1)) {
					if (isSelected(index + 1)) {
						painter.fillRect(
							QRectF(
								drawLeft + drawWidth,
								row,
								fontWidth_,
								fontHeight_),
							palette().color(group, QPalette::Highlight));
					}
				}

				painter.setPen(palette().color(group, QPalette::HighlightedText));
			} else {
				painter.setPen(QPen((*word_count & 1) ? alternateWordColor_ : palette().color(QPalette::Text)));

				// implement cold zone stuff
				if (coldZoneEnd_ > addressOffset_ && static_cast<address_t>(offset) < coldZoneEnd_ - addressOffset_) {
					painter.setPen(QPen(coldZoneColor_));
				}
			}

			painter.drawText(
				drawLeft,
				row,
				byteBuffer.length() * fontWidth_,
				fontHeight_,
				Qt::AlignTop,
				byteBuffer);

			++(*word_count);
		} else {
			break;
		}
	}
}

/**
 * @brief QHexView::drawAsciiDump
 * @param painter
 * @param offset
 * @param row
 * @param size
 * @param row_data
 */
void QHexView::drawAsciiDump(QPainter &painter, int64_t offset, int row, int64_t size, const QByteArray &row_data) const {
	const int ascii_dump_left = asciiDumpLeft();

	// i is the byte index
	const int chars_per_row = bytesPerRow();
	for (int i = 0; i < chars_per_row; ++i) {

		const int64_t index = offset + i;

		if (index < size) {
			const char ch        = row_data[i];
			const int drawLeft   = ascii_dump_left + i * fontWidth_;
			const bool printable = is_printable(ch);

			// drawing a selected character
			if (isSelected(index)) {

				const QPalette::ColorGroup group = hasFocus() ? QPalette::Active : QPalette::Inactive;

				painter.fillRect(
					QRectF(
						drawLeft,
						row,
						fontWidth_,
						fontHeight_),
					palette().color(group, QPalette::Highlight));

				painter.setPen(palette().color(group, QPalette::HighlightedText));

			} else {
				painter.setPen(QPen(printable ? palette().color(QPalette::Text) : nonPrintableTextColor_));

				// implement cold zone stuff
				if (coldZoneEnd_ > addressOffset_ && static_cast<address_t>(offset) < coldZoneEnd_ - addressOffset_) {
					painter.setPen(QPen(coldZoneColor_));
				}
			}

			const QString byteBuffer(printable ? ch : unprintableChar_);

			painter.drawText(
				drawLeft,
				row,
				fontWidth_,
				fontHeight_,
				Qt::AlignTop,
				byteBuffer);
		} else {
			break;
		}
	}
}

/**
 * @brief QHexView::paintEvent
 * @param event
 */
void QHexView::paintEvent(QPaintEvent *event) {

	Q_UNUSED(event)
	QPainter painter(viewport());
	painter.translate(-horizontalScrollBar()->value() * fontWidth_, 0);

	int word_count = 0;

	// pixel offset of this row
	int row = 0;

	const int chars_per_row = bytesPerRow();

	// current actual offset (in bytes), we do this manually because we have the else
	// case unlike the helper function
	int64_t offset = verticalScrollBar()->value() * chars_per_row;

	if (origin_ != 0) {
		if (offset > 0) {
			offset += origin_;
			offset -= chars_per_row;
		} else {
			origin_ = 0;
			updateScrollbars();
		}
	}

	const int64_t data_size = dataSize();
	const int widget_height = height();

	while (row + fontHeight_ < widget_height && offset < data_size) {

		data_->seek(offset);
		const QByteArray row_data = data_->read(chars_per_row);

		if (!row_data.isEmpty()) {
			if (showAddress_) {
				const address_t address_rva = addressOffset_ + offset;
				const QString addressBuffer = formatAddress(address_rva);
				painter.setPen(QPen(addressColor_));

				// implement cold zone stuff
				if (coldZoneEnd_ > addressOffset_ && static_cast<address_t>(offset) < coldZoneEnd_ - addressOffset_) {
					painter.setPen(QPen(coldZoneColor_));
				}

				painter.drawText(0, row, addressBuffer.length() * fontWidth_, fontHeight_, Qt::AlignTop, addressBuffer);
			}

			if (showHex_) {
				drawHexDump(painter, offset, row, data_size, &word_count, row_data);
			}

			if (showAscii_) {
				drawAsciiDump(painter, offset, row, data_size, row_data);
			}

			if (showComments_ && commentServer_) {
				drawComments(painter, offset, row, data_size);
			}
		}

		offset += chars_per_row;
		row += fontHeight_;
	}

	painter.setPen(palette().color(hasFocus() ? QPalette::Active : QPalette::Inactive, QPalette::WindowText));

	if (showAddress_ && showLine1_) {
		const int vertline1_x = line1();
		painter.drawLine(vertline1_x, 0, vertline1_x, widget_height);
	}

	if (showHex_ && showLine2_) {
		const int vertline2_x = line2();
		painter.drawLine(vertline2_x, 0, vertline2_x, widget_height);
	}

	if (showAscii_ && showLine3_) {
		const int vertline3_x = line3();
		painter.drawLine(vertline3_x, 0, vertline3_x, widget_height);
	}
}

/**
 * @brief QHexView::selectAll
 */
void QHexView::selectAll() {
	selectionStart_ = 0;
	selectionEnd_   = dataSize();
}

/**
 * @brief QHexView::deselect
 */
void QHexView::deselect() {
	selectionStart_ = -1;
	selectionEnd_   = -1;
}

/**
 * @brief QHexView::allBytes
 * @return
 */
QByteArray QHexView::allBytes() const {
	data_->seek(0);
	return data_->readAll();
}

/**
 * @brief QHexView::selectedBytes
 * @return
 */
QByteArray QHexView::selectedBytes() const {
	if (hasSelectedText()) {
		const int64_t s = std::min(selectionStart_, selectionEnd_);
		const int64_t e = std::max(selectionStart_, selectionEnd_);

		data_->seek(s);
		return data_->read(e - s);
	}

	return QByteArray();
}

/**
 * @brief QHexView::selectedBytesAddress
 * @return
 */
auto QHexView::selectedBytesAddress() const -> address_t {
	const address_t select_base = std::min(selectionStart_, selectionEnd_);
	return select_base + addressOffset_;
}

/**
 * @brief QHexView::selectedBytesSize
 * @return
 */
uint64_t QHexView::selectedBytesSize() const {

	int64_t ret;
	if (selectionEnd_ > selectionStart_) {
		ret = selectionEnd_ - selectionStart_;
	} else {
		ret = selectionStart_ - selectionEnd_;
	}

	return ret;
}

/**
 * @brief QHexView::addressOffset
 * @return
 */
auto QHexView::addressOffset() const -> address_t {
	return addressOffset_;
}

/**
 * @brief QHexView::showHexDump
 * @return
 */
bool QHexView::showHexDump() const {
	return showHex_;
}

/**
 * @brief QHexView::showAddress
 * @return
 */
bool QHexView::showAddress() const {
	return showAddress_;
}

/**
 * @brief QHexView::showAsciiDump
 * @return
 */
bool QHexView::showAsciiDump() const {
	return showAscii_;
}

/**
 * @brief QHexView::showComments
 * @return
 */
bool QHexView::showComments() const {
	return showComments_;
}

/**
 * @brief QHexView::wordWidth
 * @return
 */
int QHexView::wordWidth() const {
	return wordWidth_;
}

/**
 * @brief QHexView::rowWidth
 * @return
 */
int QHexView::rowWidth() const {
	return rowWidth_;
}

/**
 * @brief QHexView::firstVisibleAddress
 * @return
 */
auto QHexView::firstVisibleAddress() const -> address_t {
	// current actual offset (in bytes)
	int64_t offset = normalizedOffset();
	return offset + addressOffset();
}

/**
 * @brief QHexView::setAddressSize
 * @param address_size
 */
void QHexView::setAddressSize(AddressSize address_size) {
	addressSize_ = address_size;
	viewport()->update();
}

/**
 * @brief QHexView::addressSize
 * @return
 */
QHexView::AddressSize QHexView::addressSize() const {
	return addressSize_;
}

/**
 * @brief QHexView::setColdZoneEnd
 * @param offset
 */
void QHexView::setColdZoneEnd(address_t offset) {
	coldZoneEnd_ = offset;
}

/**
 * @brief QHexView::userConfigWordWidth
 * @return
 */
bool QHexView::userConfigWordWidth() const {
	return userCanSetWordWidth_;
}

/**
 * @brief QHexView::userConfigRowWidth
 * @return
 */
bool QHexView::userConfigRowWidth() const {
	return userCanSetRowWidth_;
}

/**
 * @brief QHexView::setUserConfigWordWidth
 * @param value
 */
void QHexView::setUserConfigWordWidth(bool value) {
	userCanSetWordWidth_ = value;
	viewport()->update();
}

/**
 * @brief QHexView::setUserConfigRowWidth
 * @param value
 */
void QHexView::setUserConfigRowWidth(bool value) {
	userCanSetRowWidth_ = value;
	viewport()->update();
}

/**
 * @brief QHexView::addressColor
 * @return
 */
QColor QHexView::addressColor() const {
	return addressColor_;
}

/**
 * @brief QHexView::coldZoneColor
 * @return
 */
QColor QHexView::coldZoneColor() const {
	return coldZoneColor_;
}

/**
 * @brief QHexView::alternateWordColor
 * @return
 */
QColor QHexView::alternateWordColor() const {
	return alternateWordColor_;
}

/**
 * @brief QHexView::nonPrintableTextColor
 * @return
 */
QColor QHexView::nonPrintableTextColor() const {
	return nonPrintableTextColor_;
}

/**
 * @brief QHexView::setColdZoneColor
 * @param color
 */
void QHexView::setColdZoneColor(const QColor &color) {
	coldZoneColor_ = color;
}

/**
 * @brief QHexView::setAddressColor
 * @param color
 */
void QHexView::setAddressColor(const QColor &color) {
	addressColor_ = color;
}

/**
 * @brief QHexView::setEvenWordColor
 * @param color
 */
void QHexView::setAlternateWordColor(const QColor &color) {
	alternateWordColor_ = color;
}

/**
 * @brief QHexView::setNonPrintableTextColor
 * @param color
 */
void QHexView::setNonPrintableTextColor(const QColor &color) {
	nonPrintableTextColor_ = color;
}
