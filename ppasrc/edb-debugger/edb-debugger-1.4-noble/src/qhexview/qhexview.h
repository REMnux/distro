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

#ifndef QHEXVIEW_H_
#define QHEXVIEW_H_

#include <QAbstractScrollArea>
#include <QBuffer>
#include <cstdint>
#include <memory>

class QByteArray;
class QIODevice;
class QMenu;
class QString;
class QTextStream;

class QHexView : public QAbstractScrollArea {
	Q_OBJECT

public:
	enum AddressSize {
		Address32 = 4,
		Address64 = 8
	};

public:
	using address_t = uint64_t;

private:
	class CommentServerBase {
	public:
		virtual ~CommentServerBase()                               = default;
		virtual QString comment(address_t address, int size) const = 0;
	};

	template <class T>
	class CommentServerWrapper : public CommentServerBase {
	public:
		explicit CommentServerWrapper(const T *commentServer)
			: commentServer_(commentServer) {
		}

		QString comment(address_t address, int size) const override {
			return commentServer_->comment(address, size);
		}

	private:
		const T *commentServer_;
	};

public:
	explicit QHexView(QWidget *parent = nullptr);
	~QHexView() override = default;

public:
	// We use type erasure to accept ANY type which has a QString comment(const edb::address_t &) method
	template <class T>
	void setCommentServer(T *p) {
		commentServer_ = std::make_unique<CommentServerWrapper<T>>(p);
	}

protected:
	void contextMenuEvent(QContextMenuEvent *event) override;
	void keyPressEvent(QKeyEvent *event) override;
	void mouseDoubleClickEvent(QMouseEvent *event) override;
	void mouseMoveEvent(QMouseEvent *event) override;
	void mousePressEvent(QMouseEvent *event) override;
	void mouseReleaseEvent(QMouseEvent *event) override;
	void paintEvent(QPaintEvent *event) override;
	void resizeEvent(QResizeEvent *event) override;

public Q_SLOTS:
	void repaint();
	void setAddressColor(const QColor &color);
	void setAlternateWordColor(const QColor &color);
	void setColdZoneColor(const QColor &color);
	void setFont(const QFont &font);
	void setNonPrintableTextColor(const QColor &color);
	void setRowWidth(int);
	void setShowAddress(bool);
	void setShowAddressSeparator(bool value);
	void setShowAsciiDump(bool);
	void setShowComments(bool);
	void setShowHexDump(bool);
	void setUserConfigRowWidth(bool);
	void setUserConfigWordWidth(bool);
	void setWordWidth(int);
	void setHideLeadingAddressZeros(bool);

public:
	AddressSize addressSize() const;
	QByteArray allBytes() const;
	QByteArray selectedBytes() const;
	QColor addressColor() const;
	QIODevice *data() const { return data_; }
	QMenu *createStandardContextMenu();
	address_t addressOffset() const;
	address_t firstVisibleAddress() const;
	address_t selectedBytesAddress() const;
	bool hasSelectedText() const;
	bool showAddress() const;
	bool showAsciiDump() const;
	bool showComments() const;
	bool showHexDump() const;
	bool userConfigRowWidth() const;
	bool userConfigWordWidth() const;
	bool hideLeadingAddressZeros() const;
	int rowWidth() const;
	int wordWidth() const;
	uint64_t selectedBytesSize() const;
	void scrollTo(address_t offset);
	void setAddressOffset(address_t offset);
	void setAddressSize(AddressSize address_size);
	void setColdZoneEnd(address_t offset);
	void setData(QIODevice *d);
	QColor alternateWordColor() const;
	QColor coldZoneColor() const;
	QColor nonPrintableTextColor() const;

public Q_SLOTS:
	void clear();
	void deselect();
	void mnuAddrCopy();
	void mnuCopy();
	void mnuSetFont();
	void selectAll();

private:
	QString formatAddress(address_t address);
	QString formatBytes(const QByteArray &row_data, int index) const;
	bool isInViewableArea(int64_t index) const;
	bool isSelected(int64_t index) const;
	int addressLength() const;
	int asciiDumpLeft() const;
	int bytesPerRow() const;
	int charsPerWord() const;
	int commentLeft() const;
	int hexDumpLeft() const;
	int line1() const;
	int line2() const;
	int line3() const;
	int64_t dataSize() const;
	int64_t normalizedOffset() const;
	int64_t pixelToWord(int x, int y) const;
	void drawAsciiDump(QPainter &painter, int64_t offset, int row, int64_t size, const QByteArray &row_data) const;
	void drawAsciiDumpToBuffer(QTextStream &stream, int64_t offset, int64_t size, const QByteArray &row_data) const;
	void drawComments(QPainter &painter, int64_t offset, int row, int64_t size) const;
	void drawCommentsToBuffer(QTextStream &stream, int64_t offset, int64_t size) const;
	void drawHexDump(QPainter &painter, int64_t offset, int row, int64_t size, int *word_count, const QByteArray &row_data) const;
	void drawHexDumpToBuffer(QTextStream &stream, int64_t offset, int64_t size, const QByteArray &row_data) const;
	void ensureVisible(int64_t index);
	void updateScrollbars();
	void updateToolTip();

private:
	AddressSize addressSize_      = Address64;
	QColor addressColor_          = Qt::red; // color of the address in display
	QColor alternateWordColor_    = Qt::blue;
	QColor coldZoneColor_         = Qt::gray;
	QColor nonPrintableTextColor_ = Qt::red;
	QIODevice *data_              = nullptr;
	address_t addressOffset_      = 0; // this is the offset that our base address is relative to
	address_t coldZoneEnd_        = 0; // base_address - cold_zone_end_ will be displayed as gray
	address_t origin_             = 0;
	bool showAddressSeparator_    = true; // should we show ':' character in address to separate high/low portions
	bool showAddress_             = true; // should we show the address display?
	bool showAscii_               = true; // should we show the ascii display?
	bool showComments_            = true;
	bool showHex_                 = true; // should we show the hex display?
	bool showLine1_               = true;
	bool showLine2_               = true;
	bool showLine3_               = true;
	bool userCanSetRowWidth_      = true;
	bool userCanSetWordWidth_     = true;
	bool hideLeadingAddressZeros_ = false;
	char unprintableChar_         = '.';
	int fontHeight_               = 0;  // height of a character in this font
	int fontWidth_                = 0;  // width of a character in this font
	int rowWidth_                 = 16; // amount of 'words' per row
	int wordWidth_                = 1;  // size of a 'word' in bytes
	int64_t selectionEnd_         = -1; // index of last selected word (or -1)
	int64_t selectionStart_       = -1; // index of first selected word (or -1)
	std::unique_ptr<CommentServerBase> commentServer_;
	std::unique_ptr<QBuffer> internalBuffer_;

	enum class Highlighting {
		None,
		Data,
		Ascii
	} highlighting_ = Highlighting::None;
};

#endif
