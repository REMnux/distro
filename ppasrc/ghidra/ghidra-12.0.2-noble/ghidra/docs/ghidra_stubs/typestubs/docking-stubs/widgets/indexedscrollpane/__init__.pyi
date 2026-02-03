from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import javax.swing # type: ignore


class UniformViewToIndexMapper(ViewToIndexMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, scrollable: IndexedScrollable):
        ...


class IndexedScrollable(java.lang.Object):
    """
    Interface for scrolling a FieldPanel or container of a group of FieldPanels which displays
    a list of displayable items (layouts)
    """

    class_: typing.ClassVar[java.lang.Class]

    def addIndexScrollListener(self, listener: IndexScrollListener):
        """
        Adds a listener to be notified when the view is scrolled in any way.
        
        :param IndexScrollListener listener: the listener to be notified when the visible items change
        """

    def getHeight(self, index: java.math.BigInteger) -> int:
        """
        Returns the height of the n'th item.
        
        :param java.math.BigInteger index: the index of the time to get height for
        :return: the height of the n'th item.
        :rtype: int
        """

    def getIndexAfter(self, index: java.math.BigInteger) -> java.math.BigInteger:
        """
        Returns the index of the next non-null item. Not all indexes have items. Some items span
        multiple indexes
        
        :param java.math.BigInteger index: the index to start searching for the next non-null item
        :return: the index of the next non-null item, or -1 if there is none
        :rtype: java.math.BigInteger
        """

    def getIndexBefore(self, index: java.math.BigInteger) -> java.math.BigInteger:
        """
        Returns the index of the previous non-null item. Not all indexes have items. Some items span
        multiple indexes
        
        :param java.math.BigInteger index: the index to start searching backwards for the previous non-null item
        :return: the index of the previous non-null item, or -1 if there is none
        :rtype: java.math.BigInteger
        """

    def getIndexCount(self) -> java.math.BigInteger:
        """
        Returns the number individually addressable items displayed.
        
        :return: the number individually addressable items displayed
        :rtype: java.math.BigInteger
        """

    def isUniformIndex(self) -> bool:
        """
        Returns true if all the items are the same vertical size.
        
        :return: true if all the items are the same vertical size
        :rtype: bool
        """

    def mouseWheelMoved(self, preciseWheelRotation: typing.Union[jpype.JDouble, float], isHorizontal: typing.Union[jpype.JBoolean, bool]):
        """
        Notify the scrollable that the mouse wheel was moved.
        
        :param jpype.JDouble or float preciseWheelRotation: the amount of rotation of the wheel
        :param jpype.JBoolean or bool isHorizontal: true if the rotation was horizontal, false for vertical
        """

    def removeIndexScrollListener(self, listener: IndexScrollListener):
        """
        Removes the given listener from those to be notified when the view changes.
        
        :param IndexScrollListener listener: the listener to remove
        """

    def scrollLineDown(self):
        """
        Scrolls the displayed items down by the height of one line of text
        """

    def scrollLineUp(self):
        """
        Scrolls the displayed items up by the height of one line of text
        """

    def scrollPageDown(self):
        """
        Scrolls the displayed items down by the height of one screen of text
        """

    def scrollPageUp(self):
        """
        Scrolls the displayed items up by the height of one screen of text
        """

    def showIndex(self, index: java.math.BigInteger, verticalOffset: typing.Union[jpype.JInt, int]):
        """
        Makes the item at the given index be visible on the screen at the given vertical offset
        
        :param java.math.BigInteger index: the index of the item to show
        :param jpype.JInt or int verticalOffset: the number of pixels from the top of the screen to show the item
        """

    @property
    def indexAfter(self) -> java.math.BigInteger:
        ...

    @property
    def uniformIndex(self) -> jpype.JBoolean:
        ...

    @property
    def indexCount(self) -> java.math.BigInteger:
        ...

    @property
    def indexBefore(self) -> java.math.BigInteger:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class IndexScrollListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def indexModelChanged(self):
        ...

    def indexModelDataChanged(self, start: java.math.BigInteger, end: java.math.BigInteger):
        ...

    def indexRangeChanged(self, startIndex: java.math.BigInteger, endIndex: java.math.BigInteger, yStart: typing.Union[jpype.JInt, int], yEnd: typing.Union[jpype.JInt, int]):
        ...


class DefaultViewToIndexMapper(ViewToIndexMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: IndexedScrollable, screenHeight: typing.Union[jpype.JInt, int]):
        ...


class IndexedScrollPane(javax.swing.JPanel, IndexScrollListener):

    @typing.type_check_only
    class ScrollViewLayout(java.awt.LayoutManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScrollView(javax.swing.JPanel, javax.swing.Scrollable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comp: javax.swing.JComponent):
        ...

    def getColumnHeader(self) -> javax.swing.JViewport:
        ...

    def getHorizontalScrollBar(self) -> javax.swing.JScrollBar:
        ...

    def getVerticalScrollBar(self) -> javax.swing.JScrollBar:
        ...

    def getViewSize(self) -> java.awt.Dimension:
        ...

    def getViewportBorderBounds(self) -> java.awt.Rectangle:
        ...

    def setColumnHeader(self, header: javax.swing.JViewport):
        ...

    def setColumnHeaderComp(self, comp: javax.swing.JComponent):
        ...

    def setHorizontalScrollBarPolicy(self, policy: typing.Union[jpype.JInt, int]):
        ...

    def setNeverScroll(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this scroll pane to never show scroll bars. This is useful when you want a container
        whose view is always as big as the component in this scroll pane.
        
        :param jpype.JBoolean or bool b: true to never scroll
        """

    def setScrollbarSideKickComponent(self, component: javax.swing.JComponent):
        ...

    def setVerticalScrollBarPolicy(self, policy: typing.Union[jpype.JInt, int]):
        ...

    def setWheelScrollingEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether the scroll wheel triggers scrolling **when over the scroll pane** of this
        class. When disabled, scrolling will still work when over the component inside of this class,
        but not when over the scroll bar.
        
        :param jpype.JBoolean or bool enabled: true to enable
        """

    def viewportStateChanged(self):
        ...

    @property
    def viewSize(self) -> java.awt.Dimension:
        ...

    @property
    def columnHeader(self) -> javax.swing.JViewport:
        ...

    @columnHeader.setter
    def columnHeader(self, value: javax.swing.JViewport):
        ...

    @property
    def horizontalScrollBar(self) -> javax.swing.JScrollBar:
        ...

    @property
    def verticalScrollBar(self) -> javax.swing.JScrollBar:
        ...

    @property
    def viewportBorderBounds(self) -> java.awt.Rectangle:
        ...


class ViewToIndexMapper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self, value: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        ...

    def getScrollValue(self, startIndex: java.math.BigInteger, endIndex: java.math.BigInteger, yStart: typing.Union[jpype.JInt, int], yEnd: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getVerticalOffset(self, value: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getViewHeight(self) -> int:
        ...

    def indexModelDataChanged(self, start: java.math.BigInteger, end: java.math.BigInteger):
        ...

    def setVisibleViewHeight(self, height: typing.Union[jpype.JInt, int]):
        ...

    @property
    def verticalOffset(self) -> jpype.JInt:
        ...

    @property
    def viewHeight(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> java.math.BigInteger:
        ...


class PreMappedViewToIndexMapper(ViewToIndexMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: IndexedScrollable):
        ...



__all__ = ["UniformViewToIndexMapper", "IndexedScrollable", "IndexScrollListener", "DefaultViewToIndexMapper", "IndexedScrollPane", "ViewToIndexMapper", "PreMappedViewToIndexMapper"]
