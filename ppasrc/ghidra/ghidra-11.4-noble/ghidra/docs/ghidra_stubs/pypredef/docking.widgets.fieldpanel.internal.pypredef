from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


class AnchoredLayoutHandler(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: docking.widgets.fieldpanel.LayoutModel, viewHeight: typing.Union[jpype.JInt, int]):
        ...

    def positionLayoutsAroundAnchor(self, anchorIndex: java.math.BigInteger, viewPosition: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def setViewHeight(self, viewHeight: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def shiftView(self, viewAmount: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def shiftViewDownOnePage(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def shiftViewDownOneRow(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def shiftViewUpOnePage(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def shiftViewUpOneRow(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...


class FieldBackgroundColorManager(java.lang.Object):
    """
    Interface for classes that manage the background color of fields.  The background color is 
    affected by the current selection and highlight.  Implementers of this class manage the 
    interaction of the selection and highlight to provide a single object from which to get
    background color information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBackgroundColor(self) -> java.awt.Color:
        """
        Returns the overall background color for the entire field.  If the field is totally, 
        selected, then this color will be the selection color.  If the field is highlighted,then
        the color will be the highlight color.  If both, then the color will be the combined color.
        If the color is the same the overall background color of the layout containing this field,
        then null will be returned to indicate that the background color for this field does not
        need to be painted
        
        :return: the background color for this field or null if it is the same as the background for
        the entire layout.
        :rtype: java.awt.Color
        """

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Returns the color for the right or left padding within the field.  The padding is difference
        of the width of the field and the width of the text being displayed.  Most fields pad
        to the right, but a few pad to the left.
        
        :param jpype.JInt or int padIndex: either 0 or 1 to get left padding or right padding respectively.
        :return: the color for either the right or left padding.
        :rtype: java.awt.Color
        """

    def getSelectionHighlights(self, row: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        """
        Return a list of highlights (background colors ranges) for a given row of text in the field.
        
        :param jpype.JInt or int row: the row for which to get a list of highlights.
        :return: a list of highlights for the row.
        :rtype: java.util.List[docking.widgets.fieldpanel.support.Highlight]
        """

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def selectionHighlights(self) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class LayoutColorMapFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getLayoutColorMap(index: java.math.BigInteger, selection: docking.widgets.fieldpanel.support.FieldSelection, highlight: docking.widgets.fieldpanel.support.FieldSelection, backgroundColor: java.awt.Color, selectionColor: java.awt.Color, highlightColor: java.awt.Color, mixedColor: java.awt.Color) -> LayoutBackgroundColorManager:
        ...


class LayoutBackgroundColorManagerAdapter(LayoutBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, layoutColorMap: LayoutBackgroundColorManager):
        ...

    @typing.overload
    def getBackgroundColor(self) -> java.awt.Color:
        ...

    @typing.overload
    def getBackgroundColor(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> java.awt.Color:
        ...

    def getFieldBackgroundColorManager(self, fieldNum: typing.Union[jpype.JInt, int]) -> FieldBackgroundColorManager:
        ...

    def getPaddingColor(self, gap: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def setRange(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], isLastRow: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def fieldBackgroundColorManager(self) -> FieldBackgroundColorManager:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class TestBigLayoutModel(docking.widgets.fieldpanel.LayoutModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fm: java.awt.FontMetrics, name: typing.Union[java.lang.String, str], numIndexes: java.math.BigInteger):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def setNumIndexes(self, n: java.math.BigInteger):
        ...


class EmptyBigLayoutModel(docking.widgets.fieldpanel.LayoutModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class LayoutBackgroundColorManager(java.lang.Object):
    """
    Interface for classes that manage the background color of a layout.  The background color is 
    affected by the current selection and highlight.  Implementers of this class manage the 
    interaction of the selection and highlight to provide a single object from which to get
    background color information.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getBackgroundColor(self) -> java.awt.Color:
        """
        Returns the overall background color for the entire layout.  If the layout is totally, 
        selected, then this color will be the selection color.  If the layout is highlighted,then
        the color will be the highlight color.  If both, then the color will be the combined color.
        If the color is the same the overall background color of the field panel,
        then null will be returned to indicate that the background color for this layout does not
        need to be painted.
        
        :return: the background color for this layout or null if it is the same as the background for
        the field panel.
        :rtype: java.awt.Color
        """

    @typing.overload
    def getBackgroundColor(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> java.awt.Color:
        """
        Returns the background color at a specific location within the layout.
        
        :param docking.widgets.fieldpanel.support.FieldLocation location: the location in the layout for which to get the background color.
        :return: the background color at a specific location within the layout.
        :rtype: java.awt.Color
        """

    def getFieldBackgroundColorManager(self, fieldNum: typing.Union[jpype.JInt, int]) -> FieldBackgroundColorManager:
        """
        Returns a :obj:`FieldBackgroundColorManager` to manage the background colors for field 
        indexed by fieldNum.
        
        :param jpype.JInt or int fieldNum: the index of the field for which to get a colorManager.
        :return: the FieldBackgroundColorManager for the given field index.
        :rtype: FieldBackgroundColorManager
        """

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Returns the color of the padding between fields or null if the color is the same as the
        background color for the layout.
        
        :param jpype.JInt or int padIndex: the index of the padding area.  0 represents the gap before the first field.
        a -1 indicates the gap past the last field.
        :return: the color for indicated gap padding.
        :rtype: java.awt.Color
        """

    @property
    def fieldBackgroundColorManager(self) -> FieldBackgroundColorManager:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class CursorBlinker(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, panel: docking.widgets.fieldpanel.FieldPanel):
        ...

    def dispose(self):
        ...

    def restart(self):
        ...

    def showCursor(self) -> bool:
        ...

    def stop(self):
        ...

    def updatePaintArea(self, cursorLayout: docking.widgets.fieldpanel.support.AnchoredLayout, cursorPosition: docking.widgets.fieldpanel.support.FieldLocation):
        ...


class EmptyLayoutBackgroundColorManager(LayoutBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, background: java.awt.Color):
        ...

    @typing.overload
    def getBackgroundColor(self) -> java.awt.Color:
        ...

    @typing.overload
    def getBackgroundColor(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> java.awt.Color:
        ...

    def getFieldBackgroundColorManager(self, fieldNum: typing.Union[jpype.JInt, int]) -> FieldBackgroundColorManager:
        ...

    def getPaddingColor(self, gap: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    @property
    def fieldBackgroundColorManager(self) -> FieldBackgroundColorManager:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class FieldPanelCoordinator(docking.widgets.fieldpanel.listener.ViewListener):
    """
    Coordinates the scrolling of a set of field panels by sharing bound scroll models.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, panels: jpype.JArray[docking.widgets.fieldpanel.FieldPanel]):
        """
        Constructs a new FieldPanelCoordinatro to synchronize the scrolling of the given field panels.
        
        :param jpype.JArray[docking.widgets.fieldpanel.FieldPanel] panels: the array of panels to synchronize.
        """

    def add(self, fp: docking.widgets.fieldpanel.FieldPanel):
        """
        Adds the given field panel to the list of panels to synchronize.
        
        :param docking.widgets.fieldpanel.FieldPanel fp: the field panel to add.
        """

    def dispose(self):
        """
        Cleans up resources.
        """

    def remove(self, fp: docking.widgets.fieldpanel.FieldPanel):
        """
        Removes the given field panel from the list to be synchronized.
        """


class EmptyFieldBackgroundColorManager(FieldBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_INSTANCE: typing.Final[FieldBackgroundColorManager]
    EMPTY_HIGHLIGHT_LIST: typing.Final[java.util.List[docking.widgets.fieldpanel.support.Highlight]]

    def getBackgroundColor(self) -> java.awt.Color:
        ...

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getSelectionHighlights(self, row: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def selectionHighlights(self) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class PaintContext(java.lang.Object):
    """
    Miscellaneous information needed by fields to paint.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Create a new PaintContext with default color values.
        """

    def cursorFocused(self) -> bool:
        ...

    def cursorHidden(self) -> bool:
        ...

    def getBackground(self) -> java.awt.Color:
        """
        Returns the current background color setting.
        
        :return: the current background color setting.
        :rtype: java.awt.Color
        """

    def getCursorColor(self) -> java.awt.Color:
        """
        Returns the current cursor color.
        
        :return: the current cursor color.
        :rtype: java.awt.Color
        """

    def getFocusedCursorColor(self) -> java.awt.Color:
        ...

    def getForeground(self) -> java.awt.Color:
        """
        Returns the current foreground color setting.
        
        :return: the current foreground color setting.
        :rtype: java.awt.Color
        """

    def getHighlightColor(self) -> java.awt.Color:
        """
        Returns the current highlight color setting.
        
        :return: the current highlight color setting.
        :rtype: java.awt.Color
        """

    def getNotFocusedCursorColor(self) -> java.awt.Color:
        ...

    def getSelectedHighlightColor(self) -> java.awt.Color:
        """
        Returns the current selected highlight color setting.
        
        :return: the current selected highlight color setting.
        :rtype: java.awt.Color
        """

    def getSelectionColor(self) -> java.awt.Color:
        """
        Returns the current selection color setting.
        
        :return: the current selection color setting.
        :rtype: java.awt.Color
        """

    def isPrinting(self) -> bool:
        ...

    def isTextCopying(self) -> bool:
        ...

    def setBackgroundColor(self, c: java.awt.Color):
        ...

    def setCursorColor(self, c: java.awt.Color):
        ...

    def setCursorFocused(self, isFocused: typing.Union[jpype.JBoolean, bool]):
        ...

    def setCursorHidden(self, isHidden: typing.Union[jpype.JBoolean, bool]):
        ...

    def setFocusedCursorColor(self, color: java.awt.Color):
        ...

    def setForegroundColor(self, c: java.awt.Color):
        ...

    def setHighlightColor(self, c: java.awt.Color):
        ...

    def setNotFocusedCursorColor(self, color: java.awt.Color):
        ...

    def setPrinting(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSelectionColor(self, c: java.awt.Color):
        ...

    def setTextCopying(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def textCopying(self) -> jpype.JBoolean:
        ...

    @textCopying.setter
    def textCopying(self, value: jpype.JBoolean):
        ...

    @property
    def selectionColor(self) -> java.awt.Color:
        ...

    @selectionColor.setter
    def selectionColor(self, value: java.awt.Color):
        ...

    @property
    def foreground(self) -> java.awt.Color:
        ...

    @property
    def focusedCursorColor(self) -> java.awt.Color:
        ...

    @focusedCursorColor.setter
    def focusedCursorColor(self, value: java.awt.Color):
        ...

    @property
    def printing(self) -> jpype.JBoolean:
        ...

    @printing.setter
    def printing(self, value: jpype.JBoolean):
        ...

    @property
    def cursorColor(self) -> java.awt.Color:
        ...

    @cursorColor.setter
    def cursorColor(self, value: java.awt.Color):
        ...

    @property
    def notFocusedCursorColor(self) -> java.awt.Color:
        ...

    @notFocusedCursorColor.setter
    def notFocusedCursorColor(self, value: java.awt.Color):
        ...

    @property
    def highlightColor(self) -> java.awt.Color:
        ...

    @highlightColor.setter
    def highlightColor(self, value: java.awt.Color):
        ...

    @property
    def background(self) -> java.awt.Color:
        ...

    @property
    def selectedHighlightColor(self) -> java.awt.Color:
        ...


class DefaultBackgroundColorModel(docking.widgets.fieldpanel.support.BackgroundColorModel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, backgroundColor: java.awt.Color):
        ...

    @typing.overload
    def getBackgroundColor(self, index: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    @typing.overload
    def getBackgroundColor(self, index: java.math.BigInteger) -> java.awt.Color:
        ...

    def getDefaultBackgroundColor(self) -> java.awt.Color:
        ...

    def setDefaultBackgroundColor(self, color: java.awt.Color):
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def defaultBackgroundColor(self) -> java.awt.Color:
        ...

    @defaultBackgroundColor.setter
    def defaultBackgroundColor(self, value: java.awt.Color):
        ...


class MixedFieldBackgroundColorManager(FieldBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], layoutSelection: MixedLayoutBackgroundColorManager, selectionColor: java.awt.Color, backgroundColor: java.awt.Color):
        ...

    def getBackgroundColor(self) -> java.awt.Color:
        ...

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getSelectionHighlights(self, row: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def selectionHighlights(self) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class MixedLayoutBackgroundColorManager(LayoutBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, index: java.math.BigInteger, selection: docking.widgets.fieldpanel.support.FieldSelection, highlight: docking.widgets.fieldpanel.support.FieldSelection, backgroundColor: java.awt.Color, selectionColor: java.awt.Color, highlightColor: java.awt.Color, mixedColor: java.awt.Color, leftBorderColor: java.awt.Color, rightBorderColor: java.awt.Color):
        ...

    @typing.overload
    def getBackgroundColor(self) -> java.awt.Color:
        ...

    @typing.overload
    def getBackgroundColor(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> java.awt.Color:
        ...

    def getFieldBackgroundColorManager(self, fieldNum: typing.Union[jpype.JInt, int]) -> FieldBackgroundColorManager:
        ...

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getSelection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @property
    def fieldBackgroundColorManager(self) -> FieldBackgroundColorManager:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def selection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class FullySelectedFieldBackgroundColorManager(FieldBackgroundColorManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selectionColor: java.awt.Color):
        ...

    def getBackgroundColor(self) -> java.awt.Color:
        ...

    def getPaddingColor(self, padIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getSelectionHighlights(self, row: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @property
    def selectionHighlights(self) -> java.util.List[docking.widgets.fieldpanel.support.Highlight]:
        ...

    @property
    def paddingColor(self) -> java.awt.Color:
        ...


class ColorRangeMap(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def clear(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def clear(self):
        ...

    def color(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], c: java.awt.Color):
        ...

    def copy(self) -> ColorRangeMap:
        ...

    def getColor(self, index: typing.Union[jpype.JLong, int], defaultColor: java.awt.Color) -> java.awt.Color:
        ...


class LineLockedFieldPanelCoordinator(FieldPanelCoordinator):
    """
    A LineLockedFieldPanelCoordinator coordinates the scrolling of a set of field panels by sharing 
    bound scroll models that are locked together by a set of line numbers.
    All the field panels are locked together at the line numbers specified in the locked line array.
    In other words this coordinator tries to keep the indicated line for each field panel
    side by side with the indicated line for each other field panel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, panels: jpype.JArray[docking.widgets.fieldpanel.FieldPanel]):
        ...

    def add(self, fp: docking.widgets.fieldpanel.FieldPanel):
        """
        Adds the given field panel to the list of panels to coordinate.
        
        :param docking.widgets.fieldpanel.FieldPanel fp: the field panel to add.
        """

    def lockLines(self, *newLockedLines: java.math.BigInteger):
        """
        Call this method whenever you want to change the line numbers that are locked together 
        for the associated field panels.
        
        :param jpype.JArray[java.math.BigInteger] newLockedLines: the array of locked line numbers that are directly associated with
        the array of field panels.
        
        Important: Make sure the line numbers are in the order that matches the field panels in the array.
        """

    def remove(self, fp: docking.widgets.fieldpanel.FieldPanel):
        """
        Removes the given field panel from the list of those to be coordinated.
        """

    def resetLockedLines(self):
        """
        Resets the locked line numbers for this field panel coordinator to their default
        of each being zero.
        """


class LayoutLockedFieldPanelCoordinator(LineLockedFieldPanelCoordinator):
    """
    A LayoutLockedFieldPanelCoordinator is an extension of a LineLockedFieldPanelCoordinator that
    handles the fact that field panel layouts vary in size. It coordinates the scrolling of a set 
    of field panels by sharing bound scroll models that are locked together by a set of index 
    numbers for the FieldPanel Layouts. All the field panels are locked together at the index 
    numbers specified in the locked line array.
    In other words this coordinator tries to keep the layout indicated by the line (or index)
    for each field panel side by side with the indicated layout for each other field panel.
     
    Note: The layouts that are locked together will be positioned so that the bottom of those
    layouts line up within the field panels.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, *panels: docking.widgets.fieldpanel.FieldPanel):
        """
        Constructor for the coordinator.
        
        :param jpype.JArray[docking.widgets.fieldpanel.FieldPanel] panels: the field panels that will have their positions coordinated with each other.
        """



__all__ = ["AnchoredLayoutHandler", "FieldBackgroundColorManager", "LayoutColorMapFactory", "LayoutBackgroundColorManagerAdapter", "TestBigLayoutModel", "EmptyBigLayoutModel", "LayoutBackgroundColorManager", "CursorBlinker", "EmptyLayoutBackgroundColorManager", "FieldPanelCoordinator", "EmptyFieldBackgroundColorManager", "PaintContext", "DefaultBackgroundColorModel", "MixedFieldBackgroundColorManager", "MixedLayoutBackgroundColorManager", "FullySelectedFieldBackgroundColorManager", "ColorRangeMap", "LineLockedFieldPanelCoordinator", "LayoutLockedFieldPanelCoordinator"]
