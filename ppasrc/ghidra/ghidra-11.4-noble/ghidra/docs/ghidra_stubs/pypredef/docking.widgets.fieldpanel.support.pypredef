from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import ghidra.framework.options
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import org.jdom # type: ignore


class BackgroundColorModel(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getBackgroundColor(self, index: java.math.BigInteger) -> java.awt.Color:
        ...

    def getDefaultBackgroundColor(self) -> java.awt.Color:
        ...

    def setDefaultBackgroundColor(self, c: java.awt.Color):
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


class RowColLocation(java.lang.Object):
    """
    Simple class to return a row, column location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Constructs a new RowColLocation with the given row and column.
        
        :param jpype.JInt or int row: the row location
        :param jpype.JInt or int col: the column location
        """

    def col(self) -> int:
        ...

    def row(self) -> int:
        ...

    def withCol(self, newColumn: typing.Union[jpype.JInt, int]) -> RowColLocation:
        ...

    def withRow(self, newRow: typing.Union[jpype.JInt, int]) -> RowColLocation:
        ...


class AnchoredLayout(docking.widgets.fieldpanel.Layout):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, layout: docking.widgets.fieldpanel.Layout, index: java.math.BigInteger, yPos: typing.Union[jpype.JInt, int]):
        ...

    def getEndY(self) -> int:
        ...

    def getIndex(self) -> java.math.BigInteger:
        ...

    def getYPos(self) -> int:
        ...

    def setYPos(self, yPos: typing.Union[jpype.JInt, int]):
        ...

    @property
    def endY(self) -> jpype.JInt:
        ...

    @property
    def yPos(self) -> jpype.JInt:
        ...

    @yPos.setter
    def yPos(self, value: jpype.JInt):
        ...

    @property
    def index(self) -> java.math.BigInteger:
        ...


class SingleRowLayout(RowLayout):
    """
    Convienence class for SingleRowLayout.  It provides numerous constructors to
    make it easier to create RowLayouts.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, field1: docking.widgets.fieldpanel.field.Field):
        """
        Construct a SingleRowLayout with a single field.
        
        :param docking.widgets.fieldpanel.field.Field field1: the single field in this layout
        """

    @typing.overload
    def __init__(self, field1: docking.widgets.fieldpanel.field.Field, field2: docking.widgets.fieldpanel.field.Field):
        """
        Construct a SingleRowLayout with two fields.
        
        :param docking.widgets.fieldpanel.field.Field field1: the first field in the layout.
        :param docking.widgets.fieldpanel.field.Field field2: the second field in the layout.
        """

    @typing.overload
    def __init__(self, field1: docking.widgets.fieldpanel.field.Field, field2: docking.widgets.fieldpanel.field.Field, field3: docking.widgets.fieldpanel.field.Field):
        """
        Construct a SingleRowLayout with three fields.
        
        :param docking.widgets.fieldpanel.field.Field field1: the first field in the layout.
        :param docking.widgets.fieldpanel.field.Field field2: the second field in the layout.
        :param docking.widgets.fieldpanel.field.Field field3: the third field in the layout.
        """

    @typing.overload
    def __init__(self, field1: docking.widgets.fieldpanel.field.Field, field2: docking.widgets.fieldpanel.field.Field, field3: docking.widgets.fieldpanel.field.Field, field4: docking.widgets.fieldpanel.field.Field):
        """
        Construct a SingleRowLayout with four fields.
        
        :param docking.widgets.fieldpanel.field.Field field1: the first field in the layout.
        :param docking.widgets.fieldpanel.field.Field field2: the second field in the layout.
        :param docking.widgets.fieldpanel.field.Field field3: the third field in the layout.
        :param docking.widgets.fieldpanel.field.Field field4: the fourth field in the layout,
        """

    @typing.overload
    def __init__(self, field1: docking.widgets.fieldpanel.field.Field, field2: docking.widgets.fieldpanel.field.Field, field3: docking.widgets.fieldpanel.field.Field, field4: docking.widgets.fieldpanel.field.Field, field5: docking.widgets.fieldpanel.field.Field):
        """
        Construct a SingleRowLayout with five fields.
        
        :param docking.widgets.fieldpanel.field.Field field1: the first field in the layout.
        :param docking.widgets.fieldpanel.field.Field field2: the second field in the layout.
        :param docking.widgets.fieldpanel.field.Field field3: the third field in the layout.
        :param docking.widgets.fieldpanel.field.Field field4: the fourth field in the layout.
        :param docking.widgets.fieldpanel.field.Field field5: the fifth field in the layout.
        """

    @typing.overload
    def __init__(self, fields: jpype.JArray[docking.widgets.fieldpanel.field.Field], rowNum: typing.Union[jpype.JInt, int]):
        """
        Construct a SingleRowLayout from a list of fields.
        
        :param jpype.JArray[docking.widgets.fieldpanel.field.Field] fields: an array of fields to put in this layout
        :param jpype.JInt or int rowNum: the row number of the layout within a multiRow layout.
        """

    @typing.overload
    def __init__(self, fields: jpype.JArray[docking.widgets.fieldpanel.field.Field]):
        """
        Construct a SingleRowLayout from a list of fields.
        
        :param jpype.JArray[docking.widgets.fieldpanel.field.Field] fields: an array of fields to put in this layout
        """


class ViewerPosition(java.io.Serializable):
    """
    Records the current top of screen position of the viewer.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, index: java.math.BigInteger, xOffset: typing.Union[jpype.JInt, int], yOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new viewer position with the given index, xOffset and yOffset.
        
        :param java.math.BigInteger index: the index of the layout displayed at the top of the screen.
        :param jpype.JInt or int xOffset: The horizontal scroll position (NOT CURRENTLY USED)
        :param jpype.JInt or int yOffset: the vertical position of the layout at the top of the screen.
        If the layout is totally visible, then the yOffset will be 0. Otherwise,
        it will be < 0 indicating that it begins above the top of the screen.
        """

    @typing.overload
    def __init__(self, index: typing.Union[jpype.JInt, int], xOffset: typing.Union[jpype.JInt, int], yOffset: typing.Union[jpype.JInt, int]):
        ...

    def getIndex(self) -> java.math.BigInteger:
        ...

    def getIndexAsInt(self) -> int:
        """
        Returns the index of the item at the top of the screen.
        """

    def getXOffset(self) -> int:
        """
        Returns the horizontal scroll position.
        """

    def getYOffset(self) -> int:
        """
        Returns the y coordinate of the layout at the top of the screen.
        """

    @property
    def yOffset(self) -> jpype.JInt:
        ...

    @property
    def xOffset(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> java.math.BigInteger:
        ...

    @property
    def indexAsInt(self) -> jpype.JInt:
        ...


class Highlight(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], color: java.awt.Color):
        """
        Constructs a new Highlight that indicates where to highlight text in the listing fields.
        
        :param jpype.JInt or int start: the starting character position to highlight
        :param jpype.JInt or int end: the ending character position (inclusive) to highlight
        :param java.awt.Color color: the color to use for highlighting.
        """

    def getColor(self) -> java.awt.Color:
        """
        Returns the color to use as the background highlight color.
        """

    def getEnd(self) -> int:
        """
        Returns the ending position (inclusive) of the highlight.
        """

    def getStart(self) -> int:
        """
        Returns the starting position of the highlight.
        """

    def setOffset(self, newOffset: typing.Union[jpype.JInt, int]):
        """
        Sets the offset of this highlights start and end values.  The effect of the offset is that
        calls to :meth:`getStart() <.getStart>` and :meth:`getEnd() <.getEnd>` will return their values with the 
        offset added.
        
        :param jpype.JInt or int newOffset: The new offset into this highlight.
        """

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def start(self) -> jpype.JInt:
        ...

    @property
    def end(self) -> jpype.JInt:
        ...


class FieldSelection(java.lang.Iterable[FieldRange]):
    """
    This class represents a selection in a field viewer.
     
    
    A :obj:`FieldSelection` may be within a single layout or may cross multiple layouts.  To
    determine if a selection crosses multiple layouts, you can get the :obj:`range <FieldRange>` of
    the selection.   You can then use the range's start and end locations to determine if the
    selection spans multiple layouts.   If the start and end indexes of the range are the same, then
    the selection is within a single layout; otherwise, the selection spans multiple layouts.
    
    
    .. seealso::
    
        | :obj:`FieldRange`
    
        | :obj:`FieldLocation`
    
        | :obj:`Layout`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new empty FieldSelection.
        """

    @typing.overload
    def __init__(self, selection: FieldSelection):
        """
        Construct a new FieldSelection with the same selection as the given FieldSelection.
        
        :param FieldSelection selection: the FieldSelection to copy.
        """

    @typing.overload
    def addRange(self, start: FieldLocation, end: FieldLocation):
        """
        Adds a field range to this selection.
        
        :param FieldLocation start: the starting field location.
        :param FieldLocation end: the ending field location.
        """

    @typing.overload
    def addRange(self, startIndex: typing.Union[jpype.JInt, int], endIndex: typing.Union[jpype.JInt, int]):
        """
        Add the all the indexes from startIndex to endIndex to the selection.  The added
        range includes the startIndex, but not the endIndex.
        
        :param jpype.JInt or int startIndex: the start index of the layouts to include
        :param jpype.JInt or int endIndex: the end index(not inclusive) of the layouts to include
        """

    @typing.overload
    def addRange(self, startIndex: java.math.BigInteger, endIndex: java.math.BigInteger):
        ...

    @typing.overload
    def addRange(self, startIndex: typing.Union[jpype.JInt, int], startFieldNum: typing.Union[jpype.JInt, int], endIndex: typing.Union[jpype.JInt, int], endFieldNum: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addRange(self, startIndex: java.math.BigInteger, startFieldNum: typing.Union[jpype.JInt, int], endIndex: java.math.BigInteger, endFieldNum: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def addRange(self, range: FieldRange):
        ...

    def clear(self):
        """
        Removes all indexes from the list.
        """

    def contains(self, loc: FieldLocation) -> bool:
        """
        Returns true if the given Field at the given index is in the selection.
        
        :param FieldLocation loc: the field location.
        :return: true if the field selection contains the specified location.
        :rtype: bool
        """

    @typing.overload
    def containsEntirely(self, index: java.math.BigInteger) -> bool:
        """
        Returns true if the all the fields in the layout with the given index are
        included in this selection.
        
        :param java.math.BigInteger index: index of the layout to test.
        :return: true if the all the fields in the layout with the given index are
        included in this selection.
        :rtype: bool
        """

    @typing.overload
    def containsEntirely(self, range: FieldRange) -> bool:
        ...

    def delete(self, selection: FieldSelection):
        """
        Delete all fields in the ranges in the given field selection from this one.
        
        :param FieldSelection selection: the field selection fields to remove from this field selection.
        """

    @typing.overload
    def excludesEntirely(self, range: FieldRange) -> bool:
        ...

    @typing.overload
    def excludesEntirely(self, index: java.math.BigInteger) -> bool:
        ...

    def findIntersection(self, selection: FieldSelection) -> FieldSelection:
        """
        Computes the intersection of this field selection and the given field selection.
        
        :param FieldSelection selection: the selection to intersect with.
        :return: the selection
        :rtype: FieldSelection
        """

    def getFieldRange(self, rangeNum: typing.Union[jpype.JInt, int]) -> FieldRange:
        """
        Returns the i'th Field Range in the selection.
        
        :param jpype.JInt or int rangeNum: the index of the range to retrieve.
        :return: the range
        :rtype: FieldRange
        """

    def getNumRanges(self) -> int:
        """
        Returns the current number of ranges in the list.
        
        :return: the current number of ranges in the list.
        :rtype: int
        """

    def getRangeContaining(self, loc: FieldLocation) -> FieldRange:
        """
        Returns the range if the given Field at the given index is in the selection.
        Otherwise returns null.
        
        :param FieldLocation loc: location to find the range for.
        :return: the range
        :rtype: FieldRange
        """

    def insert(self, selection: FieldSelection):
        """
        Insert all fields in the ranges in the given field selection from this one.
        
        :param FieldSelection selection: the field selection fields to add to this field selection.
        """

    @typing.overload
    def intersect(self, selection: FieldSelection):
        """
        Compute the intersection of this field selection and another one.
        The intersection of two field selections is all fields existing in
        both selections.
         
         
        Note: This field selection becomes the intersection.
        
        :param FieldSelection selection: field selection to intersect.
        """

    @typing.overload
    def intersect(self, index: typing.Union[jpype.JInt, int]) -> FieldSelection:
        ...

    @typing.overload
    def intersect(self, index: java.math.BigInteger) -> FieldSelection:
        ...

    @typing.overload
    def intersect(self, range: FieldRange) -> FieldSelection:
        ...

    def isEmpty(self) -> bool:
        ...

    def load(self, saveState: ghidra.framework.options.SaveState):
        ...

    @typing.overload
    def removeRange(self, start: FieldLocation, end: FieldLocation):
        """
        Removes the given field range from the current selection.
        
        :param FieldLocation start: the starting field location.
        :param FieldLocation end: the ending field location.
        """

    @typing.overload
    def removeRange(self, startIndex: typing.Union[jpype.JInt, int], endIndex: typing.Union[jpype.JInt, int]):
        """
        Removes the all the fields in the index range from the selection.
        
        :param jpype.JInt or int startIndex: the first index in the range to remove.
        :param jpype.JInt or int endIndex: the last index in the range to remove.
        """

    @typing.overload
    def removeRange(self, startIndex: java.math.BigInteger, endIndex: java.math.BigInteger):
        ...

    def save(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def fieldRange(self) -> FieldRange:
        ...

    @property
    def rangeContaining(self) -> FieldRange:
        ...

    @property
    def numRanges(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class DefaultRowColLocation(RowColLocation):
    """
    A location used to represent a an edge case where not suitable location can be found and the
    client does not wish to return null.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...


class FieldSelectionHelper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getAllSelectedText(selection: FieldSelection, panel: docking.widgets.fieldpanel.FieldPanel) -> str:
        """
        Returns the text within the given selection.
        
        :param FieldSelection selection: the selection
        :param docking.widgets.fieldpanel.FieldPanel panel: the field panel
        :return: the text
        :rtype: str
        """

    @staticmethod
    def getFieldSelectionText(selection: FieldSelection, panel: docking.widgets.fieldpanel.FieldPanel) -> str:
        """
        Gets the selected text that pertains to an individual field.  Null is returned if the
        given selection spans more than one field.
        
        :param FieldSelection selection: the selection
        :param docking.widgets.fieldpanel.FieldPanel panel: the field panel
        :return: the text
        :rtype: str
        """

    @staticmethod
    def isStringSelection(selection: FieldSelection) -> bool:
        ...


class FieldRange(java.lang.Comparable[FieldRange]):
    """
    A range consists of a start position within a start row to an end position within an end row
    (exclusive).
      
    
    Conceptually, this class can be thought of as a range of rows (defined by start and end
    indexes) with sub-positions within those rows. As an example, consider a text selection that
    begins on some word in a row and ends on another word in a different row.
    
    
    .. seealso::
    
        | :obj:`FieldSelection`
    
        | :obj:`FieldLocation`
    
        | :obj:`Layout`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, start: FieldLocation, end: FieldLocation):
        ...

    @typing.overload
    def __init__(self, range: FieldRange):
        ...

    @typing.overload
    def __init__(self, element: org.jdom.Element):
        ...

    def canMerge(self, newRange: FieldRange) -> bool:
        ...

    def contains(self, loc: FieldLocation) -> bool:
        """
        checks if the given location is contained in the range.
        
        :param FieldLocation loc: the field location.
        :return: true if the field range contains the specified location.
        :rtype: bool
        """

    @typing.overload
    def containsEntirely(self, index: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @typing.overload
    def containsEntirely(self, index: java.math.BigInteger) -> bool:
        ...

    def getElement(self) -> org.jdom.Element:
        ...

    def getEnd(self) -> FieldLocation:
        ...

    def getStart(self) -> FieldLocation:
        ...

    def intersect(self, range: FieldRange) -> FieldRange:
        ...

    def intersects(self, range: FieldRange) -> bool:
        ...

    def isEmpty(self) -> bool:
        ...

    def merge(self, newRange: FieldRange):
        ...

    def subtract(self, deleteRange: FieldRange) -> FieldRange:
        ...

    @property
    def start(self) -> FieldLocation:
        ...

    @property
    def end(self) -> FieldLocation:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def element(self) -> org.jdom.Element:
        ...


class RowLayout(docking.widgets.fieldpanel.Layout):
    """
    RowLayout handles a single row layout that may be part of a multiple row layout that
    is generic enough to be used by the SingleRowLayout or the MultiRowLayout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fields: jpype.JArray[docking.widgets.fieldpanel.field.Field], rowID: typing.Union[jpype.JInt, int]):
        """
        Constructs a RowLayout from an array of fields
        
        :param jpype.JArray[docking.widgets.fieldpanel.field.Field] fields: the set of fields that make up the entire layout
        :param jpype.JInt or int rowID: the rowID of this row layout in the overall layout.
        """

    def getHeightAbove(self) -> int:
        """
        Returns the height above the baseline.
        
        :return: the height above the baseline.
        :rtype: int
        """

    def getHeightBelow(self) -> int:
        """
        Returns the height below the baseline.
        
        :return: the height below the baseline.
        :rtype: int
        """

    def getRowID(self) -> int:
        """
        Returns the row number of this layout with respect to its containing layout.
        
        :return: the row number of this layout with respect to its containing layout.
        :rtype: int
        """

    @property
    def heightBelow(self) -> jpype.JInt:
        ...

    @property
    def rowID(self) -> jpype.JInt:
        ...

    @property
    def heightAbove(self) -> jpype.JInt:
        ...


class FieldHighlightFactory(java.lang.Object):
    """
    A highlighter for :obj:`Field`s.
    """

    class_: typing.ClassVar[java.lang.Class]
    NO_HIGHLIGHTS: typing.Final[jpype.JArray[Highlight]]

    def createHighlights(self, field: docking.widgets.fieldpanel.field.Field, text: typing.Union[java.lang.String, str], cursorTextOffset: typing.Union[jpype.JInt, int]) -> jpype.JArray[Highlight]:
        """
        Returns the highlights for the given text
        
        :param docking.widgets.fieldpanel.field.Field field: the field that is requesting the highlight
        :param java.lang.String or str text: the text to be considered for highlighting
        :param jpype.JInt or int cursorTextOffset: the position in the given text of the cursor. A -1 indicates the
                cursor is not in this field.
        :return: an array of highlights to be rendered
        :rtype: jpype.JArray[Highlight]
        """


class HoverProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def closeHover(self):
        """
        Hide this service's popup window if visible
        """

    def isShowing(self) -> bool:
        """
        Returns true if this service's popup window is currently visible
        
        :return: true if this service's popup window is currently visible
        :rtype: bool
        """

    def mouseHovered(self, fieldLocation: FieldLocation, field: docking.widgets.fieldpanel.field.Field, fieldBounds: java.awt.Rectangle, event: java.awt.event.MouseEvent):
        """
        Notify this service that the mouse is hovering over a specific field within a 
        field viewer.
        
        :param FieldLocation fieldLocation: the precise mouse location within the field viewer
        :param docking.widgets.fieldpanel.field.Field field: the field over which the mouse is hovering
        :param java.awt.Rectangle fieldBounds: the rectangle containing the bounds of the given field.
        :param java.awt.event.MouseEvent event: the last mouse motion event over the field viewer component (i.e., FieldPanel).
        """

    def scroll(self, amount: typing.Union[jpype.JInt, int]):
        """
        If this service's window supports scrolling, scroll by the specified amount.  The value
        will be negative when scrolling should move up.
        
        :param jpype.JInt or int amount: the amount by which to scroll
        """

    @property
    def showing(self) -> jpype.JBoolean:
        ...


class FieldUtils(java.lang.Object):
    """
    A utility class for working with Field objects.
    """

    class_: typing.ClassVar[java.lang.Class]
    WORD_WRAP_OPTION_NAME: typing.Final = "Enable Word Wrapping"
    WORD_WRAP_OPTION_DESCRIPTION: typing.Final = "Enables word wrapping.  When on, each line of text is wrapped as needed to fit within the current width.  When off, comments are displayed as entered by the user.  Lines that are too long for the field are truncated."

    @staticmethod
    def trimString(string: typing.Union[java.lang.String, str]) -> str:
        """
        Trims unwanted characters off of the given label, like spaces, '[',']', etc.
        
        :param java.lang.String or str string: The string to be trimmed
        :return: The trimmed string.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def wrap(fieldElements: java.util.List[docking.widgets.fieldpanel.field.FieldElement], width: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.field.FieldElement]:
        ...

    @staticmethod
    @typing.overload
    def wrap(fieldElement: docking.widgets.fieldpanel.field.FieldElement, width: typing.Union[jpype.JInt, int]) -> java.util.List[docking.widgets.fieldpanel.field.FieldElement]:
        """
        Splits the given FieldElement into sub-elements by wrapping the element on whitespace.
        
        :param docking.widgets.fieldpanel.field.FieldElement fieldElement: The element to wrap
        :param jpype.JInt or int width: The maximum width to allow before wrapping
        :return: The wrapped elements
        :rtype: java.util.List[docking.widgets.fieldpanel.field.FieldElement]
        """

    @staticmethod
    @typing.overload
    def wrap(fieldElement: docking.widgets.fieldpanel.field.FieldElement, width: typing.Union[jpype.JInt, int], breakOnWhiteSpace: typing.Union[jpype.JBoolean, bool]) -> java.util.List[docking.widgets.fieldpanel.field.FieldElement]:
        """
        Splits the given FieldElement into sub-elements by wrapping the element in some fashion.
        If breakOnWhiteSpace is indicated, wrapping will break lines on a white space character
        if possible, otherwise wrapping occurs on the last possible character.
        
        :param docking.widgets.fieldpanel.field.FieldElement fieldElement: is the element to wrap
        :param jpype.JInt or int width: is the maximum width to allow before wrapping
        :param jpype.JBoolean or bool breakOnWhiteSpace: determines whether line breaks should happen at white space chars
        :return: the wrapped elements
        :rtype: java.util.List[docking.widgets.fieldpanel.field.FieldElement]
        """


class FieldLocation(java.lang.Comparable[FieldLocation]):
    """
    Class to represent :obj:`Field` locations within the field viewer.
     
    
    A field location represents a place within a Field.  Fields live within a concept we call a
    layout.   A layout represents an 'item', for example an address, along with a grouping of
    related information.   Each layout will contain one or more Field objects.   Further, each
    layout's fields may have varying shapes, such as single or multiple rows within the layout.
    Thusly, a layout could conceptually represent a single line of text or multiple groupings of
    text and images, similar to how a newspaper or web page is laid out.
     
    
    A layout lives in a larger collection of layouts, which are laid out vertically.  The index of a
    layout is its position within that larger list.  This class contains the index of the layout
    within which it lives.
     
    
    A :obj:`FieldSelection` may be within a single layout or may cross multiple layouts.  To
    determine if a selection crosses multiple layouts, you can get the :obj:`range <FieldRange>` of
    the selection.   You can then use the range's start and end locations to determine if the
    selection spans multiple layouts.   If the start and end indexes of the range are the same, then
    the selection is within a single layout; otherwise, the selection spans multiple layouts.
     
    
    This location also contains row and column values.  These values refer to the row and column of
    text within a single Field.   Lastly, this class contains a field number, which represents the
    relative field number inside of the over layout, which may contain multiple fields.
    
    
    .. seealso::
    
        | :obj:`FieldSelection`
    
        | :obj:`FieldRange`
    
        | :obj:`Layout`
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX: typing.Final[FieldLocation]
    fieldNum: jpype.JInt
    row: jpype.JInt
    col: jpype.JInt

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, index: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, index: typing.Union[jpype.JInt, int], fieldNum: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, index: java.math.BigInteger):
        ...

    @typing.overload
    def __init__(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, index: typing.Union[jpype.JInt, int], fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Construct a new FieldLocation with the given index,fieldNum,row, and col.
        
        :param jpype.JInt or int index: the index of the layout containing the location
        :param jpype.JInt or int fieldNum: the index of the field in the layout containing the location
        :param jpype.JInt or int row: the text row in the field containing the location.
        :param jpype.JInt or int col: the character position the row containing the location.
        """

    @typing.overload
    def __init__(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, child: org.jdom.Element):
        ...

    @typing.overload
    def __init__(self, loc: FieldLocation):
        """
        Construct a new FieldLocation by copying from another FieldLocation.
        
        :param FieldLocation loc: the FieldLocation to be copied.
        """

    def getCol(self) -> int:
        """
        Returns the column within the Field for this location.
        
        :return: the column within the Field for this location.
        :rtype: int
        """

    def getElement(self, name: typing.Union[java.lang.String, str]) -> org.jdom.Element:
        ...

    def getFieldNum(self) -> int:
        """
        Returns the number of the field for this location.  This is the number of the field within
        a given layout.  See the javadoc header for more details.
        
        :return: the number of the field for this location.
        :rtype: int
        """

    def getIndex(self) -> java.math.BigInteger:
        """
        Returns the index for this location.  The index corresponds to the layout that contains
        the field represented by this location.  See the javadoc header for more details.
        
        :return: the index for this location.
        :rtype: java.math.BigInteger
        """

    def getRow(self) -> int:
        """
        Returns the row within the Field for this location.
        
        :return: the row within the Field for this location.
        :rtype: int
        """

    def set(self, loc: FieldLocation):
        ...

    def setIndex(self, index: java.math.BigInteger):
        ...

    @property
    def index(self) -> java.math.BigInteger:
        ...

    @index.setter
    def index(self, value: java.math.BigInteger):
        ...

    @property
    def element(self) -> org.jdom.Element:
        ...


class MultiRowLayout(docking.widgets.fieldpanel.Layout):
    """
    Handles layouts with multiple rows.
    """

    @typing.type_check_only
    class EmptyRowLayout(RowLayout):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, rowId: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
            ...


    class RowHeights(java.lang.Object):
        """
        A class to track all row heights for a given :obj:`MultiRowLayout`.   Multiple instances
        of this class can be merged to create a total collection of row heights for more than one
        :obj:`MultiRowLayout`, such as is done for the diff tool.  The merged row heights 
        represent the total number of rows possible as well as the maximum possible height for a 
        given row.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def merge(self, other: MultiRowLayout.RowHeights):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, layout: RowLayout, indexSize: typing.Union[jpype.JInt, int]):
        """
        Constructs a new MultiRowLayout with a single layout row.
        
        :param RowLayout layout: the single layout to add to this MultiRowLayout.
        :param jpype.JInt or int indexSize: the index size.
        """

    @typing.overload
    def __init__(self, layouts: jpype.JArray[RowLayout], indexSize: typing.Union[jpype.JInt, int]):
        ...

    def align(self, sharedRowHeights: MultiRowLayout.RowHeights):
        """
        Aligns the heights in this MultiRowLayout to match those in the given row heights array.  
        This is used by the diff provider to align two sets of rows.
        
        :param MultiRowLayout.RowHeights sharedRowHeights: the row heights
        """

    def getFirstRowID(self) -> int:
        ...

    def getRowHeights(self) -> MultiRowLayout.RowHeights:
        """
        Returns an object that contains all row heights for the row layouts in this class.
        
        :return: an object that contains all row heights for the row layouts in this class.
        :rtype: MultiRowLayout.RowHeights
        """

    @property
    def firstRowID(self) -> jpype.JInt:
        ...

    @property
    def rowHeights(self) -> MultiRowLayout.RowHeights:
        ...



__all__ = ["BackgroundColorModel", "RowColLocation", "AnchoredLayout", "SingleRowLayout", "ViewerPosition", "Highlight", "FieldSelection", "DefaultRowColLocation", "FieldSelectionHelper", "FieldRange", "RowLayout", "FieldHighlightFactory", "HoverProvider", "FieldUtils", "FieldLocation", "MultiRowLayout"]
