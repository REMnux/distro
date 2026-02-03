from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.internal
import docking.widgets.fieldpanel.support
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ClippingTextField(TextField):
    """
    Field for showing multiple strings, each with its own attributes in a field,
    on a single line, clipping as needed to fit within the field's width. Has the
    extra methods for mapping column positions to strings and positions in those
    strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], textElement: FieldElement, hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        Constructs a new ClippingTextField that allows the cursor beyond the end
        of the line.
        
        :param jpype.JInt or int startX: The x position of the field
        :param jpype.JInt or int width: The width of the field
        :param FieldElement textElement: The AttributedStrings to display in the field.
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: The HighlightFactory object used to paint highlights.
        """

    @typing.overload
    def __init__(self, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], textElement: FieldElement, numDataRows: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        Constructs a new ClippingTextField that allows the cursor beyond the end
        of the line.
         
         
        This constructor allows clients to specify the number of data rows that have been
        converted into a single screen row.
        
        :param jpype.JInt or int startX: The x position of the field
        :param jpype.JInt or int width: The width of the field
        :param FieldElement textElement: The AttributedStrings to display in the field.
        :param jpype.JInt or int numDataRows: the number of data rows represented by this single screen row field
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: The HighlightFactory object used to paint highlights.
        """

    def getClickedObject(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation) -> java.lang.Object:
        ...

    def isClipped(self) -> bool:
        """
        Returns true if the text is clipped (truncated)
        """

    def screenToDataLocation(self, screenRow: typing.Union[jpype.JInt, int], screenColumn: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Converts a single column value into a MultiStringLocation which specifies
        a string index and a column position within that string.
        
        :param jpype.JInt or int screenColumn: the overall column position in the total String.
        :return: MultiStringLocation the MultiStringLocation corresponding to the
                given column.
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    @property
    def clickedObject(self) -> java.lang.Object:
        ...

    @property
    def clipped(self) -> jpype.JBoolean:
        ...


class WrappingVerticalLayoutTextField(VerticalLayoutTextField):
    """
    A text field meant to take a string of text and wrap as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, textElement: FieldElement, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        This constructor will create a text field from an single AttributedString.  The string will
        be word wrapped.
        
        :param FieldElement textElement: the element to display
        :param jpype.JInt or int startX: the x position to draw the string
        :param jpype.JInt or int width: the max width allocated to this field
        :param jpype.JInt or int maxLines: the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: the highlight factory
        """

    @typing.overload
    def __init__(self, textElement: FieldElement, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory, breakOnWhiteSpace: typing.Union[jpype.JBoolean, bool]):
        """
        This constructor will create a text field from an single AttributedString.  The string will
        be word wrapped.
        
        :param FieldElement textElement: is the element to display
        :param jpype.JInt or int startX: is the position to draw the string
        :param jpype.JInt or int width: is the max width allocated to this field
        :param jpype.JInt or int maxLines: is the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: is the highlight factory
        :param jpype.JBoolean or bool breakOnWhiteSpace: is true if wrapping should break on word boundaries
        """


class FieldElement(java.lang.Object):
    """
    Used by :obj:`Field`s to combine text, attributes and location information (for example to and
    from screen and data locations).  FieldFactory classes can use the various implementations
    of this interface, or create new ones, to include additional information specific to the fields
    that they create.
    """

    class_: typing.ClassVar[java.lang.Class]

    def charAt(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the character at the given index.
        
        :param jpype.JInt or int index: the index of the character in this field element.
        :return: the character at the given index.
        :rtype: str
        """

    def getCharacterIndexForDataLocation(self, dataRow: typing.Union[jpype.JInt, int], dataColumn: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the character index appropriate for the given data location
        
        :param jpype.JInt or int dataRow: the row in the data model as determined by the creating field factory.
        :param jpype.JInt or int dataColumn: the column in the data model as determined by the creating field factory.
        :return: the character index appropriate for the given data location; -1 if this field does
                not contain the given location
        :rtype: int
        """

    def getColor(self, charIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        """
        Returns the color for a given character within this element, since different colors may be
        applied to different characters.
        
        :param jpype.JInt or int charIndex: The character index
        :return: the color for a given character within this element.
        :rtype: java.awt.Color
        """

    def getDataLocationForCharacterIndex(self, characterIndex: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Translates the given character index to a data location related to the data model, as
        determined by the FieldFactory.
        
        :param jpype.JInt or int characterIndex: The character index to translate.
        :return: The data location in the model coordinates.
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    def getFieldElement(self, column: typing.Union[jpype.JInt, int]) -> FieldElement:
        """
        Returns the inner-most FieldElement inside this field element at the given location
        
        :param jpype.JInt or int column: the character offset.
        :return: the inner-most FieldElement inside this field element at the given location
        :rtype: FieldElement
        """

    def getHeightAbove(self) -> int:
        """
        Returns the amount of height above the baseline of this element.
        
        :return: the amount of height above the baseline of this element.
        :rtype: int
        """

    def getHeightBelow(self) -> int:
        """
        Returns the amount of height below the baseline of this element.
        
        :return: the amount of height below the baseline of this element.
        :rtype: int
        """

    def getMaxCharactersForWidth(self, width: typing.Union[jpype.JInt, int]) -> int:
        """
        As the name implies, this method returns the maximum number of characters from this field
        element that will fit within the given width.
        
        :param jpype.JInt or int width: The width constraint
        :return: the maximum number of characters from this field element that will fit within
        the given width.
        :rtype: int
        """

    def getStringWidth(self) -> int:
        """
        Returns the string width of this element.  The width is based upon the associated
        FontMetrics object within this element.
        
        :return: the string width of this element.
        :rtype: int
        """

    def getText(self) -> str:
        """
        Returns the text contained by this field element.
        
        :return: the text contained by this field element.
        :rtype: str
        """

    def length(self) -> int:
        """
        Returns the length of the text within this element.  This is a convenience method for
        calling ``getText().length()``.
        
        :return: the length of the text within this element.
        :rtype: int
        """

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        Paints the text contained in this field element at the given x,y screen coordinate using the
        given Graphics object.
        
        :param javax.swing.JComponent c: the component being painted.
        :param java.awt.Graphics g: the Graphics object used to paint the field text.
        :param jpype.JInt or int x: the horizontal screen position to paint
        :param jpype.JInt or int y: the vertical screen position to paint.
        """

    def replaceAll(self, targets: jpype.JArray[jpype.JChar], replacement: typing.Union[jpype.JChar, int, str]) -> FieldElement:
        """
        Returns a new FieldElement with all occurrences of the target characters replaced with the
        given replacement character.
        
        :param jpype.JArray[jpype.JChar] targets: The array of characters to replace.
        :param jpype.JChar or int or str replacement: The replacement character.
        :return: a new FieldElement with all occurrences of the target characters replaced with the
        given replacement character.
        :rtype: FieldElement
        """

    @typing.overload
    def substring(self, start: typing.Union[jpype.JInt, int]) -> FieldElement:
        """
        Returns a new FieldElement containing just the characters beginning at the given index.
        
        :param jpype.JInt or int start: The starting index (inclusive) from which to substring this element.
        :return: a new FieldElement containing just the characters beginning at the given index.
        :rtype: FieldElement
        """

    @typing.overload
    def substring(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> FieldElement:
        """
        Returns a new FieldElement containing just the characters beginning at the given start
        index (inclusive) and ending at the given end index (exclusive).
        
        :param jpype.JInt or int start: The starting index (inclusive) from which to substring this element.
        :param jpype.JInt or int end: The end index (exclusive) to which the substring will be performed.
        :return: a new FieldElement containing just the characters beginning at the given index.
        :rtype: FieldElement
        """

    @property
    def stringWidth(self) -> jpype.JInt:
        ...

    @property
    def heightBelow(self) -> jpype.JInt:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def dataLocationForCharacterIndex(self) -> docking.widgets.fieldpanel.support.RowColLocation:
        ...

    @property
    def fieldElement(self) -> FieldElement:
        ...

    @property
    def maxCharactersForWidth(self) -> jpype.JInt:
        ...

    @property
    def heightAbove(self) -> jpype.JInt:
        ...


class FlowLayoutTextField(VerticalLayoutTextField):
    """
    This class provides a TextField implementation that takes multiple AttributedString field
    elements and places as many that will fit on a line without clipping before continuing to the
    next line.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    @deprecated("use the constructor that takes a list")
    def __init__(self, textElements: jpype.JArray[FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        This constructor will create a text field that will render one line of text. If
        ``metrics.stringWidth(text) > width``, then the text will be wrapped.
        If ``text`` contains the highlight string, then it will be highlighted using the
        highlight color.
        
        :param jpype.JArray[FieldElement] textElements: the AttributedStrings to display
        :param jpype.JInt or int startX: the x position to draw the string
        :param jpype.JInt or int width: the max width allocated to this field
        :param jpype.JInt or int maxLines: the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: the highlight factory
        
        .. deprecated::
        
        use the constructor that takes a list
        """

    @typing.overload
    def __init__(self, elements: java.util.List[FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        This constructor will create a text field that will render one line of text. If
        ``metrics.stringWidth(text) > width``, then the text will be wrapped.
        If ``text`` contains the highlight string, then it will be highlighted using the
        highlight color.
        
        :param java.util.List[FieldElement] elements: the AttributedStrings to display
        :param jpype.JInt or int startX: the x position to draw the string
        :param jpype.JInt or int width: the max width allocated to this field
        :param jpype.JInt or int maxLines: the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: the highlight factory
        """


class VerticalLayoutTextField(TextField):
    """
    This class provides a TextField implementation that takes multiple FieldElements and places
    each on its own line within the field.
    """

    @typing.type_check_only
    class FieldRow(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    @deprecated("use the constructor that takes a list")
    def __init__(self, textElements: jpype.JArray[FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        This constructor will create a text field from an array of FieldElements, putting each
        element on its own line.
        
        :param jpype.JArray[FieldElement] textElements: the FieldElements to display
        :param jpype.JInt or int startX: the x position to draw the element
        :param jpype.JInt or int width: the max width allocated to this field
        :param jpype.JInt or int maxLines: the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: the highlight factory
        
        .. deprecated::
        
        use the constructor that takes a list
        """

    @typing.overload
    def __init__(self, textElements: java.util.List[FieldElement], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        This constructor will create a text field from an array of FieldElements, putting each
        element on its own line.
        
        :param java.util.List[FieldElement] textElements: the FieldElements to display
        :param jpype.JInt or int startX: the x position to draw the element
        :param jpype.JInt or int width: the max width allocated to this field
        :param jpype.JInt or int maxLines: the max number of lines to display
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: the highlight factory
        """

    def setPrimary(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the primary State.
        
        :param jpype.JBoolean or bool state: the state to set.
        """


class EmptyTextField(Field):
    """
    A Text field that is blank.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, heightAbove: typing.Union[jpype.JInt, int], heightBelow: typing.Union[jpype.JInt, int], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int]):
        """
        Constructs a new EmptyTextField
        
        :param jpype.JInt or int heightAbove: the height above the baseline of the text field.
        :param jpype.JInt or int heightBelow: the height below the baseline of the text field.
        :param jpype.JInt or int startX: the starting x coordinate.
        :param jpype.JInt or int width: the width of the field.
        the end of the text.
        """

    def getForeground(self) -> java.awt.Color:
        """
        Get the foreground color.
        
        :return: Color could return null if the setForeground() method was
        not called, and if this method is called before the paint() method
        was called.
        :rtype: java.awt.Color
        """

    def isAllowCursorAtEnd(self) -> bool:
        """
        Returns true if the cursor is allowed past the last character.  This
        field always returns false since there is no text.
        
        :return: true if the cursor is allowed past the last character
        :rtype: bool
        """

    def setForeground(self, color: java.awt.Color):
        """
        Sets the foreground color which isn't used by objects of this class
        
        :param java.awt.Color color: the new foreground color.
        """

    def setPrimary(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the primary state for this field
        
        :param jpype.JBoolean or bool state: the state to set the primary property.
        """

    @property
    def allowCursorAtEnd(self) -> jpype.JBoolean:
        ...

    @property
    def foreground(self) -> java.awt.Color:
        ...

    @foreground.setter
    def foreground(self, value: java.awt.Color):
        ...


class AbstractTextFieldElement(FieldElement):
    """
    An object that wraps a string and provides data that describes how to render
    that string.
     
    
    This class was created as a place to house attributes of rendering that
    are not described by Java's Font object, like underlining.
    """

    class_: typing.ClassVar[java.lang.Class]


class Field(java.lang.Object):
    """
    Interface for display fields used by the FieldPanel
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given point is in this field
        
        :param jpype.JInt or int x: the horizontal coordinate of the point
        :param jpype.JInt or int y: the relative y position in this layout
        :return: true if the given point is in this field
        :rtype: bool
        """

    def getCol(self, row: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the cursor column position for the given x coordinate on the given row
        
        :param jpype.JInt or int row: the text row to find the column on
        :param jpype.JInt or int x: the horizontal pixel coordinate for which to find the character position
        :return: the column
        :rtype: int
        """

    def getCursorBounds(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        """
        Returns a bounding rectangle for the cursor at the given position
        
        :param jpype.JInt or int row: the text row
        :param jpype.JInt or int col: the character position
        :return: the rectangle
        :rtype: java.awt.Rectangle
        """

    def getHeight(self) -> int:
        """
        Returns the height of this field when populated with the given data
        
        :return: the height
        :rtype: int
        """

    def getHeightAbove(self) -> int:
        """
        Returns the height above the baseLine
        
        :return: the height above
        :rtype: int
        """

    def getHeightBelow(self) -> int:
        """
        Returns the height below the baseLine
        
        :return: the height below
        :rtype: int
        """

    def getNumCols(self, row: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the number of columns in the given row
        
        :param jpype.JInt or int row: the row from which to get the number of columns; this is the screen row
        :return: the number of columns
        :rtype: int
        """

    def getNumDataRows(self) -> int:
        """
        Returns the number of data model rows represented by this field.  Some fields may change
        the row count by wrapping or truncating.  The value returned here will be the original data
        row count before any transformations were applied.
        
        :return: the number of data rows
        :rtype: int
        """

    def getNumRows(self) -> int:
        """
        Returns the number of rows in this field
        
        :return: the number of rows in this field
        :rtype: int
        """

    def getPreferredWidth(self) -> int:
        """
        The minimum required width to paint the contents of this field
        
        :return: the minimum required width to paint the contents of this field
        :rtype: int
        """

    def getRow(self, y: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the row containing the given y coordinate
        
        :param jpype.JInt or int y: vertical pixel coordinate relative to the top of the screen
        :return: the row
        :rtype: int
        """

    def getScrollableUnitIncrement(self, topOfScreen: typing.Union[jpype.JInt, int], direction: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the amount to scroll to the next or previous line
        
        :param jpype.JInt or int topOfScreen: the current y position of the top of the screen
        :param jpype.JInt or int direction: the direction of the scroll (1 down, -1 up)
        :param jpype.JInt or int max: the maximum amount to scroll for the entire row - will be positive for down, and
                negative for up)
        :return: the scroll amount
        :rtype: int
        """

    def getStartX(self) -> int:
        """
        Returns the horizontal position of this field
        
        :return: the position
        :rtype: int
        """

    def getText(self) -> str:
        """
        Returns a string containing all the text in the field
        
        :return: the string
        :rtype: str
        """

    def getTextWithLineSeparators(self) -> str:
        """
        Returns a string containing all the text in the field with extra newlines
        
        :return: a string containing all the text in the field with extra newlines
        :rtype: str
        """

    def getWidth(self) -> int:
        """
        Returns the current width of this field
        
        :return: the current width of this field
        :rtype: int
        """

    def getX(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the x coordinate for the given cursor position
        
        :param jpype.JInt or int row: the text row of interest
        :param jpype.JInt or int col: the character column
        :return: the x value
        :rtype: int
        """

    def getY(self, row: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the y coordinate for the given row
        
        :param jpype.JInt or int row: the text row of interest
        :return: the y value
        :rtype: int
        """

    def isPrimary(self) -> bool:
        """
        Returns true if this field is "primary" (the most important) field;  used to determine the
        "primary" line in the layout
        
        :return: true if this field is "primary"
        :rtype: bool
        """

    def isValid(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given row and column represent a valid location for this field with
        the given data
        
        :param jpype.JInt or int row: the text row
        :param jpype.JInt or int col: the character position
        :return: true if valid
        :rtype: bool
        """

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, context: docking.widgets.fieldpanel.internal.PaintContext, clip: java.awt.Rectangle, colorManager: docking.widgets.fieldpanel.internal.FieldBackgroundColorManager, cursorLoc: docking.widgets.fieldpanel.support.RowColLocation, rowHeight: typing.Union[jpype.JInt, int]):
        """
        Paints this field
        
        :param javax.swing.JComponent c: the component to paint onto
        :param java.awt.Graphics g: the graphics context
        :param docking.widgets.fieldpanel.internal.PaintContext context: common paint parameters
        :param java.awt.Rectangle clip: the clipping region to paint into
        :param docking.widgets.fieldpanel.internal.FieldBackgroundColorManager colorManager: contains background color information for the field
        :param docking.widgets.fieldpanel.support.RowColLocation cursorLoc: the row,column cursor location within the field or null if the field does
        not contain the cursor
        :param jpype.JInt or int rowHeight: the number of pixels in each row of text in the field
        """

    def rowHeightChanged(self, heightAbove: typing.Union[jpype.JInt, int], heightBelow: typing.Union[jpype.JInt, int]):
        """
        notifies field that the rowHeight changed
        
        :param jpype.JInt or int heightAbove: the height above the baseline
        :param jpype.JInt or int heightBelow: the height below the baseline
        """

    def screenLocationToTextOffset(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the text offset in the overall field text string for the given row and column
        
        :param jpype.JInt or int row: the row
        :param jpype.JInt or int col: the column
        :return: the offset
        :rtype: int
        """

    def textOffsetToScreenLocation(self, textOffset: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Returns the row, column position  for an offset into the string returned by getText()
        
        :param jpype.JInt or int textOffset: the offset into the entire text string for this field
        :return: a RowColLocation that contains the row,column location in the field for a position in
                the overall field text
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    @property
    def preferredWidth(self) -> jpype.JInt:
        ...

    @property
    def numRows(self) -> jpype.JInt:
        ...

    @property
    def numCols(self) -> jpype.JInt:
        ...

    @property
    def heightBelow(self) -> jpype.JInt:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def y(self) -> jpype.JInt:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def startX(self) -> jpype.JInt:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def numDataRows(self) -> jpype.JInt:
        ...

    @property
    def textWithLineSeparators(self) -> java.lang.String:
        ...

    @property
    def primary(self) -> jpype.JBoolean:
        ...

    @property
    def heightAbove(self) -> jpype.JInt:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class SimpleTextField(Field):
    """
    The simplest possible Text field.  It does not clip and should only be used
    when the text values always fit in field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, text: typing.Union[java.lang.String, str], fontMetrics: java.awt.FontMetrics, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], allowCursorAtEnd: typing.Union[jpype.JBoolean, bool], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        Constructs a new SimpleTextField.
        
        :param java.lang.String or str text: The text for the field.
        :param java.awt.FontMetrics fontMetrics: the fontMetrics used to render the text.
        :param jpype.JInt or int startX: the starting x coordinate.
        :param jpype.JInt or int width: the width of the field.
        :param jpype.JBoolean or bool allowCursorAtEnd: if true, allows the cursor to go one position past
        the end of the text.
        """

    def getFontMetrics(self) -> java.awt.FontMetrics:
        """
        Get the font metrics for this field.
        """

    def getForeground(self) -> java.awt.Color:
        """
        Get the foreground color.
        
        :return: Color could return null if the setForeground() method was
        not called, and if this method is called before the paint() method
        was called.
        :rtype: java.awt.Color
        """

    def isAllowCursorAtEnd(self) -> bool:
        """
        Returns true if the cursor is allow to be position past the last character.
        """

    def setFontMetrics(self, metrics: java.awt.FontMetrics):
        """
        Sets the font metrics
        
        :param java.awt.FontMetrics metrics: the fontmetrics to use.
        """

    def setForeground(self, color: java.awt.Color):
        """
        Set the foreground color for this field.
        
        :param java.awt.Color color: the new foreground color.
        """

    def setPrimary(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this primary state of this field.
        
        :param jpype.JBoolean or bool state: if true, then makes this field primary.
        """

    @property
    def allowCursorAtEnd(self) -> jpype.JBoolean:
        ...

    @property
    def foreground(self) -> java.awt.Color:
        ...

    @foreground.setter
    def foreground(self, value: java.awt.Color):
        ...

    @property
    def fontMetrics(self) -> java.awt.FontMetrics:
        ...

    @fontMetrics.setter
    def fontMetrics(self, value: java.awt.FontMetrics):
        ...


class TextFieldElement(AbstractTextFieldElement):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, attributedString: AttributedString, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]):
        ...


class ReverseClippingTextField(TextField):
    """
    Field for showing multiple strings, each with its own attributes in a field,
    on a single line, clipping the beginning of the text as needed to fit within the field's width.
    Has the extra methods for mapping column positions to strings and positions in those
    strings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], textElement: FieldElement, hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        """
        Constructs a new ReverseClippingTextField that allows the cursor beyond the end
        of the line. This is just a pass through constructor that makes the call:
         
         
        this(startX, width, new AttributedString[] { textElement }, hlFactory, true);
         
        
        :param jpype.JInt or int startX: The x position of the field
        :param jpype.JInt or int width: The width of the field
        :param FieldElement textElement: The AttributedStrings to display in the field.
        :param docking.widgets.fieldpanel.support.FieldHighlightFactory hlFactory: The HighlightFactory object used to paint highlights.
        """

    def isClipped(self) -> bool:
        """
        Returns true if the text is clipped (truncated)
        """

    def screenToDataLocation(self, screenRow: typing.Union[jpype.JInt, int], screenColumn: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Converts a single column value into a MultiStringLocation which specifies
        a string index and a column position within that string.
        
        :param jpype.JInt or int screenColumn: the overall column position in the total String.
        :return: MultiStringLocation the MultiStringLocation corresponding to the
                given column.
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    @property
    def clipped(self) -> jpype.JBoolean:
        ...


class TextField(Field):

    class_: typing.ClassVar[java.lang.Class]

    def dataToScreenLocation(self, dataRow: typing.Union[jpype.JInt, int], dataColumn: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Translates a data row and column into a screen row and column.
        
        :param jpype.JInt or int dataRow: row as defined by the factory
        :param jpype.JInt or int dataColumn: the character offset into the dataRow
        :return: row and column in the screen coordinate system; a :obj:`DefaultRowColLocation` if
                this field does not contain the given column
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    def getFieldElement(self, screenRow: typing.Union[jpype.JInt, int], screenColumn: typing.Union[jpype.JInt, int]) -> FieldElement:
        """
        Returns the FieldElement at the given screen location.
        
        :param jpype.JInt or int screenRow: the row on the screen
        :param jpype.JInt or int screenColumn: the column on the screen
        :return: the FieldElement at the given screen location.
        :rtype: FieldElement
        """

    def isClipped(self) -> bool:
        """
        Returns true if the field is not displaying all the text information
        
        :return: true if the field is not displaying all the text information
        :rtype: bool
        """

    def screenToDataLocation(self, screenRow: typing.Union[jpype.JInt, int], screenColumn: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.RowColLocation:
        """
        Translates a screen coordinate to a row and column in the data from the factory
        
        :param jpype.JInt or int screenRow: the row in the displayed field text.
        :param jpype.JInt or int screenColumn: the column in the displayed field text.
        :return: a RowColLocation containing the row and column within the data from the factory.
        :rtype: docking.widgets.fieldpanel.support.RowColLocation
        """

    def setPrimary(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this field to be primary such that its row is primary
        
        :param jpype.JBoolean or bool b: this field to be primary such that its row is primary
        """

    @property
    def clipped(self) -> jpype.JBoolean:
        ...


class CompositeFieldElement(FieldElement):
    """
    A FieldElement that is composed of other FieldElements.  The elements are laid out horizontally.
    """

    @typing.type_check_only
    class IndexedOffset(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, elements: java.util.List[FieldElement]):
        ...

    @typing.overload
    def __init__(self, fieldElements: jpype.JArray[FieldElement]):
        ...

    def getNumElements(self) -> int:
        """
        Returns the number of sub-elements contained in this field
        
        :return: the number of sub-elements contained in this field
        :rtype: int
        """

    @property
    def numElements(self) -> jpype.JInt:
        ...


class AttributedString(java.lang.Object):
    """
    An object that wraps a string and provides data that describes how to render
    that string.
     
    
    This class was created as a place to house attributes of rendering that
    are not described by Java's Font object, like underlining.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], textColor: java.awt.Color, fontMetrics: java.awt.FontMetrics):
        """
        Creates an attributed string with the given text, color and metrics with
        no other attributes, like highlighting or underlining.
        
        :param java.lang.String or str text: The text that this class describes.
        :param java.awt.Color textColor: The color to paint the text.
        :param java.awt.FontMetrics fontMetrics: The font metrics used to draw the text.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], textColor: java.awt.Color, fontMetrics: java.awt.FontMetrics, underline: typing.Union[jpype.JBoolean, bool], underlineColor: java.awt.Color):
        """
        Creates an attributed string with the given text, color and metrics with
        other attributes, like highlighting and underlining.
        
        :param java.lang.String or str text: The text that this class describes.
        :param java.awt.Color textColor: The color to paint the text.
        :param java.awt.FontMetrics fontMetrics: The font metrics used to draw the text.
        :param jpype.JBoolean or bool underline: True if ``text`` should be underlined.
        :param java.awt.Color underlineColor: the color to use for underlining.
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, text: typing.Union[java.lang.String, str], textColor: java.awt.Color, fontMetrics: java.awt.FontMetrics, underline: typing.Union[jpype.JBoolean, bool], underlineColor: java.awt.Color):
        """
        Creates an attributed string with the given text, color, icon and metrics with
        other attributes, like highlighting and underlining.
        
        :param javax.swing.Icon icon: icon image to be displayed to the left of the text
        :param java.lang.String or str text: The text that this class describes.
        :param java.awt.Color textColor: The color to paint the text.
        :param java.awt.FontMetrics fontMetrics: The font metrics used to draw the text.
        :param jpype.JBoolean or bool underline: True if ``text`` should be underlined.
        :param java.awt.Color underlineColor: the color to use for underlining.
        """

    def deriveAttributedString(self, newText: typing.Union[java.lang.String, str]) -> AttributedString:
        ...

    def getCharPosition(self, x: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getColor(self, charIndex: typing.Union[jpype.JInt, int]) -> java.awt.Color:
        ...

    def getFontMetrics(self, charIndex: typing.Union[jpype.JInt, int]) -> java.awt.FontMetrics:
        ...

    def getHeightAbove(self) -> int:
        ...

    def getHeightBelow(self) -> int:
        ...

    def getIcon(self) -> javax.swing.Icon:
        ...

    def getStringWidth(self) -> int:
        ...

    def getText(self) -> str:
        ...

    def length(self) -> int:
        ...

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    def replaceAll(self, targets: jpype.JArray[jpype.JChar], repacement: typing.Union[jpype.JChar, int, str]) -> AttributedString:
        ...

    @typing.overload
    def substring(self, start: typing.Union[jpype.JInt, int]) -> AttributedString:
        ...

    @typing.overload
    def substring(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]) -> AttributedString:
        ...

    @property
    def stringWidth(self) -> jpype.JInt:
        ...

    @property
    def heightBelow(self) -> jpype.JInt:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def charPosition(self) -> jpype.JInt:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def fontMetrics(self) -> java.awt.FontMetrics:
        ...

    @property
    def heightAbove(self) -> jpype.JInt:
        ...


class StrutFieldElement(FieldElement):
    """
    Used to force a clip to happen by using this field with space characters and size that far
    exceeds the available painting width.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, baseElement: FieldElement, width: typing.Union[jpype.JInt, int]):
        """
        Constructor. Clients may choose to pass
        
        :param FieldElement baseElement: the base type replaced by this strut; may be null if no type is being
        replaced
        :param jpype.JInt or int width: the width of this strut class
        """

    def getBaseType(self) -> FieldElement:
        """
        Returns the base type replaced by this strut; may be null
        
        :return: the base type replaced by this strut; may be null
        :rtype: FieldElement
        """

    @property
    def baseType(self) -> FieldElement:
        ...


class CompositeAttributedString(AttributedString):
    """
    An AttributedString that is composed of other AttributedStrings.
    """

    @typing.type_check_only
    class IndexedOffset(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, stringList: java.util.List[AttributedString]):
        ...

    @typing.overload
    def __init__(self, *attributedStrings: AttributedString):
        ...


class SimpleImageField(Field):
    """
    Field to display an image.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, metrics: java.awt.FontMetrics, startX: typing.Union[jpype.JInt, int], startY: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int]):
        """
        Constructs a new field for displaying an image.
        
        :param javax.swing.Icon icon: the image icon to display
        :param java.awt.FontMetrics metrics: the font metrics
        :param jpype.JInt or int startX: the starting x coordinate of the field.
        :param jpype.JInt or int startY: the starting y coordinate of the field.
        :param jpype.JInt or int width: the width of the field.
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, metrics: java.awt.FontMetrics, startX: typing.Union[jpype.JInt, int], startY: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], center: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new field for displaying an image.
        
        :param javax.swing.Icon icon: the image icon to display
        :param java.awt.FontMetrics metrics: the font metrics
        :param jpype.JInt or int startX: the starting x coordinate of the field.
        :param jpype.JInt or int startY: the starting y coordinate of the field.
        :param jpype.JInt or int width: the width of the field.
        :param jpype.JBoolean or bool center: flag to center the image in the field.
        """

    def setPrimary(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the primary state of this field
        
        :param jpype.JBoolean or bool state: true if this field is primary, false otherwise.
        """


class CompositeVerticalLayoutTextField(TextField):
    """
    A :obj:`TextField` that takes in other TextFields.
     
     
    This class allows clients to create custom text layout behavior by combining individual
    TextFields that dictate layout behavior.  As an example, consider this rendering:
     
        1)  This is some text...
        2)    This
            is
            more
            text
     
    In this example, 1) is a row of text inside of a :obj:`ClippingTextField`.  Row 2) is a
    multi-line text rendering specified in a single :obj:`FlowLayoutTextField`, using a
    narrow width to trigger the field to place each element on its own line.
    """

    @typing.type_check_only
    class FieldRow(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fields: java.util.List[TextField], startX: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], maxLines: typing.Union[jpype.JInt, int], hlFactory: docking.widgets.fieldpanel.support.FieldHighlightFactory):
        ...

    def getRowSeparator(self) -> str:
        ...

    @property
    def rowSeparator(self) -> java.lang.String:
        ...



__all__ = ["ClippingTextField", "WrappingVerticalLayoutTextField", "FieldElement", "FlowLayoutTextField", "VerticalLayoutTextField", "EmptyTextField", "AbstractTextFieldElement", "Field", "SimpleTextField", "TextFieldElement", "ReverseClippingTextField", "TextField", "CompositeFieldElement", "AttributedString", "StrutFieldElement", "CompositeAttributedString", "SimpleImageField", "CompositeVerticalLayoutTextField"]
