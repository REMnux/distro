from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.internal
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import docking.widgets.indexedscrollpane
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.accessibility # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


T = typing.TypeVar("T")


class FieldDescriptionProvider(java.lang.Object):
    """
    Provides descriptions for fields in a field panel
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self, loc: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field) -> str:
        """
        Gets a description for the given location and field.
        
        :param docking.widgets.fieldpanel.support.FieldLocation loc: the FieldLocation to get a description for
        :param docking.widgets.fieldpanel.field.Field field: the Field to get a description for
        :return: a String describing the given field location
        :rtype: str
        """


class FieldPanelOverLayoutListener(java.lang.Object):
    """
    A listener for field panel overlay events.
    
    
    .. seealso::
    
        | :obj:`FieldPanelOverLayoutManager`
    """

    class_: typing.ClassVar[java.lang.Class]

    def fieldLayout(self, ev: FieldPanelOverLayoutEvent):
        """
        The manager is about to layout a component over a field in the panel
        
        :param FieldPanelOverLayoutEvent ev: the event describing the layout
        """


class FieldPanel(javax.swing.JPanel, docking.widgets.indexedscrollpane.IndexedScrollable, docking.widgets.fieldpanel.listener.LayoutModelListener, javax.swing.event.ChangeListener):

    @typing.type_check_only
    class AccessibleFieldPanel(javax.swing.JComponent.AccessibleJComponent, javax.accessibility.AccessibleText):

        class_: typing.ClassVar[java.lang.Class]

        def cursorChanged(self, newCursorLoc: docking.widgets.fieldpanel.support.FieldLocation, trigger: docking.widgets.EventTrigger):
            ...

        def selectionChanged(self, currentSelection: docking.widgets.fieldpanel.support.FieldSelection, trigger: docking.widgets.EventTrigger):
            ...

        def setFieldDescriptionProvider(self, provider: FieldDescriptionProvider):
            ...

        def updateLayouts(self):
            ...


    @typing.type_check_only
    class FieldPanelMouseAdapter(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldPanelMouseMotionAdapter(java.awt.event.MouseMotionAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class KeyAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def handleKeyEvent(self, event: java.awt.event.KeyEvent):
            ...


    @typing.type_check_only
    class UpKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DownKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LeftKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RightKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HomeKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EndKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PageUpKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PageDownKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EnterKeyAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TabRightAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TabLeftAction(FieldPanel.KeyAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldPanelKeyAdapter(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FieldPanelFocusListener(java.awt.event.FocusListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MouseHandler(java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyHandler(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelectionHandler(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CursorHandler(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    MOUSEWHEEL_LINES_TO_SCROLL: typing.Final = 3

    @typing.overload
    def __init__(self, model: LayoutModel):
        ...

    @typing.overload
    def __init__(self, model: LayoutModel, name: typing.Union[java.lang.String, str]):
        ...

    def addFieldInputListener(self, listener: docking.widgets.fieldpanel.listener.FieldInputListener):
        ...

    def addFieldLocationListener(self, listener: docking.widgets.fieldpanel.listener.FieldLocationListener):
        ...

    def addFieldMouseListener(self, listener: docking.widgets.fieldpanel.listener.FieldMouseListener):
        ...

    def addFieldSelectionListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        ...

    def addHighlightListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        ...

    def addLayoutListener(self, listener: docking.widgets.fieldpanel.listener.LayoutListener):
        ...

    def addLiveFieldSelectionListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        """
        Adds a selection listener that will be notified while the selection is being created
        
        :param docking.widgets.fieldpanel.listener.FieldSelectionListener listener: the listener to be notified
        """

    def addViewListener(self, listener: docking.widgets.fieldpanel.listener.ViewListener):
        ...

    def center(self, location: docking.widgets.fieldpanel.support.FieldLocation):
        ...

    def clearHighlight(self):
        """
        Clears the marked area highlight;
        """

    def clearSelection(self):
        """
        Clears the selection;
        """

    def cursorBottomOfFile(self):
        ...

    def cursorDown(self):
        ...

    def cursorEnd(self):
        """
        Moves the cursor to the end of the line.
        """

    def cursorHome(self):
        """
        Moves the cursor to the beginning of the line.
        """

    def cursorLeft(self):
        ...

    def cursorRight(self):
        ...

    def cursorTopOfFile(self):
        ...

    def cursorUp(self):
        ...

    def dispose(self):
        """
        Cleans up resources when this FieldPanel is no longer needed.
        """

    def enableSelection(self, b: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def getBackgroundColor(self) -> java.awt.Color:
        """
        Returns the default background color.
        
        :return: the default background color.
        :rtype: java.awt.Color
        
        .. seealso::
        
            | :obj:`.getBackground()`
        """

    @typing.overload
    def getBackgroundColor(self, index: java.math.BigInteger) -> java.awt.Color:
        ...

    def getCurrentField(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    def getCursorBounds(self) -> java.awt.Rectangle:
        ...

    def getCursorLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    def getCursorOffset(self) -> int:
        """
        Returns the offset of the cursor from the top of the screen
        
        :return: the offset of the cursor from the top of the screen
        :rtype: int
        """

    def getCursorPoint(self) -> java.awt.Point:
        """
        Returns the point in pixels of where the cursor is located.
        
        :return: the point in pixels of where the cursor is located.
        :rtype: java.awt.Point
        """

    def getFieldAt(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], loc: docking.widgets.fieldpanel.support.FieldLocation) -> docking.widgets.fieldpanel.field.Field:
        """
        Returns the Field at the given x,y coordinates.
         
        
        Note the x,y must currently be visible on the screen or else this method will return null.
        
        :param jpype.JInt or int x: the x mouse coordinate in the component.
        :param jpype.JInt or int y: the y mouse coordinate in the component.
        :param docking.widgets.fieldpanel.support.FieldLocation loc: will be filled in with the FieldLocation for the given point. Values will be
                    undefined if the Field return value is null.
        :return: Field the Field object the point is over.
        :rtype: docking.widgets.fieldpanel.field.Field
        """

    def getFocusedCursorColor(self) -> java.awt.Color:
        """
        Returns the cursor color when this field panel is focused.
        
        :return: the cursor color when this field panel is focused.
        :rtype: java.awt.Color
        """

    def getForegroundColor(self) -> java.awt.Color:
        """
        Returns the foreground color.
        
        :return: the foreground color.
        :rtype: java.awt.Color
        """

    def getHighlight(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        """
        Returns the current highlight (marked area).
        
        :return: the current highlight (marked area).
        :rtype: docking.widgets.fieldpanel.support.FieldSelection
        """

    def getHighlightColor(self) -> java.awt.Color:
        """
        Returns the color color used as the background for highlighted items.
        
        :return: the color color used as the background for highlighted items.
        :rtype: java.awt.Color
        """

    def getHoverHandler(self) -> HoverHandler:
        """
        Returns the class responsible for triggering popups for this field panel.
        
        :return: the hover handler.
        :rtype: HoverHandler
        """

    def getLayoutModel(self) -> LayoutModel:
        ...

    def getLocationForPoint(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    def getNonFocusCursorColor(self) -> java.awt.Color:
        """
        Returns the cursor color when this field panel is not focused.
        
        :return: the cursor color when this field panel is not focused.
        :rtype: java.awt.Color
        """

    def getOffset(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> int:
        ...

    def getPointForLocation(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> java.awt.Point:
        ...

    def getSelection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        """
        Returns the current selection.
        
        :return: the current selection.
        :rtype: docking.widgets.fieldpanel.support.FieldSelection
        """

    def getSelectionColor(self) -> java.awt.Color:
        """
        Returns the color used as the background for selected items.
        
        :return: the color used as the background for selected items.
        :rtype: java.awt.Color
        """

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        """
        Returns a ViewerPosition object which contains the top of screen information.
         
        
        The ViewerPosition will have the index of the layout at the top of the screen and the yPos of
        that layout. For example, if the layout is completely displayed, yPos will be 0. If part of
        the layout is off the top off the screen, then yPos will have a negative value (indicating
        that it begins above the displayable part of the screen.
        
        :return: the position
        :rtype: docking.widgets.fieldpanel.support.ViewerPosition
        """

    def getVisibleEndLayout(self) -> docking.widgets.fieldpanel.support.AnchoredLayout:
        """
        Returns the last visible layout or null if there are no visible layouts
        
        :return: the last visible layout
        :rtype: docking.widgets.fieldpanel.support.AnchoredLayout
        """

    def getVisibleLayouts(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    def getVisibleStartLayout(self) -> docking.widgets.fieldpanel.support.AnchoredLayout:
        """
        Returns the first visible layout or null if there are no visible layouts
        
        :return: the first visible layout
        :rtype: docking.widgets.fieldpanel.support.AnchoredLayout
        """

    def goTo(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], alwaysCenterCursor: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the cursor to the given Field location and attempts to show that location in the center
        of the screen.
        
        :param java.math.BigInteger index: the index of the line to go to.
        :param jpype.JInt or int fieldNum: the field on the line to go to.
        :param jpype.JInt or int row: the row in the field to go to.
        :param jpype.JInt or int col: the column in the field to go to.
        :param jpype.JBoolean or bool alwaysCenterCursor: if true, centers cursor on screen. Otherwise, only centers cursor
                    if cursor is offscreen.
        """

    def isCursorOn(self) -> bool:
        """
        Returns the state of the cursor. True if on, false if off.
        
        :return: the state of the cursor. True if on, false if off.
        :rtype: bool
        """

    def isFocused(self) -> bool:
        ...

    def isLocationVisible(self, location: docking.widgets.fieldpanel.support.FieldLocation) -> bool:
        """
        Returns true if the given field location is rendered on the screen; false if scrolled
        offscreen
        
        :param docking.widgets.fieldpanel.support.FieldLocation location: the location
        :return: true if the location is on the screen
        :rtype: bool
        """

    def isStartDragOK(self) -> bool:
        ...

    def pageDown(self):
        ...

    def pageUp(self):
        ...

    def positionCursor(self, offset: typing.Union[jpype.JInt, int]):
        """
        Scrolls the view so that the cursor is at the given offset from the top of the screen
        
        :param jpype.JInt or int offset: the pixel distance from the top of the screen at which to scroll the display
                    such that the cursor is at that offset.
        """

    def removeFieldInputListener(self, listener: docking.widgets.fieldpanel.listener.FieldInputListener):
        ...

    def removeFieldLocationListener(self, listener: docking.widgets.fieldpanel.listener.FieldLocationListener):
        ...

    def removeFieldMouseListener(self, listener: docking.widgets.fieldpanel.listener.FieldMouseListener):
        ...

    def removeFieldSelectionListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        ...

    def removeHighlightListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        ...

    def removeLayoutListener(self, listener: docking.widgets.fieldpanel.listener.LayoutListener):
        ...

    def removeLiveFieldSelectionListener(self, listener: docking.widgets.fieldpanel.listener.FieldSelectionListener):
        """
        Removes the selection listener from being notified when the selection is being created
        
        :param docking.widgets.fieldpanel.listener.FieldSelectionListener listener: the listener to be removed from being notified
        """

    def removeViewListener(self, listener: docking.widgets.fieldpanel.listener.ViewListener):
        ...

    def scrollTo(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation):
        ...

    def scrollToCursor(self):
        ...

    def scrollView(self, viewAmount: typing.Union[jpype.JInt, int]):
        ...

    def setBackgroundColor(self, c: java.awt.Color):
        """
        Sets the default background color
        
        :param java.awt.Color c: the color to use for the background.
        """

    def setBackgroundColorModel(self, model: docking.widgets.fieldpanel.support.BackgroundColorModel):
        ...

    def setBlinkCursor(self, blinkCursor: typing.Union[java.lang.Boolean, bool]):
        ...

    def setCursorOn(self, cursorOn: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the cursor on or off.
         
        
        When the cursor is turned off, there is no visible cursor displayed on the screen.
        
        :param jpype.JBoolean or bool cursorOn: true turns the cursor on, false turns it off.
        """

    @typing.overload
    def setCursorPosition(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> bool:
        """
        Sets the cursorPosition to the given location.
        
        :param java.math.BigInteger index: the index of the Layout on which to place the cursor.
        :param jpype.JInt or int fieldNum: the index of the field within its layout on which to place the cursor.
        :param jpype.JInt or int row: the row within the field to place the cursor.
        :param jpype.JInt or int col: the col within the row to place the cursor.
        :return: true if the cursor changed
        :rtype: bool
        """

    @typing.overload
    def setCursorPosition(self, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], trigger: docking.widgets.EventTrigger) -> bool:
        """
        Sets the cursorPosition to the given location with the given trigger.
        
        :param java.math.BigInteger index: the index of the Layout on which to place the cursor.
        :param jpype.JInt or int fieldNum: the index of the field within its layout on which to place the cursor.
        :param jpype.JInt or int row: the row within the field to place the cursor.
        :param jpype.JInt or int col: the col within the row to place the cursor.
        :param docking.widgets.EventTrigger trigger: a caller-specified event trigger.
        :return: true if the cursor changed
        :rtype: bool
        """

    def setFieldDescriptionProvider(self, provider: FieldDescriptionProvider):
        ...

    def setFocusedCursorColor(self, color: java.awt.Color):
        """
        Sets the cursor color for when this component has focus.
        
        :param java.awt.Color color: Color to use for the cursor when this component has keyboard focus.
        """

    def setHighlight(self, sel: docking.widgets.fieldpanel.support.FieldSelection):
        """
        Sets the current highlight to the specified field selection.
        
        :param docking.widgets.fieldpanel.support.FieldSelection sel: the selection to set as the highlight.
        """

    def setHighlightColor(self, color: java.awt.Color):
        """
        Sets the highlight color
        
        :param java.awt.Color color: the color to use for highlights.
        """

    def setHorizontalScrollingEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setHoverProvider(self, hoverProvider: docking.widgets.fieldpanel.support.HoverProvider):
        """
        Add a new hover provider to be managed.
        
        :param docking.widgets.fieldpanel.support.HoverProvider hoverProvider: the new hover provider to be managed.
        """

    def setLayoutModel(self, model: LayoutModel):
        """
        Sets the layout model for this field panel
        
        :param LayoutModel model: the layout model to use.
        """

    def setNonFocusCursorColor(self, color: java.awt.Color):
        """
        Sets the cursor color for when this component does not have focus.
        
        :param java.awt.Color color: Color to use for the cursor when this component does not have keyboard focus.
        """

    @typing.overload
    def setSelection(self, sel: docking.widgets.fieldpanel.support.FieldSelection):
        """
        Sets the current selection.
        
        :param docking.widgets.fieldpanel.support.FieldSelection sel: the selection to set.
        """

    @typing.overload
    def setSelection(self, sel: docking.widgets.fieldpanel.support.FieldSelection, trigger: docking.widgets.EventTrigger):
        """
        Sets the current selection.
        
        :param docking.widgets.fieldpanel.support.FieldSelection sel: the selection to set.
        :param docking.widgets.EventTrigger trigger: the cause of the change
        """

    def setSelectionColor(self, color: java.awt.Color):
        """
        Sets the selection color
        
        :param java.awt.Color color: the color to use for selection.
        """

    def setViewerPosition(self, index: java.math.BigInteger, xPos: typing.Union[jpype.JInt, int], yPos: typing.Union[jpype.JInt, int]):
        """
        Scrolls the display to show the layout specified by index at the vertical position specified
        by yPos.
         
        
        Generally, the index will be layout at the top of the screen and the yPos will be <= 0,
        meaning the layout may be partially off the top of the screen.
        
        :param java.math.BigInteger index: the index of the layout to show at the top of the screen.
        :param jpype.JInt or int xPos: the x position to set.
        :param jpype.JInt or int yPos: the y position to set.
        """

    def tabLeft(self):
        ...

    def tabRight(self):
        ...

    def takeFocus(self):
        """
        Tell the panel to grab the keyboard input focus.
        """

    @property
    def cursorPoint(self) -> java.awt.Point:
        ...

    @property
    def selectionColor(self) -> java.awt.Color:
        ...

    @selectionColor.setter
    def selectionColor(self, value: java.awt.Color):
        ...

    @property
    def cursorOn(self) -> jpype.JBoolean:
        ...

    @cursorOn.setter
    def cursorOn(self, value: jpype.JBoolean):
        ...

    @property
    def focusedCursorColor(self) -> java.awt.Color:
        ...

    @focusedCursorColor.setter
    def focusedCursorColor(self, value: java.awt.Color):
        ...

    @property
    def highlight(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @highlight.setter
    def highlight(self, value: docking.widgets.fieldpanel.support.FieldSelection):
        ...

    @property
    def cursorLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...

    @property
    def locationVisible(self) -> jpype.JBoolean:
        ...

    @property
    def visibleLayouts(self) -> java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]:
        ...

    @property
    def pointForLocation(self) -> java.awt.Point:
        ...

    @property
    def hoverHandler(self) -> HoverHandler:
        ...

    @property
    def nonFocusCursorColor(self) -> java.awt.Color:
        ...

    @nonFocusCursorColor.setter
    def nonFocusCursorColor(self, value: java.awt.Color):
        ...

    @property
    def startDragOK(self) -> jpype.JBoolean:
        ...

    @property
    def visibleEndLayout(self) -> docking.widgets.fieldpanel.support.AnchoredLayout:
        ...

    @property
    def backgroundColor(self) -> java.awt.Color:
        ...

    @backgroundColor.setter
    def backgroundColor(self, value: java.awt.Color):
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition:
        ...

    @property
    def currentField(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def foregroundColor(self) -> java.awt.Color:
        ...

    @property
    def cursorBounds(self) -> java.awt.Rectangle:
        ...

    @property
    def highlightColor(self) -> java.awt.Color:
        ...

    @highlightColor.setter
    def highlightColor(self, value: java.awt.Color):
        ...

    @property
    def selection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @selection.setter
    def selection(self, value: docking.widgets.fieldpanel.support.FieldSelection):
        ...

    @property
    def focused(self) -> jpype.JBoolean:
        ...

    @property
    def layoutModel(self) -> LayoutModel:
        ...

    @layoutModel.setter
    def layoutModel(self, value: LayoutModel):
        ...

    @property
    def cursorOffset(self) -> jpype.JInt:
        ...

    @property
    def visibleStartLayout(self) -> docking.widgets.fieldpanel.support.AnchoredLayout:
        ...


class AccessibleField(javax.accessibility.AccessibleContext, javax.accessibility.Accessible, javax.accessibility.AccessibleComponent, javax.accessibility.AccessibleText):
    """
    Implements Accessible interfaces for individual fields in the field panel
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, field: docking.widgets.fieldpanel.field.Field, parent: javax.swing.JComponent, indexInParent: typing.Union[jpype.JInt, int], bounds: java.awt.Rectangle):
        """
        Constructor
        
        :param docking.widgets.fieldpanel.field.Field field: the field this is providing accessible access to
        :param javax.swing.JComponent parent: the component containing the field (FieldPanel)
        :param jpype.JInt or int indexInParent: the number of this field relative to the visible fields on the screen.
        :param java.awt.Rectangle bounds: the bounds of the field relative to the field panel.
        """

    def getField(self) -> docking.widgets.fieldpanel.field.Field:
        """
        Returns the field associated with this AccessibleField.
        
        :return: the field associated with this AccessibleField
        :rtype: docking.widgets.fieldpanel.field.Field
        """

    def getText(self) -> str:
        """
        Returns the text of the field
        
        :return: the text of the field
        :rtype: str
        """

    def getTextOffset(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> int:
        """
        Converts a row,col position to an text offset in the field
        
        :param jpype.JInt or int row: the row
        :param jpype.JInt or int col: the col
        :return: an offset into the text that represents the row,col position
        :rtype: int
        """

    def isSelected(self) -> bool:
        """
        Returns true if the field is currently part of a selection.
        
        :return: true if the field is currently part of a selection.
        :rtype: bool
        """

    def setCaretPos(self, caretPos: typing.Union[jpype.JInt, int]):
        """
        Sets the position of the cursor relative to the text in this field. It is only meaningful
        when the corresponding field is the field containing the field panel's actual cursor.
        
        :param jpype.JInt or int caretPos: the offset into the text of the field of where the cursor is being displayed
        by the field panel.
        """

    def setSelected(self, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Sets that this field is part of the overall selection.
        
        :param jpype.JBoolean or bool selected: true if the field is part of the selection; false otherwise
        """

    @property
    def field(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...


class AccessibleFieldPanelDelegate(java.lang.Object):
    """
    Contains all the code for implementing the AccessibleFieldPanel which is an inner class in
    the FieldPanel class. The AccessibleFieldPanel has to be declared as an inner class because
    it needs to extend AccessibleJComponent which is a non-static inner class of JComponent. 
    However, we did not want to put all the logic in there as FieldPanel is already an
    extremely large and complex class. Also, by delegating the logic, testing is much
    easier.
     
    
    The model for accessibility for the FieldPanel is a bit complex because
    the field panel displays text, but in a 2 dimensional array of fields, where each field
    has potentially 2 dimensional text.  So for the purpose of accessibility, the FieldPanel 
    acts as both a text field and a text component.
     
    
    To support screen readers reacting to cursor movements in the FieldPanel, the FieldPanel
    acts like a text field, but it acts like it only has the text of one inner Field at a time
    (The one where the cursor is). The other approach that was considered was to treat the field
    panel as a single text document. This would be difficult to implement because of the way fields
    are multi-lined. Also, the user of the screen reader would lose all concepts that there are
    fields. By maintaining the fields as a concept to the screen reader, it can provide more
    meaningful descriptions as the cursor is moved between fields. 
     
    
    The Field panel also acts as an :obj:`AccessibleComponent` with virtual children for each of its 
    visible fields. This is what allows screen readers to read the context of whatever the mouse
    is hovering over keeping the data separated by the field boundaries.
    """

    @typing.type_check_only
    class AccessibleLayout(java.lang.Object):
        """
        Wraps each AnchoredLayout to assist organizing the list of layouts into a single list
        of fields.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, layout: docking.widgets.fieldpanel.support.AnchoredLayout, startingFieldNum: typing.Union[jpype.JInt, int]):
            ...

        def createAccessibleField(self, fieldNum: typing.Union[jpype.JInt, int]) -> AccessibleField:
            """
            Creates the AccessibleField as needed.
            
            :param jpype.JInt or int fieldNum: the number of the field to create an AccessibleField for. This number
            is relative to all the fields in the field panel and not to this layout.
            :return: an AccessibleField for the given fieldNum
            :rtype: AccessibleField
            """

        def getFieldNum(self, p: java.awt.Point) -> int:
            """
            Returns the overall field number of the field containing the given point.
            
            :param java.awt.Point p: the point to find the field for
            :return: the overall field number of the field containing the given point.
            :rtype: int
            """

        def getIndex(self) -> java.math.BigInteger:
            """
            Returns the index of the layout as defined by the client code. The only requirements for
            indexes is that the index for a layout is always bigger then the index of the previous
            layout.
            
            :return: the index of the layout as defined by the client code.
            :rtype: java.math.BigInteger
            """

        def getStartingFieldNum(self) -> int:
            """
            Returns the overall field number of the first field in this layout. For example, 
            the first layout would have a starting field number of 0 and if it has 5 fields, the
            next layout would have a starting field number of 5 and so on.
            
            :return: the overall field number of the first field in this layout.
            :rtype: int
            """

        def getYpos(self) -> int:
            """
            Return the y position of this layout relative to the field panel.
            
            :return: the y position of this layout relative to the field panel.
            :rtype: int
            """

        @property
        def ypos(self) -> jpype.JInt:
            ...

        @property
        def index(self) -> java.math.BigInteger:
            ...

        @property
        def fieldNum(self) -> jpype.JInt:
            ...

        @property
        def startingFieldNum(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, layouts: java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout], context: javax.accessibility.AccessibleContext, panel: FieldPanel):
        ...

    def getAccessibleAt(self, p: java.awt.Point) -> javax.accessibility.Accessible:
        """
        Returns the :obj:`AccessibleField` that is at the given point relative to the FieldPanel.
        
        :param java.awt.Point p: the point to get an Accessble child at
        :return: the :obj:`AccessibleField` that is at the given point relative to the FieldPanel
        :rtype: javax.accessibility.Accessible
        """

    @typing.overload
    def getAccessibleField(self, fieldNum: typing.Union[jpype.JInt, int]) -> AccessibleField:
        """
        Returns the n'th AccessibleField that is visible on the screen.
        
        :param jpype.JInt or int fieldNum: the number of the field to get
        :return: the n'th AccessibleField that is visible on the screen
        :rtype: AccessibleField
        """

    @typing.overload
    def getAccessibleField(self, loc: docking.widgets.fieldpanel.support.FieldLocation) -> AccessibleField:
        """
        Returns the AccessibleField associated with the given field location.
        
        :param docking.widgets.fieldpanel.support.FieldLocation loc: the FieldLocation to get the visible field for
        :return: the AccessibleField associated with the given field location
        :rtype: AccessibleField
        """

    def getAfterIndex(self, part: typing.Union[jpype.JInt, int], index: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the char, word, or sentence after the given char index.
        
        :param jpype.JInt or int part: specifies char, word or sentence (See :obj:`AccessibleText`)
        :param jpype.JInt or int index: the character index to get data for
        :return: the char, word, or sentence after the given char index
        :rtype: str
        """

    def getAtIndex(self, part: typing.Union[jpype.JInt, int], index: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the char, word, or sentence at the given char index.
        
        :param jpype.JInt or int part: specifies char, word or sentence (See :obj:`AccessibleText`)
        :param jpype.JInt or int index: the character index to get data for
        :return: the char, word, or sentences at the given char index
        :rtype: str
        """

    def getBeforeIndex(self, part: typing.Union[jpype.JInt, int], index: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the char, word, or sentence at the given char index.
        
        :param jpype.JInt or int part: specifies char, word or sentence (See :obj:`AccessibleText`)
        :param jpype.JInt or int index: the character index to get data for
        :return: the char, word, or sentence at the given char index
        :rtype: str
        """

    def getCaretPosition(self) -> int:
        """
        Returns the caret position relative the current active field.
        
        :return: the caret position relative the current active field
        :rtype: int
        """

    def getCharCount(self) -> int:
        """
        Returns the number of characters in the current active field.
        
        :return: the number of characters in the current active field.
        :rtype: int
        """

    def getCharacterBounds(self, index: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        """
        Return the bounds relative to the field panel for the character at the given index
        
        :param jpype.JInt or int index: the index of the character in the active field whose bounds is to be returned.
        :return: the bounds relative to the field panel for the character at the given index
        :rtype: java.awt.Rectangle
        """

    def getFieldCount(self) -> int:
        """
        Returns the number of visible field showing on the screen in the field panel.
        
        :return: the number of visible field showing on the screen in the field panel
        :rtype: int
        """

    def getFieldDescription(self) -> str:
        """
        Returns a description of the current field
        
        :return: a description of the current field
        :rtype: str
        """

    def getIndexAtPoint(self, p: java.awt.Point) -> int:
        """
        Returns the character index at the given point relative to the FieldPanel. Note this
        only returns chars in the active field.
        
        :param java.awt.Point p: the point to get the character for
        :return: the character index at the given point relative to the FieldPanel.
        :rtype: int
        """

    def getSelectedText(self) -> str:
        """
        Returns either null if the field is not selected or the full field text if it is selected.
        
        :return: either null if the field is not selected or the full field text if it is selected
        :rtype: str
        """

    def getSelectionEnd(self) -> int:
        """
        Returns the selection character end index. This is either 0, indicating there is no selection
        or the index at the end of the text meaning the entire field is selected.
        
        :return: the selection character start index.
        :rtype: int
        """

    def getSelectionStart(self) -> int:
        """
        Returns the selection character start index. This currently always returns 0 as
        selections are all or nothing.
        
        :return: the selection character start index.
        :rtype: int
        """

    def setCaret(self, newCursorLoc: docking.widgets.fieldpanel.support.FieldLocation, trigger: docking.widgets.EventTrigger):
        """
        Tells this delegate that the cursor moved. It updates its internal state and fires
        events to the accessibility system.
        
        :param docking.widgets.fieldpanel.support.FieldLocation newCursorLoc: the new FieldLoation of the cursor
        :param docking.widgets.EventTrigger trigger: the event trigger
        """

    def setFieldDescriptionProvider(self, provider: FieldDescriptionProvider):
        """
        Sets the :obj:`FieldDescriptionProvider` that can generate descriptions of the current
        field.
        
        :param FieldDescriptionProvider provider: the description provider
        """

    def setLayouts(self, layouts: java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]):
        """
        Whenever the set of visible layouts changes, the field panel rebuilds its info for the
        new visible fields and notifies the accessibility system that its children changed.
        
        :param java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout] layouts: the new set of visible layouts.
        """

    def setSelection(self, currentSelection: docking.widgets.fieldpanel.support.FieldSelection, trigger: docking.widgets.EventTrigger):
        """
        Tells this delegate that the selection has changed. If the current field is in the selection,
        it sets the current AccessibleField to be selected. (A field is either entirely selected
        or not)
        
        :param docking.widgets.fieldpanel.support.FieldSelection currentSelection: the new current field panel selection
        :param docking.widgets.EventTrigger trigger: the event trigger
        """

    @property
    def fieldCount(self) -> jpype.JInt:
        ...

    @property
    def selectionStart(self) -> jpype.JInt:
        ...

    @property
    def charCount(self) -> jpype.JInt:
        ...

    @property
    def selectedText(self) -> java.lang.String:
        ...

    @property
    def accessibleAt(self) -> javax.accessibility.Accessible:
        ...

    @property
    def caretPosition(self) -> jpype.JInt:
        ...

    @property
    def selectionEnd(self) -> jpype.JInt:
        ...

    @property
    def indexAtPoint(self) -> jpype.JInt:
        ...

    @property
    def fieldDescription(self) -> java.lang.String:
        ...

    @property
    def accessibleField(self) -> AccessibleField:
        ...

    @property
    def characterBounds(self) -> java.awt.Rectangle:
        ...


class LayoutModel(java.lang.Iterable[Layout]):
    """
    The Big Layout Model interface.  Objects that implement this interface can be dispayed
    using a BigFieldPanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addLayoutModelListener(self, listener: docking.widgets.fieldpanel.listener.LayoutModelListener):
        """
        Adds a LayoutModelListener to be notified when changes occur.
        
        :param docking.widgets.fieldpanel.listener.LayoutModelListener listener: the LayoutModelListener to add.
        """

    def flushChanges(self):
        """
        Returns true if the model knows about changes that haven't yet been told to the 
        LayoutModelListeners.
        """

    def getIndexAfter(self, index: java.math.BigInteger) -> java.math.BigInteger:
        """
        Returns the closest larger index in the model that has a non-null layout.
        
        :param java.math.BigInteger index: for which to find the next index with a non-null layout.
        :return: returns the closest larger index in the model that has a non-null layout.
        :rtype: java.math.BigInteger
        """

    def getIndexBefore(self, index: java.math.BigInteger) -> java.math.BigInteger:
        """
        Returns the closest smaller index in the model that has a non-null layout.
        
        :param java.math.BigInteger index: for which to find the previous index with a non-null layout.
        :return: returns the closest smaller index in the model that has a non-null layout.
        :rtype: java.math.BigInteger
        """

    def getLayout(self, index: java.math.BigInteger) -> Layout:
        """
        Returns a layout for the given index.
        
        :param java.math.BigInteger index: the index of the layout to retrieve.
        """

    def getNumIndexes(self) -> java.math.BigInteger:
        """
        Returns the total number of indexes.
        """

    def getPreferredViewSize(self) -> java.awt.Dimension:
        """
        Returns the width of the largest possible layout.
        """

    def isUniform(self) -> bool:
        """
        Returns true if every index returns a non-null layout and all the layouts
        are the same height.
        """

    @typing.overload
    def iterator(self) -> LayoutModelIterator:
        """
        Returns an iterator that walks all the Layout items in this model.
        
        :return: new iterator
        :rtype: LayoutModelIterator
        """

    @typing.overload
    def iterator(self, startIndex: java.math.BigInteger) -> LayoutModelIterator:
        """
        Returns an iterator that walks all the Layout items in this model, starting at the
        specified index.
        
        :param java.math.BigInteger startIndex: start index in the model to beginning iterating
        :return: new iterator
        :rtype: LayoutModelIterator
        """

    def removeLayoutModelListener(self, listener: docking.widgets.fieldpanel.listener.LayoutModelListener):
        """
        Removes a LayoutModelListener to be notified when changes occur.
        
        :param docking.widgets.fieldpanel.listener.LayoutModelListener listener: the LayoutModelListener to remove.
        """

    @property
    def layout(self) -> Layout:
        ...

    @property
    def uniform(self) -> jpype.JBoolean:
        ...

    @property
    def indexAfter(self) -> java.math.BigInteger:
        ...

    @property
    def preferredViewSize(self) -> java.awt.Dimension:
        ...

    @property
    def numIndexes(self) -> java.math.BigInteger:
        ...

    @property
    def indexBefore(self) -> java.math.BigInteger:
        ...


class LayoutModelIterator(java.util.Iterator[Layout]):
    """
    An :obj:`Iterator` returning :obj:`Layout` objects that hides the details of using :obj:`LayoutModel`'s
    indexing methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, layoutModel: LayoutModel):
        ...

    @typing.overload
    def __init__(self, layoutModel: LayoutModel, startIndex: java.math.BigInteger):
        ...

    def getIndex(self) -> java.math.BigInteger:
        """
        Returns the LayoutModel index of the item that was just returned via :meth:`next() <.next>`.
        
        :return: index of the last Layout item returned.
        :rtype: java.math.BigInteger
        """

    def getNextIndex(self) -> java.math.BigInteger:
        """
        Returns the LayoutModel index of the next item that will be returned via :meth:`next() <.next>`.
        
        :return: index of the next Layout item returned, or null if no additional items are present
        :rtype: java.math.BigInteger
        """

    def getPreviousIndex(self) -> java.math.BigInteger:
        """
        Returns the LayoutModel index of the previous item that was returned via :meth:`next() <.next>`.
        
        :return: index of the previous Layout item returned, or null if this iterator hasn't been
        used yet.
        :rtype: java.math.BigInteger
        """

    @property
    def index(self) -> java.math.BigInteger:
        ...

    @property
    def nextIndex(self) -> java.math.BigInteger:
        ...

    @property
    def previousIndex(self) -> java.math.BigInteger:
        ...


class HoverHandler(java.awt.event.ActionListener):

    class_: typing.ClassVar[java.lang.Class]

    def hoverExited(self):
        """
        Call this when the mouse is no longer over the hover source
        """

    def isEnabled(self) -> bool:
        ...

    def isHoverShowing(self) -> bool:
        ...

    def mouseHovered(self, e: java.awt.event.MouseEvent):
        ...

    def scroll(self, scrollAmount: typing.Union[jpype.JInt, int]):
        ...

    def setHoverProvider(self, hoverProvider: docking.widgets.fieldpanel.support.HoverProvider):
        ...

    def startHover(self, e: java.awt.event.MouseEvent):
        ...

    def stopHover(self):
        ...

    @property
    def hoverShowing(self) -> jpype.JBoolean:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...


class FieldPanelOverLayoutEvent(java.lang.Object):
    """
    An event related to component layout over a :obj:`FieldPanel`.
    
    
    .. seealso::
    
        | :obj:`FieldPanelOverLayoutManager`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, field: docking.widgets.fieldpanel.field.Field, loc: docking.widgets.fieldpanel.support.FieldLocation, component: java.awt.Component):
        """
        Create a new event on the given field, location, and component.
        
        :param docking.widgets.fieldpanel.field.Field field: the field that will have a component placed over it
        :param docking.widgets.fieldpanel.support.FieldLocation loc: the location of the field
        :param java.awt.Component component: the component to be placed over the field
        """

    def cancel(self):
        """
        Prevent the actual layout from taking place.
         
        Further listeners may still process this event, though.
        """

    def consume(self):
        """
        Prevent this event from being further processed.
         
        The actual layout will still occur, though.
        """

    def getComponent(self) -> java.awt.Component:
        """
        Get the component to be placed over the field
        
        :return: the component
        :rtype: java.awt.Component
        """

    def getField(self) -> docking.widgets.fieldpanel.field.Field:
        """
        Get the field that will have a component placed over it
        
        :return: the field
        :rtype: docking.widgets.fieldpanel.field.Field
        """

    def getLocation(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        """
        Get the field location
        
        :return: the location of the field
        :rtype: docking.widgets.fieldpanel.support.FieldLocation
        """

    def isCancelled(self) -> bool:
        """
        Check if the actual layout will be performed.
        
        :return: true if the layout has been cancelled.
        :rtype: bool
        """

    def isConsumed(self) -> bool:
        """
        Check if this event has been consumed by an earlier listener.
        
        :return: true if the event has been consumed, i.e., should not be further processed
        :rtype: bool
        """

    @property
    def consumed(self) -> jpype.JBoolean:
        ...

    @property
    def component(self) -> java.awt.Component:
        ...

    @property
    def field(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def location(self) -> docking.widgets.fieldpanel.support.FieldLocation:
        ...


class Layout(java.lang.Object):
    """
    Interface for a set of data fields that represent one indexable set of information
    in the model. The fields in a layout are arranged into rows.  The height of the
    row is the height of the tallest field in that row.  Each field contains one or
    more lines of text.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, yPos: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given yPos lies within this layout.
        
        :param jpype.JInt or int yPos: the vertical coordinate to check if in this layout.
        """

    def cursorBeginning(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation) -> int:
        """
        Sets the given FieldLocation as far to the left as possible.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified.
        :return: the x coordinate of the cursor after the operation.
        :rtype: int
        """

    def cursorDown(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation, lastX: typing.Union[jpype.JInt, int]) -> bool:
        """
        Moves the cursor up down row from its current position.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified
        :param jpype.JInt or int lastX: the x coordinate of the cursor before the move.
        :return: true if the cursor was successfully moved down without leaving the layout.
        :rtype: bool
        """

    def cursorEnd(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation) -> int:
        """
        Sets the given FieldLocation as far to the right as possible.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified.
        :return: the x coordinate of the cursor after the operation.
        :rtype: int
        """

    def cursorLeft(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation) -> int:
        """
        Sets the given FieldLocation one position to the left.  If already at the
        left most position, it tries to move to the end of the previous row.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified.
        :return: the x coordinate of the cursor after the operation.  Returns -1 if
        it was already at the top, left most position.
        :rtype: int
        """

    def cursorRight(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation) -> int:
        """
        Sets the given FieldLocation one position to the right.  If already at the
        right most position, it tries to move to the beginning of the next row.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified.
        :return: the x coordinate of the cursor after the operation.  Returns -1 if
        it was already at the bottom, right most position.
        :rtype: int
        """

    def cursorUp(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation, lastX: typing.Union[jpype.JInt, int]) -> bool:
        """
        Moves the cursor up one row from its current position.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the cursor location object to be modified
        :param jpype.JInt or int lastX: the x coordinate of the cursor before the move.
        :return: true if the cursor was successfully moved up without leaving the layout.
        :rtype: bool
        """

    def enterLayout(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation, lastX: typing.Union[jpype.JInt, int], fromTop: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Tries to move the cursor into this layout.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the field location to hold new location.
        :param jpype.JInt or int lastX: the last valid x coordinate.
        :param jpype.JBoolean or bool fromTop: true if entering from the above this layout
        :return: true if the cursor successfully moves into this layout.
        :rtype: bool
        """

    def getBeginRowFieldNum(self, field1: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getCompressableWidth(self) -> int:
        """
        Returns the smallest possible width of this layout that can display its full contents
        
        :return: the smallest possible width of this layout that can display its full contents
        :rtype: int
        """

    def getCursorRect(self, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        """
        Returns a rectangle which bounds the given cursor position.
        
        :param jpype.JInt or int fieldNum: the index of the field containing the cursor position.
        :param jpype.JInt or int row: the text row in the field containing the cursor position.
        :param jpype.JInt or int col: the character position in the row containing the cursor position.
        """

    def getEndRowFieldNum(self, field2: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getField(self, index: typing.Union[jpype.JInt, int]) -> docking.widgets.fieldpanel.field.Field:
        """
        Returns the i'th Field in this Layout.
        
        :param jpype.JInt or int index: the index of the field to retrieve.
        """

    def getFieldBounds(self, index: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        """
        Returns the bounds of the given field (in coordinates relative to the layout)
        
        :param jpype.JInt or int index: the field id for the field for which to get bounds
        """

    def getFieldIndex(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the index of the field at the given coordinates (relative to the layout)
        
        :param jpype.JInt or int x: the x coordinate
        :param jpype.JInt or int y: the y coordinate
        :return: the index of the field at the given coordinates (relative to the layout)
        :rtype: int
        """

    def getHeight(self) -> int:
        """
        Returns the total height of this layout.
        """

    def getIndexSize(self) -> int:
        """
        Returns the number of indexes consumed by this layout.
        """

    def getNumFields(self) -> int:
        """
        Returns the number of Fields in this Layout.
        """

    def getPrimaryOffset(self) -> int:
        """
        Returns the vertical offset (in pixels) of the start of the primary
        field in the layout.
        
        :return: -1 if layout does not have a primary field.
        :rtype: int
        """

    def getScrollableUnitIncrement(self, topOfScreen: typing.Union[jpype.JInt, int], direction: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the amount to scroll to reveal the line of text.
        
        :param jpype.JInt or int topOfScreen: the y coordinate that represents the top or bottom of
        the screen
        :param jpype.JInt or int direction: the direction to scroll
        """

    def insertSpaceAbove(self, size: typing.Union[jpype.JInt, int]):
        """
        Inserts empty space above the layout
        
        :param jpype.JInt or int size: the amount of space to insert above the layout
        """

    def insertSpaceBelow(self, size: typing.Union[jpype.JInt, int]):
        """
        Inserts empty space below the layout
        
        :param jpype.JInt or int size: the amount of space to insert below the layout
        """

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, context: docking.widgets.fieldpanel.internal.PaintContext, rect: java.awt.Rectangle, layoutColorMap: docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager, cursorLocation: docking.widgets.fieldpanel.support.FieldLocation):
        """
        Paints this layout on the screen.
        
        :param java.awt.Graphics g: The graphics context with which to paint.
        :param docking.widgets.fieldpanel.internal.PaintContext context: contains various information needed to do the paint
        :param java.awt.Rectangle rect: the screen area that needs to be painted.
        :param docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager layoutColorMap: indicates where the selection exists
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLocation: the location of the cursor or null if the cursor is not in this layout
        """

    def setCursor(self, cursorLoc: docking.widgets.fieldpanel.support.FieldLocation, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> int:
        """
        Sets the cursor to the given point location.  The cursor will be positioned
        to the row column position that is closest to the given point.
        
        :param docking.widgets.fieldpanel.support.FieldLocation cursorLoc: the location that is to be filled in.
        :param jpype.JInt or int x: the x coordinate of the point to be translated into a cursor location.
        :param jpype.JInt or int y: the y coordinate of the point to be translated into a cursor location.
        :return: the x coordinated of the computed cursor location.
        :rtype: int
        """

    @property
    def fieldBounds(self) -> java.awt.Rectangle:
        ...

    @property
    def field(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def primaryOffset(self) -> jpype.JInt:
        ...

    @property
    def beginRowFieldNum(self) -> jpype.JInt:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...

    @property
    def indexSize(self) -> jpype.JInt:
        ...

    @property
    def endRowFieldNum(self) -> jpype.JInt:
        ...

    @property
    def compressableWidth(self) -> jpype.JInt:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class FieldPanelOverLayoutManager(java.awt.LayoutManager2):
    """
    A :obj:`LayoutManager` that can be applied to a :obj:`FieldPanel`, allowing :obj:`Component`s
    to be placed over a given field location.
     
     
    
    To apply it, use :meth:`Container.setLayout(LayoutManager) <Container.setLayout>` to install it. In this case, the
    :obj:`Container` must be a :obj:`FieldPanel`. Then, use
    :meth:`Container.add(Component, Object) <Container.add>`, passing a :obj:`FieldLocation` as the constraint.
    Currently, you must call :meth:`layoutContainer(Container) <.layoutContainer>` manually after you add or remove any
    components.
     
     
    
    When this layout manager is removed from the :obj:`FieldPanel`, you should call
    :meth:`unregister() <.unregister>` in order to dispose of internal resources.
    """

    @typing.type_check_only
    class MyListener(docking.widgets.fieldpanel.listener.LayoutListener):
        """
        A listener for callbacks on the :obj:`FieldPanel`'s field layout changing.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fieldpane: FieldPanel):
        ...

    def addLayoutListener(self, listener: FieldPanelOverLayoutListener):
        """
        Add a listener for overlay layout events
        
        :param FieldPanelOverLayoutListener listener: the listener to add
        """

    def getLayoutListeners(self) -> jpype.JArray[FieldPanelOverLayoutListener]:
        """
        Get the list of register overlay layout event listeners
        
        :return: the array
        :rtype: jpype.JArray[FieldPanelOverLayoutListener]
        """

    def getListeners(self, listenerType: java.lang.Class[T]) -> jpype.JArray[T]:
        ...

    def removeLayoutListener(self, listener: FieldPanelOverLayoutListener):
        """
        Remove a listener for overlay layout events
        
        :param FieldPanelOverLayoutListener listener: the listener to remove
        """

    def unregister(self):
        """
        Remove my callbacks from the :obj:`FieldPanel`
        """

    @property
    def listeners(self) -> jpype.JArray[T]:
        ...

    @property
    def layoutListeners(self) -> jpype.JArray[FieldPanelOverLayoutListener]:
        ...



__all__ = ["FieldDescriptionProvider", "FieldPanelOverLayoutListener", "FieldPanel", "AccessibleField", "AccessibleFieldPanelDelegate", "LayoutModel", "LayoutModelIterator", "HoverHandler", "FieldPanelOverLayoutEvent", "Layout", "FieldPanelOverLayoutManager"]
