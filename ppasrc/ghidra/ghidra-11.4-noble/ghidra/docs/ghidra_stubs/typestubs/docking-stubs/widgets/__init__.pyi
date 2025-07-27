from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.label
import docking.widgets.list
import docking.widgets.shapes
import docking.widgets.table
import generic.theme.laf
import ghidra.security
import ghidra.util
import ghidra.util.bean
import ghidra.util.task
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore
import utility.function


T = typing.TypeVar("T")
T1 = typing.TypeVar("T1")


@typing.type_check_only
class VariableHeightLayoutManager(java.awt.LayoutManager):
    ...
    class_: typing.ClassVar[java.lang.Class]


class PasswordDialog(docking.DialogComponentProvider):
    """
    ``PasswordDialog`` is a modal dialog which 
    prompts a user for a password.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], passPrompt: typing.Union[java.lang.String, str], allowUserIdEntry: typing.Union[jpype.JBoolean, bool], userIdPrompt: typing.Union[java.lang.String, str], defaultUserId: typing.Union[java.lang.String, str], choicePrompt: typing.Union[java.lang.String, str], choices: jpype.JArray[java.lang.String], defaultChoice: typing.Union[jpype.JInt, int], includeAnonymousOption: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PasswordDialog which may include user ID specification/prompt, if either
        ``allowUserIdEntry`` is true or a non-null ``defaultUserId`` has been specified, and 
        other optional elements.  The dialog includes a message text area which supports the use 
        of :meth:`setErrorText(String) <.setErrorText>`.
        
        :param java.lang.String or str title: title of the dialog
        :param java.lang.String or str serverType: 'Server' or 'Key-store' designation
        :param java.lang.String or str serverName: name of server or keystore pathname
        :param java.lang.String or str passPrompt: password prompt to show in the dialog; may be null/empty, in which case
        "Password:" is displayed next to the password field
        :param jpype.JBoolean or bool allowUserIdEntry: if true user ID entry will be supported
        :param java.lang.String or str userIdPrompt: User ID / Name prompt to show in the dialog, if null "User ID:" is prompt
        if either ``allowUserIdEntry`` is true or a non-null ``defaultUserId`` has been specified.
        :param java.lang.String or str defaultUserId: default name when prompting for a name
        :param java.lang.String or str choicePrompt: namePrompt name prompt to show in the dialog, if null a name will not be prompted for.
        :param jpype.JArray[java.lang.String] choices: array of choices to present if choicePrompt is not null
        :param jpype.JInt or int defaultChoice: default choice index
        :param jpype.JBoolean or bool includeAnonymousOption: true signals to add a checkbox to request anonymous login
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], passPrompt: typing.Union[java.lang.String, str]):
        """
        Construct a new PasswordDialog which only prompts for a password for a specified server
        type and name.  The dialog will not include a User ID display, although server fields 
        may be used for a similar display purpose.  The dialog includes a message text area
        which supports the use of :meth:`setErrorText(String) <.setErrorText>`.
        
        :param java.lang.String or str title: title of the dialog
        :param java.lang.String or str serverType: 'Server' or 'Key-store' designation
        :param java.lang.String or str serverName: name of server or keystore pathname
        :param java.lang.String or str passPrompt: password prompt to show in the dialog; may be null, in which case
        "Password:" is prompt.
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], passPrompt: typing.Union[java.lang.String, str], hasMessages: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PasswordDialog which only prompts for a password for a specified server
        type and name.  The dialog will not include a User ID display, although server fields 
        may be used for a similar display purpose.  The dialog optionally includes a message 
        text area which supports the use of :meth:`setErrorText(String) <.setErrorText>`.
        
        :param java.lang.String or str title: title of the dialog
        :param java.lang.String or str serverType: 'Server' or 'Key-store' designation
        :param java.lang.String or str serverName: name of server or keystore pathname
        :param java.lang.String or str passPrompt: password prompt to show in the dialog; may be null, in which case
        "Password:" is displayed next to the password field
        :param jpype.JBoolean or bool hasMessages: true if a message text area should be included allowing for use of
        :meth:`setErrorText(String) <.setErrorText>`
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], passPrompt: typing.Union[java.lang.String, str], allowUserIdEntry: typing.Union[jpype.JBoolean, bool], userIdPrompt: typing.Union[java.lang.String, str], defaultUserId: typing.Union[java.lang.String, str], hasMessages: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PasswordDialog which may include user ID specification/prompt if either
        ``allowUserIdEntry`` is true or a non-null ``defaultUserId`` has been specified.
        The dialog optionally includes a message text area which supports the use of 
        :meth:`setErrorText(String) <.setErrorText>`.
        
        :param java.lang.String or str title: title of the dialog
        :param java.lang.String or str serverType: 'Server' or 'Key-store' designation
        :param java.lang.String or str serverName: name of server or keystore pathname
        :param java.lang.String or str passPrompt: password prompt to show in the dialog; may be null/empty, in which case
        "Password:" is displayed next to the password field
        :param jpype.JBoolean or bool allowUserIdEntry: if true user ID entry will be supported
        :param java.lang.String or str userIdPrompt: User ID / Name prompt to show in the dialog, if null "User ID:" is prompt
        if either ``allowUserIdEntry`` is true or a non-null ``defaultUserId`` has been specified.
        :param java.lang.String or str defaultUserId: default name when prompting for a name
        :param jpype.JBoolean or bool hasMessages: true if a message text area should be included allowing for use of
        :meth:`setErrorText(String) <.setErrorText>`
        """

    def anonymousAccessRequested(self) -> bool:
        """
        Returns true if anonymous access is requested
        
        :return: true if anonymous access requested
        :rtype: bool
        """

    def getChoice(self) -> int:
        """
        Returns index of selected choice or -1 if no choice has been made
        
        :return: index of selected choice or -1 if no choice has been made
        :rtype: int
        """

    def getPassword(self) -> jpype.JArray[jpype.JChar]:
        """
        Return the password entered in the password field.
        
        :return: the password chars
        :rtype: jpype.JArray[jpype.JChar]
        """

    def getUserID(self) -> str:
        """
        Return the user ID / Name entered in the password field
        
        :return: the user ID / Name entered in the password field
        :rtype: str
        """

    def okWasPressed(self) -> bool:
        """
        Returns true if the OK button was pressed.
        
        :return: true if the OK button was pressed.
        :rtype: bool
        """

    def setErrorText(self, text: typing.Union[java.lang.String, str]):
        """
        Display error status
        
        :param java.lang.String or str text: the text
        """

    @property
    def password(self) -> jpype.JArray[jpype.JChar]:
        ...

    @property
    def choice(self) -> jpype.JInt:
        ...

    @property
    def userID(self) -> java.lang.String:
        ...


class DropDownTextFieldDataModel(java.lang.Object, typing.Generic[T]):
    """
    This interface represents all methods needed by the :obj:`DropDownSelectionTextField` in order
    to search, show, manipulate and select objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self, value: T) -> str:
        """
        Returns a description for this item that gives that will be displayed along side of the
        :obj:`DropDownSelectionTextField`'s matching window.
        
        :param T value: the value.
        :return: the description.
        :rtype: str
        """

    def getDisplayText(self, value: T) -> str:
        """
        Returns the text for the given item that will be entered into the 
        :obj:`DropDownSelectionTextField` when the user makes a selection.
        
        :param T value: the value.
        :return: the description.
        :rtype: str
        """

    def getIndexOfFirstMatchingEntry(self, data: java.util.List[T], text: typing.Union[java.lang.String, str]) -> int:
        """
        Returns the index in the given list of the first item that matches the given text.  For 
        data sets that do not allow duplicates, this is simply the index of the item that matches
        the text in the list.  For items that allow duplicates, the is the index of the first match.
        
        :param java.util.List[T] data: the list to search.
        :param java.lang.String or str text: the text to match against the items in the list.
        :return: the index in the given list of the first item that matches the given text.
        :rtype: int
        """

    def getListRenderer(self) -> javax.swing.ListCellRenderer[T]:
        """
        Returns the renderer to be used to paint the contents of the list returned by 
        :meth:`getMatchingData(String) <.getMatchingData>`.
        
        :return: the renderer.
        :rtype: javax.swing.ListCellRenderer[T]
        """

    def getMatchingData(self, searchText: typing.Union[java.lang.String, str]) -> java.util.List[T]:
        """
        Returns a list of data that matches the given ``searchText``.  A match typically 
        means a "startsWith" match.  A list is returned to allow for multiple matches.
        
        :param java.lang.String or str searchText: The text used to find matches.
        :return: a list of items matching the given text.
        :rtype: java.util.List[T]
        """

    @property
    def displayText(self) -> java.lang.String:
        ...

    @property
    def matchingData(self) -> java.util.List[T]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def listRenderer(self) -> javax.swing.ListCellRenderer[T]:
        ...


class DataToStringConverter(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]
    stringDataToStringConverter: typing.Final[DataToStringConverter[java.lang.String]]

    def getString(self, t: T) -> str:
        ...

    @property
    def string(self) -> java.lang.String:
        ...


class DropDownSelectionChoiceListener(java.lang.Object, typing.Generic[T]):
    """
    A listener that is called when the user makes a selection from the 
    :obj:`DropDownSelectionTextField` (e.g., they click an item or press enter on a selected 
    item and the matching window is closed).
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectionChanged(self, t: T):
        ...


class SearchLocation(java.lang.Object):
    """
    An object that describes a search result.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startIndexInclusive: typing.Union[jpype.JInt, int], endIndexInclusive: typing.Union[jpype.JInt, int], searchText: typing.Union[java.lang.String, str], forwardDirection: typing.Union[jpype.JBoolean, bool]):
        ...

    def getCursorPosition(self) -> CursorPosition:
        ...

    def getEndIndexInclusive(self) -> int:
        ...

    def getMatchLength(self) -> int:
        ...

    def getSearchText(self) -> str:
        ...

    def getStartIndexInclusive(self) -> int:
        ...

    def isForwardDirection(self) -> bool:
        ...

    @property
    def searchText(self) -> java.lang.String:
        ...

    @property
    def cursorPosition(self) -> CursorPosition:
        ...

    @property
    def startIndexInclusive(self) -> jpype.JInt:
        ...

    @property
    def endIndexInclusive(self) -> jpype.JInt:
        ...

    @property
    def forwardDirection(self) -> jpype.JBoolean:
        ...

    @property
    def matchLength(self) -> jpype.JInt:
        ...


@typing.type_check_only
class SingleRowLayoutManager(VariableHeightLayoutManager):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SelectFromListDialog(docking.DialogComponentProvider, typing.Generic[T]):
    """
    Dialog that presents the user with a list of strings and returns the object
    associated with the user-picked element.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], list: java.util.List[T], toStringFunc: java.util.function.Function[T, java.lang.String]):
        ...

    def getSelectedObject(self) -> T:
        ...

    @staticmethod
    def selectFromList(list: java.util.List[T], title: typing.Union[java.lang.String, str], prompt: typing.Union[java.lang.String, str], toStringFunction: java.util.function.Function[T, java.lang.String]) -> T:
        """
        Modally shows the user a dialog with a list of strings, and returns the picked object.
         
        
        (automatically switches to Swing thread)
        
        :param java.util.List[T] list: list of object of type T
        :param java.lang.String or str title: title of dialog
        :param java.lang.String or str prompt: prompt shown above list
        :param java.util.function.Function[T, java.lang.String] toStringFunction: function that converts a T into a String.
        :return: the chosen T object, or null if dialog canceled.
        :rtype: T
        """

    def setSelectedObject(self, obj: T):
        ...

    @property
    def selectedObject(self) -> T:
        ...

    @selectedObject.setter
    def selectedObject(self, value: T):
        ...


class DropDownMultiSelectionTextField(DropDownSelectionTextField[T], typing.Generic[T]):
    """
    Extension of the :obj:`DropDownSelectionTextField` that allows multiple items to be selected.
     
    
    Note that multiple selection introduces some display complications that are not an issue with
    single selection. Namely:
     
    * how do you display multiple selected items in the preview pane
    * how do you display those same items in the drop down text field
    
    The solution here is to:
     
    * let the preview panel operate normally; it will simply display the preview text for whatever
    was last selected
    * display all selected items in the drop down text field as a comma-delimited list
    """

    @typing.type_check_only
    class PreviewListener(javax.swing.event.ListSelectionListener):
        """
        Listener for the preview panel which is kicked whenever a selection has been made in the
        drop down. This will prompt the preview panel to change what it displays.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataModel: DropDownTextFieldDataModel[T]):
        """
        Constructor.
        
        :param DropDownTextFieldDataModel[T] dataModel: the model for the drop down widget
        """

    def addDropDownSelectionChoiceListener(self, listener: DropDownMultiSelectionChoiceListener[T]):
        """
        Adds the caller to a list of subscribers who will be notified when selection changes.
        
        :param DropDownMultiSelectionChoiceListener[T] listener: the subscriber to be added
        """

    def getSelectedValues(self) -> java.util.List[T]:
        """
        Returns a list of all selected items in the list.
        
        :return: the selected items
        :rtype: java.util.List[T]
        """

    @property
    def selectedValues(self) -> java.util.List[T]:
        ...


class PopupWindow(java.lang.Object):
    """
    A generic window intended to be used as a temporary window to show information.  This window is
    designed to stay open as long as the user mouses over the window.   Once the user mouses away,
    the window will be closed.
    """

    @typing.type_check_only
    class PopupSource(java.lang.Object):
        """
        A class that holds info related to the source of a hover request.  This is used to position
        the popup window that will be shown.
        """

        @typing.type_check_only
        class ShapeDebugPainter(ghidra.util.bean.GGlassPanePainter):
            """
            Paints shapes used by this class (useful for debugging)
            """

            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, displayComponent: javax.swing.JComponent):
        ...

    @typing.overload
    def __init__(self, sourceComponent: java.awt.Component, displayComponent: javax.swing.JComponent):
        ...

    @typing.overload
    def __init__(self, parentWindow: java.awt.Window, displayComponent: javax.swing.JComponent):
        ...

    def addComponentListener(self, listener: java.awt.event.ComponentListener):
        ...

    def dispose(self):
        ...

    def getDisplayComponent(self) -> javax.swing.JComponent:
        ...

    def hide(self):
        ...

    @staticmethod
    def hideAllWindows():
        ...

    def isShowing(self) -> bool:
        ...

    def pack(self):
        ...

    def setCloseWindowDelay(self, delayInMillis: typing.Union[jpype.JInt, int]):
        """
        Sets the amount of time that will pass before the popup window is closed **after** the
        user moves away from the popup window and out of the neutral zone
        
        :param jpype.JInt or int delayInMillis: the timer delay
        """

    def setPopupPlacer(self, popupWindowPlacer: docking.widgets.shapes.PopupWindowPlacer):
        """
        Sets the object that decides where to place the popup window.
        
        :param docking.widgets.shapes.PopupWindowPlacer popupWindowPlacer: the placer
        """

    def setWindowName(self, name: typing.Union[java.lang.String, str]):
        ...

    def showOffsetPopup(self, e: java.awt.event.MouseEvent, keepVisibleArea: java.awt.Rectangle, forceShow: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def showPopup(self, e: java.awt.event.MouseEvent, forceShow: typing.Union[jpype.JBoolean, bool]):
        """
        Shows this popup window unless popups are disabled as reported by 
        :meth:`DockingUtils.isTipWindowEnabled() <DockingUtils.isTipWindowEnabled>`.  If ``forceShow`` is true, then the popup 
        will be shown regardless of the state returned by :meth:`DockingUtils.isTipWindowEnabled() <DockingUtils.isTipWindowEnabled>`.
        
        :param java.awt.event.MouseEvent e: the event
        :param jpype.JBoolean or bool forceShow: true to show the popup even popups are disabled application-wide
        """

    @typing.overload
    def showPopup(self, component: java.awt.Component, location: java.awt.Point, forceShow: typing.Union[jpype.JBoolean, bool]):
        """
        Shows this popup window unless popups are disabled as reported by 
        :meth:`DockingUtils.isTipWindowEnabled() <DockingUtils.isTipWindowEnabled>`.  If ``forceShow`` is true, then the popup 
        will be shown regardless of the state returned by :meth:`DockingUtils.isTipWindowEnabled() <DockingUtils.isTipWindowEnabled>`.
         
        
        Note: the component passed in is the component to which the ``location`` the location 
        belongs.   In the example below, the component used to get the location is to the component
        passed to this method.  This is because the location is relative to the parent's coordinate
        space.  Thus, when calling this method, make sure to use the correct component.
         
        Point location = textField.getLocation(); // this is relative to the text field's parent
        Component parent = textField.getParent();
        PopupWindow.showPopup(parent, location, true);
         
        
        :param java.awt.Component component: the component whose coordinate space the location belongs
        :param java.awt.Point location: the location to show the popup
        :param jpype.JBoolean or bool forceShow: true to show the popup even popups are disabled application-wide
        """

    @typing.overload
    def showPopup(self, e: java.awt.event.MouseEvent):
        """
        Shows this popup window unless popups are disabled as reported by 
        :meth:`DockingUtils.isTipWindowEnabled() <DockingUtils.isTipWindowEnabled>`.
        
        :param java.awt.event.MouseEvent e: the event
        """

    @property
    def displayComponent(self) -> javax.swing.JComponent:
        ...

    @property
    def showing(self) -> jpype.JBoolean:
        ...


class PopupKeyStorePasswordProvider(ghidra.security.KeyStorePasswordProvider):

    @typing.type_check_only
    class KeystorePasswordPrompt(java.lang.Runnable):
        """
        Swing runnable for prompting user for a keystore password.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EmptyBorderButton(javax.swing.JButton):
    """
    Class that is a JButton that has an empty border and adds a mouse listener
    so that the button looks raised when the mouse pointer enters the button,
    and looks lowered when the mouse pointer exits the button.e
    """

    @typing.type_check_only
    class ButtonStateListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ButtonFocusListener(java.awt.event.FocusListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RAISED_BUTTON_BORDER: typing.Final[javax.swing.border.Border]
    """
    A raised beveled border.
    """

    NO_BUTTON_BORDER: typing.Final[javax.swing.border.Border]
    """
    An empty border.
    """

    LOWERED_BUTTON_BORDER: typing.Final[javax.swing.border.Border]
    """
    A lowered border beveled border.
    """

    FOCUSED_BUTTON_BORDER: typing.Final[javax.swing.border.Border]

    @typing.overload
    def __init__(self):
        """
        Construct a new EmptyBorderButton.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Construct a new EmptyBorderButton that has the given button text.
        
        :param java.lang.String or str text: text of the button
        """

    @typing.overload
    def __init__(self, a: javax.swing.Action):
        """
        Construct a new EmptyBorderButton that has an associated action.
        
        :param javax.swing.Action a: action for the button
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Construct a new EmptyBorderButton that has an icon.
        
        :param javax.swing.Icon icon: icon for the button
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Construct a new EmptyBorderButton that has text and an icon.
        
        :param java.lang.String or str text: button text
        :param javax.swing.Icon icon: icon for the button
        """

    def clearBorder(self):
        ...

    def raiseBorder(self):
        ...

    def removeListeners(self):
        ...


class MultiLineLabel(javax.swing.JPanel):
    """
    Class to render a String that has new line characters as a multiline
    label. Calculates the resizing and centering characteristics.
     
    
    Not affected by HTML formatting.
    """

    class_: typing.ClassVar[java.lang.Class]
    LEFT: typing.Final = 0
    """
    Indicator for left alignment.
    """

    CENTER: typing.Final = 1
    """
    Indicator for centering each line.
    """

    RIGHT: typing.Final = 2
    """
    Indicator for right alignment.
    """


    @typing.overload
    def __init__(self):
        """
        Default constructor.
        """

    @typing.overload
    def __init__(self, label: typing.Union[java.lang.String, str], margin_width: typing.Union[jpype.JInt, int], margin_height: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]):
        """
        Construct a new MultiLineLabel.
        
        :param java.lang.String or str label: String to split up if it contains new line characters
        :param jpype.JInt or int margin_width: width of label
        :param jpype.JInt or int margin_height: height of label
        :param jpype.JInt or int alignment: alignment of label, LEFT, CENTER, or RIGHT
        """

    @typing.overload
    def __init__(self, label: typing.Union[java.lang.String, str]):
        """
        Construct a new MultiLineLabel that is left aligned with the default
        width and height margins.
        
        :param java.lang.String or str label: String to split up if it contains new line characters
        """

    def addNotify(self):
        """
        This method is invoked after Canvas is first created
        but before it can be actually displayed. After we have
        invoked our superclass's addNotify() method, we have font
        metrics and can successfully call measure() to figure out
        how big the label is.
        """

    def getAlignment(self) -> int:
        """
        Get alignment for text, LEFT, CENTER, RIGHT.
        """

    def getLabel(self) -> str:
        """
        Get the label text.
        """

    def getMarginHeight(self) -> int:
        """
        Get margin height.
        """

    def getMarginWidth(self) -> int:
        """
        Get margin width.
        """

    def getMinimumSize(self) -> java.awt.Dimension:
        """
        This method is called when layout manager wants to
        know the bare minimum amount of space we need to get by.
        """

    def getPreferredSize(self) -> java.awt.Dimension:
        """
        This method is called by a layout manager when it wants
        to know how big we'd like to be
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Simple test for the MultiLineLabel class.
        
        :param jpype.JArray[java.lang.String] args: not used
        """

    def paint(self, g: java.awt.Graphics):
        """
        This method draws label (applets use same method).
        Note that it handles the margins and the alignment, but
        that is does not have to worry about the color or font --
        the superclass takes care of setting those in the Graphics
        object we've passed.
        
        :param java.awt.Graphics g: the graphics context to paint with.
        """

    def setAlignment(self, a: typing.Union[jpype.JInt, int]):
        """
        Set alignment for text, LEFT, RIGHT, CENTER.
        
        :param jpype.JInt or int a: the new alignment.
        """

    def setFont(self, f: java.awt.Font):
        """
        Sets a new font for label
        
        :param java.awt.Font f: Font to set label
        """

    def setForeground(self, c: java.awt.Color):
        """
        Sets a new color for Canvas
        
        :param java.awt.Color c: Color to display in canvas
        """

    @typing.overload
    def setLabel(self, label: typing.Union[java.lang.String, str]):
        """
        Set a new label for JPanel
        
        :param java.lang.String or str label: String to display in canvas
        """

    @typing.overload
    def setLabel(self, text: jpype.JArray[java.lang.String]):
        """
        Set the label text.
        
        :param jpype.JArray[java.lang.String] text: array of strings to display.
        """

    def setMarginHeight(self, mh: typing.Union[jpype.JInt, int]):
        """
        Sets the margin height
        
        :param jpype.JInt or int mh: the new margin height.
        """

    def setMarginWidth(self, mw: typing.Union[jpype.JInt, int]):
        """
        Set margin width.
        
        :param jpype.JInt or int mw: the new margin width.
        """

    @property
    def minimumSize(self) -> java.awt.Dimension:
        ...

    @property
    def preferredSize(self) -> java.awt.Dimension:
        ...

    @property
    def marginHeight(self) -> jpype.JInt:
        ...

    @marginHeight.setter
    def marginHeight(self, value: jpype.JInt):
        ...

    @property
    def label(self) -> java.lang.String:
        ...

    @label.setter
    def label(self, value: java.lang.String):
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @alignment.setter
    def alignment(self, value: jpype.JInt):
        ...

    @property
    def marginWidth(self) -> jpype.JInt:
        ...

    @marginWidth.setter
    def marginWidth(self, value: jpype.JInt):
        ...


class SideKickVerticalScrollbar(javax.swing.JScrollBar):
    """
    A Vertical JScrollbar that displays an additional component to its right and sized such that
    its top is just below the top button of the scrollbar and its bottom is just above the bottom
    button of the scrollbar.  Useful for providing an "overview" panel.
    """

    @typing.type_check_only
    class MyScrollBar(javax.swing.JScrollBar):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SideKickLayout(java.awt.LayoutManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sideKick: java.awt.Component, viewport: javax.swing.JViewport):
        ...


@typing.type_check_only
class InlineComponentTitledBorder(javax.swing.border.TitledBorder):
    """
    A helper class to the InlineComponentTitledPanel that implements the component-in-border effect.
     
    
    **This class should not be used outside InlineComponentTitledPanel.**
    
    
    .. seealso::
    
        | :obj:`docking.widgets.InlineComponentTitledPanel`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, component: javax.swing.JComponent):
        ...

    @typing.overload
    def __init__(self, border: javax.swing.border.Border):
        ...

    @typing.overload
    def __init__(self, border: javax.swing.border.Border, component: javax.swing.JComponent):
        ...

    @typing.overload
    def __init__(self, border: javax.swing.border.Border, component: javax.swing.JComponent, titleJustification: typing.Union[jpype.JInt, int], titlePosition: typing.Union[jpype.JInt, int]):
        ...

    def getComponentRect(self, rect: java.awt.Rectangle, borderInsets: java.awt.Insets) -> java.awt.Rectangle:
        ...

    def getTitleComponent(self) -> javax.swing.JComponent:
        ...

    def setTitleComponent(self, component: javax.swing.JComponent):
        ...

    @property
    def titleComponent(self) -> javax.swing.JComponent:
        ...

    @titleComponent.setter
    def titleComponent(self, value: javax.swing.JComponent):
        ...


class TitledPanel(javax.swing.JPanel):
    """
    Adds a border to a component that displays a title and provides a area for adding
    components (usually icon buttons)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], panel: javax.swing.JComponent, margin: typing.Union[jpype.JInt, int]):
        """
        Creates a new TitlePanel
        
        :param java.lang.String or str title: the title; this allow clients to provide HTML-based
                title text.  Note: it is up to the client to escape this text as needed for safety
        :param javax.swing.JComponent panel: the component to wrap
        :param jpype.JInt or int margin: the size of the margin to use
        """

    def addTitleComponent(self, comp: javax.swing.JComponent):
        """
        Adds a component to the right side of the title bar.
        
        :param javax.swing.JComponent comp: the component to add.
        """

    def setBottomComponent(self, comp: javax.swing.JComponent):
        """
        Sets a component below the main panel that was passed to the constructor.
        If the component passed to this method is null then the TitledPanel will
        not have a component below the main panel.
        
        :param javax.swing.JComponent comp: the component to display below the main panel. Null indicates none.
        """

    def setTitleName(self, name: typing.Union[java.lang.String, str]):
        ...


class AbstractGCellRenderer(docking.widgets.label.GDHtmlLabel, generic.theme.laf.FontChangeListener):
    """
    A common base class for list and table renderer objects, unifying the Ghidra look and feel.
     
    
    It allows (but default-disables) HTML content, automatically paints alternating row background
    colors, and highlights the drop target in a drag-n-drop operation.
     
    
    The preferred method to change the font used by this renderer is :meth:`setBaseFontId(String) <.setBaseFontId>`.
    If you would like this renderer to use a monospaced font, then, as an alternative to creating a
    font ID, you can instead override :meth:`getDefaultFont() <.getDefaultFont>` to return this
    class's :obj:`.fixedWidthFont`.  
     
    Also, the fixed width font of this class is based on the
    default font set when calling :meth:`setBaseFontId(String) <.setBaseFontId>`, so it stays up-to-date with theme
    changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def firePropertyChange(self, propertyName: typing.Union[java.lang.String, str], oldValue: typing.Union[jpype.JBoolean, bool], newValue: typing.Union[jpype.JBoolean, bool]):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    def getBoldFont(self) -> java.awt.Font:
        ...

    def getFixedWidthFont(self) -> java.awt.Font:
        ...

    def getItalicFont(self) -> java.awt.Font:
        ...

    def invalidate(self):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    @typing.overload
    def repaint(self, tm: typing.Union[jpype.JLong, int], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    @typing.overload
    def repaint(self, r: java.awt.Rectangle):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    @typing.overload
    def repaint(self):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    def revalidate(self):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    def setBackground(self, bg: java.awt.Color):
        """
        Overrides this method to ensure that the new background color is not
        a :obj:`GColorUIResource`. Some Look and Feels will ignore color values that extend
        :obj:`UIResource`, choosing instead their own custom painting behavior. By not using a
        UIResource, we prevent the Look and Feel from overriding this renderer's color value.
        
        :param java.awt.Color bg: the new background color
        """

    def setBaseFontId(self, fontId: typing.Union[java.lang.String, str]):
        """
        Sets this renderer's theme font id.  This will be used to load the base font and to create
        the derived fonts, such as bold and fixed width.
        
        :param java.lang.String or str fontId: the font id
        
        .. seealso::
        
            | :obj:`Gui.registerFont(Component, String)`
        """

    def setDropRow(self, dropRow: typing.Union[jpype.JInt, int]):
        """
        Sets the row where DnD would perform drop operation.
        
        :param jpype.JInt or int dropRow: the drop row
        """

    def setFixedWidthFontId(self, fontId: typing.Union[java.lang.String, str]):
        """
        Sets this renderer's fixed width theme font id.
        
        :param java.lang.String or str fontId: the font id
        
        .. seealso::
        
            | :obj:`Gui.registerFont(Component, String)`
        """

    def setForeground(self, fg: java.awt.Color):
        """
        Overrides this method to ensure that the new foreground color is not
        a :obj:`GColorUIResource`. Some Look and Feels will ignore color values that extend
        :obj:`UIResource`, choosing instead their own custom painting behavior. By not using a
        UIResource, we prevent the Look and Feel from overriding this renderer's color value.
        
        :param java.awt.Color fg: the new foreground color
        """

    def setShouldAlternateRowBackgroundColors(self, alternate: typing.Union[jpype.JBoolean, bool]):
        ...

    def shouldAlternateRowBackgroundColor(self) -> bool:
        """
        Return whether or not the renderer should alternate row background colors.
         
        
        A renderer is unable to override an enforcing DISABLE_ALTERNATING_ROW_COLORS_PROPERTY
        system property -- if the property has disabled alternating colors (i.e., set to
        'true'), this method returns false. If the property is false, individual renderers
        may assert control over alternating row colors.
        
        :return: True if the rows may be painted in alternate background colors, false otherwise
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.DISABLE_ALTERNATING_ROW_COLORS_PROPERTY`
        """

    def validate(self):
        """
        See :obj:`DefaultTableCellRenderer` class header javadoc for more info.
        """

    @property
    def boldFont(self) -> java.awt.Font:
        ...

    @property
    def fixedWidthFont(self) -> java.awt.Font:
        ...

    @property
    def italicFont(self) -> java.awt.Font:
        ...


class DialogRememberOption(java.lang.Object):
    """
    Instances of this type are used to add a checkBox to a Dialog so that the dialog results
    can be saved and reused in future uses of that dialog (e.g., "Apply to all",
    "Remember my decision"). If the checkBox is selected, the dialog results are saved and
    subsequent calls to show the same dialog or another dialog constructed with the same
    instance of this object will immediately return the result instead of actually showing
    the dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, description: typing.Union[java.lang.String, str]):
        """
        Constructs a new DialogRememberOption for use in an OptionDialog for adding an
        "Apply to all", "Remember my decision", etc. checkBox.
        
        :param java.lang.String or str description: the checkBox text (e.g. "Apply to all")
        """

    def getDescription(self) -> str:
        """
        Returns the description that will be displayed to the user.
        
        :return: the description that will be displayed to the user.
        :rtype: str
        """

    def getRememberedResult(self) -> int:
        """
        Returns the result from a previous call to an OptionDialog that had this class installed.
        
        :return: the saved results from a previous call to an OptionDialog.
        :rtype: int
        """

    def hasRememberedResult(self) -> bool:
        """
        Returns true if a previous call to the dialog was remembered (The user selected the
        checkBox)
        
        :return: true if a previous call to the dialog was remembered
        :rtype: bool
        """

    def rememberResult(self, choice: typing.Union[jpype.JInt, int]):
        """
        Sets the results from the dialog only if choice is true.
         
        
        In other words, if the user selects the checkBox, then the result will be saved.  Then,
        whenever the dialog is shown, if there is a saved result, it will be returned instead of
        actually showing the dialog.
        
        :param jpype.JInt or int choice: the user's choice from the OptionDialog
        """

    @property
    def rememberedResult(self) -> jpype.JInt:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class EventTrigger(java.lang.Enum[EventTrigger]):
    """
    This class is used to provide information regarding the source of an event.   It is often 
    useful for event processing clients to know of the user generated an event through the UI 
    or from an API call, or if the event came from an internal source, like a change to the 
    client's model.
    """

    class_: typing.ClassVar[java.lang.Class]
    GUI_ACTION: typing.Final[EventTrigger]
    API_CALL: typing.Final[EventTrigger]
    MODEL_CHANGE: typing.Final[EventTrigger]
    INTERNAL_ONLY: typing.Final[EventTrigger]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EventTrigger:
        ...

    @staticmethod
    def values() -> jpype.JArray[EventTrigger]:
        ...


class DropDownTextField(javax.swing.JTextField, GComponent, typing.Generic[T]):
    """
    A text field that handles comparing text typed by the user to the list of objects and then
    presenting potential matches in a drop down window.  The items in this window cannot be selected.
    
     
    This class will fire :meth:`fireEditingStopped() <.fireEditingStopped>` and :meth:`fireEditingCancelled() <.fireEditingCancelled>` events
    when the user makes a choice by pressing the ENTER key, thus allowing the client code to use
    this class similar in fashion to a property editor.  This behavior can be configured to:
     
    * Not consume the ENTER key press (it consumes by default), allowing the parent container
    to process the event (see:meth:`setConsumeEnterKeyPress(boolean) <.setConsumeEnterKeyPress>`
    * Ignore the ENTER key press completely (see :meth:`setIgnoreEnterKeyPress(boolean) <.setIgnoreEnterKeyPress>`
    
    
     
    This class is subclassed to not only have the matching behavior, but to also allow for user
    selections.
    """

    @typing.type_check_only
    class DropDownList(docking.widgets.list.GList[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HideWindowFocusListener(java.awt.event.FocusAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ListSelectionMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateCaretListener(javax.swing.event.CaretListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateDocumentListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class WindowComponentListener(java.awt.event.ComponentAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InternalKeyListener(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PreviewListener(javax.swing.event.ListSelectionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NoSelectionAllowedListSelectionModel(javax.swing.DefaultListSelectionModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataModel: DropDownTextFieldDataModel[T]):
        """
        Constructor.
         
        
        Uses the default refresh delay of 350ms.
        
        :param DropDownTextFieldDataModel[T] dataModel: provides element storage and search capabilities to this component.
        """

    @typing.overload
    def __init__(self, dataModel: DropDownTextFieldDataModel[T], updateMinDelay: typing.Union[jpype.JInt, int]):
        """
        Constructor.
        
        :param DropDownTextFieldDataModel[T] dataModel: provides element storage and search capabilities to this component.
        :param jpype.JInt or int updateMinDelay: suggestion list refresh delay, triggered after search results have
        changed. Too low a value may cause an inconsistent view as filtering tasks complete; too
        high a value delivers an unresponsive user experience.
        """

    def addCellEditorListener(self, listener: javax.swing.event.CellEditorListener):
        """
        Adds a listener to be notified when cell editing is canceled or completed.
        
        :param javax.swing.event.CellEditorListener listener: The listener to add
        :raises IllegalArgumentException: if the listener has already been added
        """

    def addDropDownSelectionChoiceListener(self, listener: DropDownSelectionChoiceListener[T]):
        """
        Adds a listener that will be called back when the user makes a choice from the drop-down
        list.  A choice is a user action that triggers the selection window to be closed and updates
        the text field.
        
         
        Note: the listener is stored in a :obj:`weak data structure <WeakDataStructureFactory>`,
        so you must maintain a reference to the listener you pass in--anonymous classes or lambdas
        will not work.
        
        :param DropDownSelectionChoiceListener[T] listener: the listener
        """

    def closeDropDownWindow(self):
        """
        Closes the drop down window
        """

    def getSelectedValue(self) -> T:
        """
        Returns the user's selection or null if the user has not made a selection.
         
        
        Note: the value returned from this method may not match the text in the field in the
        case that the user has selected a value and then typed some text.
        
        :return: the user's selection or null if the user has not made a selection.
        :rtype: T
        """

    def isMatchingListShowing(self) -> bool:
        ...

    def removeCellEditorListener(self, listener: javax.swing.event.CellEditorListener):
        """
        Removes the given listener from this class if it has previously been added.
        
        :param javax.swing.event.CellEditorListener listener: The listener to remove.
        """

    def setConsumeEnterKeyPress(self, consume: typing.Union[jpype.JBoolean, bool]):
        """
        When true, this field will not pass Enter key press events up to it's parent **when the
        drop-down selection window is open**.  However, an Enter key press will still be
        "unconsumed" when the drop-down window is not open. When set to false, this method will
        always pass the Enter key press up to it's parent.
        
         
        The default is true.  Clients will set this to false when they wish to respond to an
        Enter event.  For example, a dialog may want to close itself on an Enter key press, even
        when the drop-down selection text field is still open. Contrastingly, when this field is
        embedded inside of a larger editor, like a multi-editor field dialog, the Enter key press
        should simply trigger the drop-down window to close and the editing to stop, but should not
        trigger the overall dialog to close.
        
        :param jpype.JBoolean or bool consume: true to consume
        """

    def setIgnoreEnterKeyPress(self, ignore: typing.Union[jpype.JBoolean, bool]):
        """
        True signals to do nothing when the user presses Enter.  The default is to respond to the
        Enter key, using any existing selection to set this field's :meth:`selected value <.getSelectedValue>`.
        
         
        This can be set to true to allow clients to show drop-down matches without allowing the
        user to select them, triggering the window to be closed.
        
        :param jpype.JBoolean or bool ignore: true to ignore Enter presses; false is the default
        """

    def setMatchingWindowHeight(self, height: typing.Union[jpype.JInt, int]):
        """
        Sets the height of the matching window.  The default value is 300.
        
        :param jpype.JInt or int height: the new height
        """

    def setSelectedValue(self, value: T):
        """
        Sets the current selection on this text field.  This will store the provided value and set
        the text of the text field to be the name of that value.  If the given value is null, then
        the text of this field will be cleared.
        
        :param T value: The value that is to be the current selection or null to clear the selected
        value of this text field.
        """

    def setShowMatchingListOnEmptyText(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Allows this text field to show all potential matches when the text of the field is empty.
        The default is false.
        
        :param jpype.JBoolean or bool show: true to allow the list to be shown
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Overridden to allow for the setting of text without showing the completion window.  This
        is useful for setting the current value to be edited before the using initiates editing.
        
        :param java.lang.String or str text: The text to set on this text field.
        """

    def showMatchingList(self):
        """
        Shows the matching list.  This can be used to show all data when the user has not typed any
        text.
        """

    @property
    def matchingListShowing(self) -> jpype.JBoolean:
        ...

    @property
    def selectedValue(self) -> T:
        ...

    @selectedValue.setter
    def selectedValue(self, value: T):
        ...


class InlineComponentTitledPanel(javax.swing.JPanel):
    """
    A panel with a component-containing border. Use a checkbox as the component, for example, 
    to control the enablement of child widgets.
     
     
    Users should modify the contents of this panel via the JPanel from ``getContentPane()`` 
    -- ``add()`` and ``remove()`` methods have been overridden to modify the 
    content pane; other calls to this panel should ``getContentPane()`` first.
      
    
    Example:
      
    public class MyPanel extends InlineComponentTitledPanel {
        private JCheckBox enableCheckbox = null;
        public MyPanel() {
        super(new JCheckBox("Enable"), BorderFactory.createEtchedBorder());
        enableCheckbox = (JCheckBox) getTitleComponent();
        enableCheckbox.addActionListener(...);
          
        JPanel content = getContentPane();
        content.setLayout(new BorderLayout());
        add(new JButton("Click me"));
        ...
        }
        ...
    }
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, titleComponent: javax.swing.JComponent):
        """
        Create a panel with ``titleComponent`` in the top, left corner
        
        :param javax.swing.JComponent titleComponent: widget to draw in the border
        """

    @typing.overload
    def __init__(self, titleComponent: javax.swing.JComponent, otherBorder: javax.swing.border.Border):
        """
        Create a panel with ``titleComponent`` in the top, left corner
        
        :param javax.swing.JComponent titleComponent: widget to draw in the border
        :param javax.swing.border.Border otherBorder: secondary border to place around this panel
        """

    @typing.overload
    def __init__(self, titleComponent: javax.swing.JComponent, titleJustification: typing.Union[jpype.JInt, int], titlePosition: typing.Union[jpype.JInt, int]):
        """
        Create a panel with ``titleComponent`` in the prescribed location
        
        :param javax.swing.JComponent titleComponent: widget to draw in the border
        :param jpype.JInt or int titleJustification: top-bottom alignment
        :param jpype.JInt or int titlePosition: left-right alignment
        
        .. seealso::
        
            | :obj:`TitledBorder`
        """

    @typing.overload
    def __init__(self, titleComponent: javax.swing.JComponent, titleJustification: typing.Union[jpype.JInt, int], titlePosition: typing.Union[jpype.JInt, int], otherBorder: javax.swing.border.Border):
        """
        Create a panel with ``titleComponent`` in the prescribed location with a secondary
        border
        
        :param javax.swing.JComponent titleComponent: widget to draw in the border
        :param jpype.JInt or int titleJustification: top-bottom alignment
        :param jpype.JInt or int titlePosition: left-right alignment
        :param javax.swing.border.Border otherBorder: secondary border to place around this panel
        
        .. seealso::
        
            | :obj:`TitledBorder`
        """

    def getContentPane(self) -> javax.swing.JPanel:
        """
        This class requires that all content be placed within a designated panel, this method returns that panel.
        
        :return: panel The content panel
        :rtype: javax.swing.JPanel
        """

    def getOtherBorder(self) -> javax.swing.border.Border:
        ...

    def getTitleComponent(self) -> javax.swing.JComponent:
        ...

    def setBorder(self, otherBorder: javax.swing.border.Border):
        """
        Sets the secondary border.
         
        NOTE: Rendering conflicts may occur with co-located sub-borders; a TitledBorder that 
        renders in the same position (top, bottom, etc.) will cause the component to shift, and
        will be rendered-over if the new title resides in the same position and justification 
        (left-to-right alignment) as the component.
        
        :param javax.swing.border.Border otherBorder: 
        
        .. seealso::
        
            | :obj:`setOtherBorder(Border)`
        """

    def setOtherBorder(self, otherBorder: javax.swing.border.Border):
        ...

    def setTitleComponent(self, component: javax.swing.JComponent):
        ...

    @property
    def otherBorder(self) -> javax.swing.border.Border:
        ...

    @otherBorder.setter
    def otherBorder(self, value: javax.swing.border.Border):
        ...

    @property
    def titleComponent(self) -> javax.swing.JComponent:
        ...

    @titleComponent.setter
    def titleComponent(self, value: javax.swing.JComponent):
        ...

    @property
    def contentPane(self) -> javax.swing.JPanel:
        ...


class FindDialog(docking.ReusableDialogComponentProvider):
    """
    A dialog used to perform text searches on a text display.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], searcher: FindDialogSearcher):
        ...

    def getSearchText(self) -> str:
        ...

    def getSearcher(self) -> FindDialogSearcher:
        ...

    def next(self):
        ...

    def previous(self):
        ...

    def setClosedCallback(self, c: utility.function.Callback):
        ...

    def setHistory(self, history: java.util.List[java.lang.String]):
        ...

    def setSearchText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def searcher(self) -> FindDialogSearcher:
        ...

    @property
    def searchText(self) -> java.lang.String:
        ...

    @searchText.setter
    def searchText(self, value: java.lang.String):
        ...


@deprecated("Replaced by GHyperlinkComponent")
class HyperlinkComponent(javax.swing.JPanel):
    """
    A component that acts like a label, but adds the ability to render HTML anchors and the 
    ability for clients to add anchor handlers.
     
    
    When given HTML content (a String that 
    starts with <HTML>) and anchor tags (<a href="callback_name">a hyper link<a>),
    this component will display the hyperlinks properly and will notify any registered 
    listeners (:meth:`addHyperlinkListener(String, HyperlinkListener) <.addHyperlinkListener>` that the user has clicked the link
    by the given name.
    
    
    .. deprecated::
    
    Replaced by :obj:`GHyperlinkComponent`
    """

    @typing.type_check_only
    class NonScrollingCaret(javax.swing.text.DefaultCaret):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, htmlTextWithHyperlinks: typing.Union[java.lang.String, str]):
        ...

    def addHyperlinkListener(self, anchorName: typing.Union[java.lang.String, str], listener: javax.swing.event.HyperlinkListener):
        """
        Add a listener that will be called whenever hyperlink updates happen (hover, activate, etc).
        
        :param java.lang.String or str anchorName: The value in the ``href`` attribute of the anchor tag.
        :param javax.swing.event.HyperlinkListener listener: The listener to be called when the anchor(s) with a matching ``href`` is
                manipulated by the user.
        """

    def getText(self) -> str:
        ...

    def removeHyperlinkListener(self, anchorName: typing.Union[java.lang.String, str], listener: javax.swing.event.HyperlinkListener):
        ...

    def setText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...


class ListSelectionTableDialog(docking.DialogComponentProvider, typing.Generic[T]):

    @typing.type_check_only
    class ListTableModel(docking.widgets.table.AbstractGTableModel[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], list: java.util.List[T]):
        ...

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], model: docking.widgets.table.RowObjectTableModel[T]):
        ...

    def getSelectedItem(self) -> T:
        ...

    def getSelectedItems(self) -> java.util.List[T]:
        ...

    def hideOkButton(self):
        """
        Removes the ok button from the dialog.  This is useful if you are using this dialog 
        as a presentation of data and do not wish to do anything when the user makes selections.
        """

    @deprecated("to be removed sometime after the 9.3 release")
    def setMultiSelectionMode(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Calling this method does not work correctly when used with 
        :meth:`show(Component) <.show>` or :meth:`showSelectMultiple(Component) <.showSelectMultiple>`.   To use this method, you
        must show the dialog by calling: 
         
            DockingWindowManager.showDialog(parent, dialog);
         
         
         
        There is no need to use this method when using either of the aforementioned 
        ``show`` methods
        
        :param jpype.JBoolean or bool enable: true to allow multiple selection
        
        .. deprecated::
        
        to be removed sometime after the 9.3 release
        """

    def show(self, parent: java.awt.Component) -> T:
        ...

    def showSelectMultiple(self, parent: java.awt.Component) -> java.util.List[T]:
        ...

    @property
    def selectedItem(self) -> T:
        ...

    @property
    def selectedItems(self) -> java.util.List[T]:
        ...


class CursorPosition(java.lang.Object):
    """
    A simple tracker of position in an object for that allows more specialized users to extend and
    add functionality.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, position: typing.Union[jpype.JInt, int]):
        ...

    def getPosition(self) -> int:
        ...

    def setOffset(self, offset: typing.Union[jpype.JInt, int]):
        ...

    @property
    def position(self) -> jpype.JInt:
        ...


class OptionDialog(docking.DialogComponentProvider):
    """
    A utility class to easily show dialogs that require input from the user.
    
    
     
    **************
    Option Dialogs
    **************
    
    The primary type of
    dialog provided herein is the basic option dialog that allows the user to specify the buttons
    that appear on the dialog.  By default, the given option text will appear as a button(s),
    followed by a ``Cancel`` button (you can call the
    :meth:`showOptionNoCancelDialog(Component, String, String, String, String, int) <.showOptionNoCancelDialog>` methods if
    you do not want a ``Cancel`` button.  To use this type of dialog you can use the
    various **``showOptionDialog*``** methods.
     
    
    Each of the option dialog methods will return a result, which is a number indicating the
    choice made by the user.  See each method for more details.
    
    
     
    =============================
    Data Input and Choice Dialogs
    =============================
    
    The methods listed here allow the user to either enter data from the keyboard or to choose
    from a pre-populated list of data.
     
    * :meth:`showInputChoiceDialog(Component, String, String, String[], String, int) <.showInputChoiceDialog>`
    * :meth:`showInputMultilineDialog(Component, String, String, String) <.showInputMultilineDialog>`
    * :meth:`showInputSingleLineDialog(Component, String, String, String) <.showInputSingleLineDialog>`
    
    
    
     
    ==============
    Yes/No Dialogs
    ==============
    
    Finally, there are a series of methods that present ``Yes`` and ``No`` buttons in
    a dialog.  There are versions that do and do not have a ``Cancel`` button.
    
    
     
    =======================================
    Basic Message / Warning / Error Dialogs
    =======================================
    
    If you would like to display a simple message to the user, but do not require input from the
    user, then you should use the various methods of :obj:`Msg`, such as
    :meth:`Msg.showInfo(Object, Component, String, Object) <Msg.showInfo>`.
     
    
    Note, the user will be unable to select any text shown in the message area of the dialog.
     
     
    ===================================
    "Apply to All" / "Don't Show Again"
    ===================================
    
    For more advanced input dialog usage, to include allowing the user to tell the dialog
    to remember a particular decision, or to apply a given choice to all future request, see
    :obj:`OptionDialogBuilder`.
    
    
    .. seealso::
    
        | :obj:`Msg`
    
        | :obj:`OptionDialogBuilder`
    """

    @typing.type_check_only
    class DoNothingDialogRememberOption(DialogRememberOption):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    MESSAGE_COMPONENT_NAME: typing.Final = "MESSAGE-COMPONENT"
    ERROR_MESSAGE: typing.Final = 0
    """
    Used for error messages.
    """

    INFORMATION_MESSAGE: typing.Final = 1
    """
    Used for information messages.
    """

    WARNING_MESSAGE: typing.Final = 2
    """
    Used for warning messages.
    """

    QUESTION_MESSAGE: typing.Final = 3
    """
    Used for questions.
    """

    PLAIN_MESSAGE: typing.Final = -1
    """
    No icon is used.
    """

    CANCEL_OPTION: typing.Final = 0
    """
    Identifier for the cancel option.
    """

    YES_OPTION: typing.Final = 1
    NO_OPTION: typing.Final = 2
    OPTION_ONE: typing.Final = 1
    """
    Identifier for option one.
    """

    OPTION_TWO: typing.Final = 2
    """
    Identifier for option two.
    """

    OPTION_THREE: typing.Final = 3
    """
    Identifier for option three.
    """


    @staticmethod
    def createBuilder(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> OptionDialogBuilder:
        """
        A convenience method to create a :obj:`OptionDialogBuilder`
        
        :param java.lang.String or str title: the dialog title
        :param java.lang.String or str message: the dialog message
        :return: the builder
        :rtype: OptionDialogBuilder
        """

    @staticmethod
    def getIconForMessageType(messageType: typing.Union[jpype.JInt, int]) -> javax.swing.Icon:
        """
        Returns the Icon to use for the given message type.
        
        :param jpype.JInt or int messageType: the type of message being displayed.
        :return: the appropriate Icon.
        :rtype: javax.swing.Icon
        """

    def getMessage(self) -> str:
        """
        Returns the dialog's message to the user
        
        :return: the message
        :rtype: str
        """

    def getResult(self) -> int:
        """
        Returns which option was selected:
        CANCEL_OPTION if the operation was cancelled;
        OPTION_ONE if Option 1 was selected;
        OPTION_TWO if Option 2 was selected.
        
        :return: selected option; returns CANCEL_OPTION for informational dialogs
        :rtype: int
        """

    @typing.overload
    def show(self) -> int:
        ...

    @typing.overload
    def show(self, parent: java.awt.Component) -> int:
        ...

    @staticmethod
    def showEditableInputChoiceDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], selectableValues: jpype.JArray[java.lang.String], initialValue: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> str:
        """
        Displays a dialog for the user to enter a string value by either typing it or
        selecting from a list of possible strings.  The list of possible values is editable
        such that the user can enter their own value by typing text.
        
        :param java.awt.Component parent: the component to parent this dialog to
        :param java.lang.String or str title: the title to display on the input dialog
        :param java.lang.String or str label: the label to display in front of the combo box
        :param jpype.JArray[java.lang.String] selectableValues: an array of string to choose from
        :param java.lang.String or str initialValue: an optional value to set the combo box to, can be null
        in which the combo box will have the first item from the selectable values.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
            INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: the string entered or chosen OR null if the dialog was canceled.
        :rtype: str
        """

    @staticmethod
    def showInputChoiceDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], selectableValues: jpype.JArray[java.lang.String], initialValue: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> str:
        """
        Displays a dialog for the user to enter a string value by either typing it or
        selecting from a list of possible strings.
        
        :param java.awt.Component parent: the component to parent this dialog to
        :param java.lang.String or str title: the title to display on the input dialog
        :param java.lang.String or str label: the label to display in front of the combo box
        :param jpype.JArray[java.lang.String] selectableValues: an array of string to choose from
        :param java.lang.String or str initialValue: an optional value to set the combo box to, can be null
        in which the combo box will have the first item from the selectable values.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
            INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: the string entered or chosen OR null if the dialog was canceled.
        :rtype: str
        """

    @staticmethod
    def showInputMultilineDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str]) -> str:
        """
        Displays a dialog for the user to enter a **multi-line** string value.
        
        :param java.awt.Component parent: the component to parent this dialog to
        :param java.lang.String or str title: the title to display on the input dialog
        :param java.lang.String or str label: the label to display in front of the text area
        :param java.lang.String or str initialValue: an optional value that will be set in the text area, can be null
        :return: the string entered OR null if the dialog was canceled.
        :rtype: str
        """

    @staticmethod
    def showInputSingleLineDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], initialValue: typing.Union[java.lang.String, str]) -> str:
        """
        Displays a dialog for the user to enter a string value on a single line.
        
        :param java.awt.Component parent: the component to parent this dialog to
        :param java.lang.String or str title: the title to display on the input dialog
        :param java.lang.String or str label: the label to display in front of the text field
        :param java.lang.String or str initialValue: an optional value to set in the text field, can be null
        :return: the string entered OR null if the dialog was canceled.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str]) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int], defaultButtonName: typing.Union[java.lang.String, str]) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :param java.lang.String or str defaultButtonName: the name of the button to be the default.  Null will make the first
        button the default
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], icon: javax.swing.Icon) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :param javax.swing.Icon icon: allows the user to specify the icon to be used.  If non-null,
            this will override the messageType.
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], option3: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an **three-option** dialog.  The dialog
        will remain until the user presses the Option1, Option2, Option3 or Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used.
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param java.lang.String or str option3: The text to place on the third option button.
        :param jpype.JInt or int messageType: The type of message to display
        :return: The options selected by the user. 1 for the first option and
        2 for the second option and so on.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str]) -> int:
        """
        Static helper method to easily display an two-option dialog.  The dialog
        will remain until the user presses the Option1, Option2 or Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.\
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an two-option dialog.  The dialog
        will remain until the user presses the Option1, Option2 or Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], icon: javax.swing.Icon) -> int:
        """
        Static helper method to easily display an two-option dialog.  The dialog
        will remain until the user presses the Option1, Option2 or Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param javax.swing.Icon icon: allows the user to specify the icon to be used.  If non-null,
            this will override the messageType.
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialogWithCancelAsDefaultButton(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str]) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
         
        
        The dialog shown by this method will have the cancel button set as the default button so
        that an Enter key press will trigger a cancel action.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionDialogWithCancelAsDefaultButton(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an single-option dialog.  The dialog
        will remain until the user presses the Option1 button or the Cancel button.
         
        
        The dialog shown by this method will have the cancel button set as the default button so
        that an Enter key press will trigger a cancel action.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: The options selected by the user. 1 if the option button is pressed
        or 0 if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionNoCancelDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an two-option dialog.  The dialog
        will remain until the user presses the Option1, Option2 or Cancel button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionNoCancelDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], icon: javax.swing.Icon) -> int:
        """
        Static helper method to easily display an two-option dialog with no Cancel button.
        The dialog will remain until the user presses the Option1 or Option 2 button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param javax.swing.Icon icon: allows the user to specify the icon to be used.  If non-null,
            this will override the messageType.
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionNoCancelDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], option3: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]) -> int:
        """
        Static helper method to easily display an three-option dialog with no Cancel button.
        The dialog will remain until the user presses the
        Option1, Option 2, or Option 3 button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :param java.lang.String or str option1: The text to place on the first option button.
        :param java.lang.String or str option2: The text to place on the second option button.
        :param java.lang.String or str option3: The text to place on the third option button.
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled.
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def showOptionNoCancelDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], option1: typing.Union[java.lang.String, str], option2: typing.Union[java.lang.String, str], option3: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int], help: ghidra.util.HelpLocation) -> int:
        """
        Static helper method to easily display an three-option dialog with no Cancel button.
        The dialog will remain until the user presses the
        Option1, Option 2, or Option 3 button.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area
        :param java.lang.String or str message: The information message to be displayed in the dialog
        :param java.lang.String or str option1: The text to place on the first option button
        :param java.lang.String or str option2: The text to place on the second option button
        :param java.lang.String or str option3: The text to place on the third option button
        :param jpype.JInt or int messageType: used to specify a default icon, can be ERROR_MESSAGE,
                INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
        :param ghidra.util.HelpLocation help: The help location for this dialog
        :return: The options selected by the user. 1 for the first option and
        2 for the second option.  0 is returned if the operation is cancelled
        :rtype: int
        """

    @staticmethod
    def showYesNoCancelDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
        """
        Dialog with only YES/NO options, **no CANCEL**
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :return: The options selected by the user:
         
                        0 is returned if the operation is cancelled
                        1 for the first option
                        2 for the second option
         
        :rtype: int
        """

    @staticmethod
    def showYesNoDialog(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
        """
        Dialog with only YES/NO options, no CANCEL
        
        :param java.awt.Component parent: The parent dialog or frame of this dialog. (Can be null)
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :return: The options selected by the user:
         
                        0 is returned if the operation is cancelled
                        1 for **Yes**
                        2 for **No**
         
        :rtype: int
        """

    @staticmethod
    def showYesNoDialogWithNoAsDefaultButton(parent: java.awt.Component, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]) -> int:
        """
        Dialog with only YES/NO options, **no CANCEL**
         
        
        The dialog shown by this method will have the ``No`` button set as the default button so
        that an Enter key press will trigger a ``No`` action.
        
        :param java.awt.Component parent: The parent component of this dialog. If the given component is
        a frame or dialog, then the component will be used to parent the option dialog.
        Otherwise, the parent frame or dialog will be found by traversing up the given
        component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
        but this promotes poor dialog behavior
        :param java.lang.String or str title: The String to be placed in the dialogs title area.
        :param java.lang.String or str message: The information message to be displayed in the dialog.
        :return: The options selected by the user:
         
                        1 for **Yes**
                        2 for **No**
         
        :rtype: int
        """

    @property
    def result(self) -> jpype.JInt:
        ...

    @property
    def message(self) -> java.lang.String:
        ...


class OkDialog(OptionDialog):
    """
    A dialog with an OK button.  The client can specify the message type in the constructor.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], messageType: typing.Union[jpype.JInt, int]):
        """
        Construct a simple informational dialog with a single OK button
        
        :param java.lang.String or str title: The String to be placed in the dialogs title area
        :param java.lang.String or str message: The information message to be displayed in the dialog
        :param jpype.JInt or int messageType: used to specify a default icon
                      
        * ERROR_MESSAGE
        * INFORMATION_MESSAGE
        * WARNING_MESSAGE
        * QUESTION_MESSAGE
        * PLAIN_MESSAGE
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Construct a simple informational dialog with a single OK button
        
        :param java.lang.String or str title: The String to be placed in the dialogs title area
        :param java.lang.String or str message: The information message to be displayed in the dialog
        :param javax.swing.Icon icon: allows the user to specify the icon to be used
                    If non-null, this will override the messageType
        """

    @staticmethod
    def show(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Show a :obj:`plain <OptionDialog.PLAIN_MESSAGE>` :obj:`OkDialog` with the given title and message
        
        :param java.lang.String or str title: the title
        :param java.lang.String or str message: the message
        """

    @staticmethod
    def showError(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Show a :obj:`plain <OptionDialog.ERROR_MESSAGE>` :obj:`OkDialog` with the given 
        title and message
        
        :param java.lang.String or str title: the title
        :param java.lang.String or str message: the message
        """

    @staticmethod
    def showInfo(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Show a :obj:`plain <OptionDialog.INFORMATION_MESSAGE>` :obj:`OkDialog` with the given 
        title and message
        
        :param java.lang.String or str title: the title
        :param java.lang.String or str message: the message
        """


class DropDownMultiSelectionChoiceListener(java.lang.Object, typing.Generic[T]):
    """
    Listener called when the user makes a selection on the :obj:`DropDownMultiSelectionTextField`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectionChanged(self, t: java.util.List[T]):
        """
        Invoked when the selection in the dropdown has changed.
        
        :param java.util.List[T] t: the selected items
        """


class ListSelectionDialog(docking.DialogComponentProvider, typing.Generic[T]):

    @typing.type_check_only
    class DefaultTableModel(docking.widgets.table.AbstractGTableModel[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelectionListener(DropDownSelectionChoiceListener[T1], typing.Generic[T1]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], data: java.util.List[T], searchConverter: DataToStringConverter[T]):
        ...

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], data: java.util.List[T], searchConverter: DataToStringConverter[T], descriptionConverter: DataToStringConverter[T]):
        ...

    def getSelectedItem(self) -> T:
        ...

    @staticmethod
    def getStringListSelectionDialog(title: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], data: java.util.List[java.lang.String]) -> ListSelectionDialog[java.lang.String]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def show(self, parent: java.awt.Component) -> T:
        ...

    def wasCancelled(self) -> bool:
        ...

    @property
    def selectedItem(self) -> T:
        ...


class TextComponentSearcher(FindDialogSearcher):
    """
    A class to find text matches in the given :obj:`TextComponent`.  This class will search for all
    matches and cache the results for future requests when the user presses Next or Previous.  All
    matches will be highlighted in the text component.  The match containing the cursor will be a 
    different highlight color than the others.  When the find dialog is closed, all highlights are
    removed.
    """

    @typing.type_check_only
    class SearchResults(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TextComponentSearchLocation(SearchLocation):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int], searchText: typing.Union[java.lang.String, str], forwardDirection: typing.Union[jpype.JBoolean, bool], match: TextComponentSearcher.FindMatch):
            ...


    @typing.type_check_only
    class SearchTask(ghidra.util.task.Task):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FindMatch(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DocumentChangeListener(javax.swing.event.DocumentListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CaretChangeListener(javax.swing.event.CaretListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, editorPane: javax.swing.JEditorPane):
        ...

    def getEditorPane(self) -> javax.swing.JEditorPane:
        ...

    def hasSearchResults(self) -> bool:
        ...

    def isStale(self) -> bool:
        ...

    def setEditorPane(self, editorPane: javax.swing.JEditorPane):
        ...

    @property
    def stale(self) -> jpype.JBoolean:
        ...

    @property
    def editorPane(self) -> javax.swing.JEditorPane:
        ...

    @editorPane.setter
    def editorPane(self, value: javax.swing.JEditorPane):
        ...


class AutoLookup(java.lang.Object):
    """
    A class that holds the logic and state for finding matching rows in a widget when a user types
    in the widget.   This class was designed for row-based widgets, such as tables and lists.
    """

    @typing.type_check_only
    class AutoLookupItem(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    KEY_TYPING_TIMEOUT: typing.Final = 800

    def __init__(self):
        ...

    def getCurrentRow(self) -> int:
        """
        Returns the currently selected row
        
        :return: the row
        :rtype: int
        """

    def getRowCount(self) -> int:
        """
        Returns the total number of rows
        
        :return: the row count
        :rtype: int
        """

    def getValueString(self, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns a string representation of the item at the given row and column.  The text 
        should match what the user sees.
        
        :param jpype.JInt or int row: the row
        :param jpype.JInt or int col: the column
        :return: the text
        :rtype: str
        """

    def isSorted(self, column: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given column is sorted.  This class will use a binary search if the
        given column is sorted.  Otherwise, a brute-force search will be used.
        
        :param jpype.JInt or int column: the column
        :return: true if sorted
        :rtype: bool
        """

    def isSortedAscending(self) -> bool:
        """
        Returns true if the currently sorted column is sorted ascending.  This is used in 
        conjunction with :meth:`isSorted(int) <.isSorted>`.  If that method returns false, then this method
        will not be called.
        
        :return: true if sorted ascending
        :rtype: bool
        """

    def keyTyped(self, e: java.awt.event.KeyEvent):
        """
        Clients call this method when the user types keys
        
        :param java.awt.event.KeyEvent e: the key event
        """

    def matchFound(self, row: typing.Union[jpype.JInt, int]):
        """
        This method will be called when a match for the call to :meth:`keyTyped(KeyEvent) <.keyTyped>` is 
        found
        
        :param jpype.JInt or int row: the matching row
        """

    def setColumn(self, column: typing.Union[jpype.JInt, int]):
        """
        Sets the column that is searched when a lookup is performed
        
        :param jpype.JInt or int column: the column
        """

    def setTimeout(self, timeout: typing.Union[jpype.JLong, int]):
        """
        Sets the delay between keystrokes after which each keystroke is considered a new lookup
        
        :param jpype.JLong or int timeout: the timeout
        """

    def setTimeoutPredicate(self, p: java.util.function.Predicate[java.lang.Long]):
        """
        Sets the logic for deciding whether the elapsed time between keystrokes is enough to
        trigger a new auto lookup or to continue with the previous match.
         
         
        This method is intended for tests that need precise control over the timeout mechanism.
        
        :param java.util.function.Predicate[java.lang.Long] p: the predicate that takes the amount of elapsed time
        
        .. seealso::
        
            | :obj:`.setTimeout(long)`
        """

    @property
    def sorted(self) -> jpype.JBoolean:
        ...

    @property
    def currentRow(self) -> jpype.JInt:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def sortedAscending(self) -> jpype.JBoolean:
        ...


class SmallBorderButton(javax.swing.JButton):
    """
    Class that is a JButton that has an empty border and adds a mouse listener
    so that the button looks raised when the mouse pointer enters the button,
    and looks lowered when the mouse pointer exits the button.
    """

    @typing.type_check_only
    class ButtonMouseListener(java.awt.event.MouseAdapter):
        """
        Mouse listener on the button to render it appropriately.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    RAISED_BORDER: typing.Final[javax.swing.border.Border]
    """
    A raised beveled border.
    """

    NO_BORDER: typing.Final[javax.swing.border.Border]
    """
    An empty border.
    """

    LOWERED_BORDER: typing.Final[javax.swing.border.Border]
    """
    A lowered border beveled border.
    """


    @typing.overload
    def __init__(self):
        """
        Construct a new EmptyBorderButton.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Construct a new EmptyBorderButton that has the given button text.
        
        :param java.lang.String or str text: text of the button
        """

    @typing.overload
    def __init__(self, a: javax.swing.Action):
        """
        Construct a new EmptyBorderButton that has an associated action.
        
        :param javax.swing.Action a: action for the button
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Construct a new EmptyBorderButton that has an icon.
        
        :param javax.swing.Icon icon: icon for the button
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], icon: javax.swing.Icon):
        """
        Construct a new EmptyBorderButton that has text and an icon.
        
        :param java.lang.String or str text: button text
        :param javax.swing.Icon icon: icon for the button
        """

    def clearBorder(self):
        """
        Clear the border on this button and set it to NO_BORDER.
        """

    def setOverrideBorder(self, overrideBorder: javax.swing.border.Border):
        """
        Override the default border created by this button.
        
        :param javax.swing.border.Border overrideBorder: new border to use
        """


class DropDownSelectionTextField(DropDownTextField[T], typing.Generic[T]):
    """
    A text field that handles comparing text typed by the user to the list of objects
    and then presenting potential matches in a drop down window.  This class differs from 
    its parent in that it allows the user to select items from the popup list.
     
     
    **Usage note:** Typically this text field will not be used directly, but will 
    instead be used indirectly by way of an editor.
    If this field is used directly, then the user should use :meth:`setSelectedValue(Object) <.setSelectedValue>` and
    :meth:`getSelectedValue() <.getSelectedValue>` to get and set data on this field, rather than calling 
    ~~:meth:`setText(String) <.setText>`~~ and ~~:meth:`getText() <.getText>`~~.
     
     
    Usage notes:
         
    * Pressing ENTER with the drop-down list open will select and item and close 
    the list
    * Pressing ENTER with the drop-down list not showing will trigger an
    editingStopped() event, signaling that the user has made a choice
    * Pressing ESCAPE with the drop-down list open will close the list
    * Pressing ESCAPE with the drop-down list not showing will trigger an 
    editingCancelled() event, signaling that the user has cancelled editing
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataModel: DropDownTextFieldDataModel[T]):
        ...


class GenericDateCellRenderer(docking.widgets.table.GTableCellRenderer):
    """
    The JDK-provided DateRenderer does not inherit the backgrounds and such properly.
    For LAFs having tables with alternating backgrounds, e.g., Aqua and Nimbus, the date
    column does not have the correct background. This fixes that.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, toolTip: typing.Union[java.lang.String, str]):
        ...


class ScrollableTextArea(javax.swing.JScrollPane):
    """
    A JScrollPane wrapper for a text area that can be told to scroll to bottom
    """

    @typing.type_check_only
    class CopyActionListener(java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PrivateTextArea(javax.swing.JTextArea):
        """
        JTextArea's getRowHeight() is protected, so we need to derive
        a class to use it :(
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a scrollable JTextArea, where a default model is set,
        the initial string is null, and rows/columns are set to 0.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        """
        Constructs a scrollable JextArea with the specified text displayed.
        A default model is created and rows/columns are set to 0.
        
        :param java.lang.String or str text: the initial text.
        """

    @typing.overload
    def __init__(self, rows: typing.Union[jpype.JInt, int], columns: typing.Union[jpype.JInt, int]):
        """
        Constructs a new empty TextArea with the specified number
        of rows and columns. A default model is created, and the
        initial string is null.
        
        :param jpype.JInt or int rows: the number of visible rows.
        :param jpype.JInt or int columns: the number of visible columns.
        """

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str], rows: typing.Union[jpype.JInt, int], columns: typing.Union[jpype.JInt, int]):
        """
        Constructs a scrollable JTextArea with the specified text and 
        number of rows and columns. A default model is created.
        
        :param java.lang.String or str text: initial text.
        :param jpype.JInt or int rows: the number of visible rows.
        :param jpype.JInt or int columns: the number of visible columns.
        """

    @typing.overload
    def __init__(self, doc: javax.swing.text.Document):
        """
        Constructs a scrollable JTextArea with the given document model,
        and defaults for all of the other arguments (null, 0, 0).
        
        :param javax.swing.text.Document doc: - the model to use
        """

    @typing.overload
    def __init__(self, doc: javax.swing.text.Document, text: typing.Union[java.lang.String, str], rows: typing.Union[jpype.JInt, int], columns: typing.Union[jpype.JInt, int]):
        """
        Constructs a scrollable JTextArea with the specified number of
        rows and columns, and the given model. All of the
        constructors feed through this constructor.
        
        :param javax.swing.text.Document doc: - the model to use
        :param java.lang.String or str text: initial text.
        :param jpype.JInt or int rows: the number of visible rows.
        :param jpype.JInt or int columns: the number of visible columns.
        """

    def append(self, text: typing.Union[java.lang.String, str]):
        """
        Appends the text to the text area maintained in this scroll pane
        
        :param java.lang.String or str text: the text to append.
        """

    def getLineCount(self) -> int:
        """
        Returns the number of lines current set in the text area
        
        :return: the count
        :rtype: int
        """

    def getTabSize(self) -> int:
        """
        Returns the tab size set in the text area
        
        :return: the size
        :rtype: int
        """

    def getText(self) -> str:
        """
        Returns the text contained within the text area
        
        :return: the text
        :rtype: str
        """

    def getTextAreaHeight(self) -> int:
        """
        Returns the total area height of the text area (row height * line count)
        
        :return: the height
        :rtype: int
        """

    def getTextVisibleHeight(self) -> int:
        """
        Returns the visible height of the text area
        
        :return: the height
        :rtype: int
        """

    def insert(self, text: typing.Union[java.lang.String, str], position: typing.Union[jpype.JInt, int]):
        """
        Inserts the string at the specified position
        
        :param java.lang.String or str text: the text to insert.
        :param jpype.JInt or int position: the character postition at which to insert the text.
        """

    def replaceRange(self, text: typing.Union[java.lang.String, str], start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]):
        """
        replaces the range of text specified
        
        :param java.lang.String or str text: the new text that will replace the old text.
        :param jpype.JInt or int start: the starting character postition of the text to replace.
        :param jpype.JInt or int end: the ending character position of the text to replace.
        """

    def scrollToBottom(self):
        """
        forces the scroll pane to scroll to bottom of text area
        """

    def scrollToTop(self):
        """
        Scroll the pane to the top of the text area.
        """

    def setCaretPosition(self, position: typing.Union[jpype.JInt, int]):
        ...

    def setEditable(self, editable: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the ability to edit the text area content
        
        :param jpype.JBoolean or bool editable: true to edit, false to not allow edit.
        """

    def setTabSize(self, tabSize: typing.Union[jpype.JInt, int]):
        """
        Sets the number of characters to expand tabs to. This will be
        multiplied by the maximum advance for variable width fonts.
        A PropertyChange event ("tabSize") is fired when tab size changes.
        
        :param jpype.JInt or int tabSize: the new tab size.
        """

    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        set the text in the text area
        
        :param java.lang.String or str text: the text to set.
        """

    @property
    def textVisibleHeight(self) -> jpype.JInt:
        ...

    @property
    def tabSize(self) -> jpype.JInt:
        ...

    @tabSize.setter
    def tabSize(self, value: jpype.JInt):
        ...

    @property
    def textAreaHeight(self) -> jpype.JInt:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def lineCount(self) -> jpype.JInt:
        ...


class JTreeMouseListenerDelegate(java.awt.event.MouseAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tree: javax.swing.JTree):
        ...

    def addMouseListener(self, listener: java.awt.event.MouseListener):
        ...

    def addMouseListeners(self, listenerList: java.util.List[java.awt.event.MouseListener]):
        ...

    def getMouseListeners(self) -> jpype.JArray[java.awt.event.MouseListener]:
        ...

    def removeMouseListener(self, listener: java.awt.event.MouseListener):
        ...

    @property
    def mouseListeners(self) -> jpype.JArray[java.awt.event.MouseListener]:
        ...


class OptionDialogBuilder(java.lang.Object):
    """
    Class for creating OptionDialogs using the builder pattern.
    
     
    At a minimum, an OptionDialog requires a title and a message.  They can be specified
    in the constructor or set later.
    
     
    You can also, specify the messageType or an icon.  The messageType is used to set the
    icon to one of several predefined ones appropriate for the message(ERROR, WARNING, etc.)
    You should not specify both, but if you do, the specified Icon will be used and the
    MessageType will be ignored.
    
     
    You can also add "options" which are custom buttons with the given text. Each option
    button is mapped to a different integer dialog result.  The result values start at 1
    for the first option and increment by 1 for each additional option.
    For example, if you add options "yes" and "no" in that order, then pressing the "yes"
    button will produce a dialog result of 1, and pressing the "no" button will produce a
    dialog result of 2.  If no options are added, then an "OK" button will automatically be added.
    
     
    You can also set the default button by calling :meth:`setDefaultButton(String) <.setDefaultButton>` where the
    string is the text of the button (the option) that you want to be the default .  For example, if you
    have the options "yes" and "no", you can make the "no" button the default by specifying
    "no" as the defaultOption.
    
     
    You can also add a Cancel button, which will return a result of 0 if pressed. Note that this
    is different than adding an option named "Cancel" which would return a result greater than
    ``0``, depending on where in the order it was added.
    
     
    
    .. _RememberOption:
    
    A "Remember Option" can be added to OptionDialog to
    present the user with a choice for remembering a dialog result and automatically
    returning that result instead of showing the dialog or similar dialogs in the future.
    Note that for simple OK dialogs, there really isn't a meaningful result to remember, other
    than a decision was made not to show the dialog again.
    
     
    The "Remember Option" is represented as a checkBox at the bottom of an OptionDialog.
    The checkBox text will be either "Apply to all", "Remember my decision",
    or "Don't show again" depending on whether :meth:`addApplyToAllOption() <.addApplyToAllOption>`,
    :meth:`addDontShowAgainOption() <.addDontShowAgainOption>`, or :meth:`addRememberMyDecisionOption() <.addRememberMyDecisionOption>` method is
    called.  Each of these methods called will overwrite the previously called method.
    
     
    If the user selects the checkBox, then the dialog result will be remembered.
    In future calls to display that dialog (or any dialog sharing
    the same DialogRememberChoice object), the dialog will first check if has a
    DialogRememberChoice object and that it has a remembered result, and if so, will just return
    the remembered result instead of showing the dialog.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs an OptionDialogBuilder with not even the minimal information required. If
        this constructor is used, then both :meth:`setTitle(String) <.setTitle>` and the
        :meth:`setMessage(String) <.setMessage>` methods must be called
        or else the dialog will have no title or message.
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str]):
        """
        Constructs an OptionDialogBuilder with not even the minimal information required. If
        this constructor is used, then the :meth:`setMessage(String) <.setMessage>` method must be called
        or else the dialog will be blank.
        
        :param java.lang.String or str title: the title of the dialog
        """

    @typing.overload
    def __init__(self, title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Constructs an OptionDialogBuilder with the minimal information required. If no
        other information is set, the builder will create the simplest dialog that has
        a title, message and an "Ok" button.
        
        :param java.lang.String or str title: the title of the dialog.
        :param java.lang.String or str message: the main message to be displayed in the dialog.
        """

    def addApplyToAllOption(self) -> OptionDialogBuilder:
        """
        Adds an "Apply to all" option to the dialog. See `header documentation <RememberOption_>`_ for details.
         
        
        This will replace any previously added "checkBox" options.
        
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def addCancel(self) -> OptionDialogBuilder:
        """
        Adds a cancel button to the OptionDialog.
        
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def addDontShowAgainOption(self) -> OptionDialogBuilder:
        """
        Adds a "Don't show again" option to the dialog. See `header documentation <RememberOption_>`_ for details.
         
        
        This will replace any previously added "checkBox" options.
        
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def addOption(self, optionName: typing.Union[java.lang.String, str]) -> OptionDialogBuilder:
        """
        Adds a button option to the dialog.
        
        :param java.lang.String or str optionName: the name of the button to be added to the dialog
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def addRememberMyDecisionOption(self) -> OptionDialogBuilder:
        """
        Adds a "Remember my decision" option to the dialog. See `header documentation <RememberOption_>`_ for details.
         
        
        This will replace any previously added "checkBox" options.
        
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def build(self) -> OptionDialog:
        """
        Builds an OptionDialog based on the values set in this builder.
        
        :return: an OptionDialog built based on the values set in this builder.
        :rtype: OptionDialog
        """

    def setDefaultButton(self, optionName: typing.Union[java.lang.String, str]) -> OptionDialogBuilder:
        """
        Sets the name of the button to be used as the default button.
        
        :param java.lang.String or str optionName: the name of the option to be the default.
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def setIcon(self, icon: javax.swing.Icon) -> OptionDialogBuilder:
        """
        Sets the Icon for the OptionDialog.
         
        
        If both an Icon and a message type are specified,
        the icon will take precedence.
        
        :param javax.swing.Icon icon: the icon to display in the dialog.
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def setMessage(self, message: typing.Union[java.lang.String, str]) -> OptionDialogBuilder:
        """
        Sets the main message for the OptionDialog.
        
        :param java.lang.String or str message: the main message for the dialog.
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def setMessageType(self, messageType: typing.Union[jpype.JInt, int]) -> OptionDialogBuilder:
        """
        Sets the message type for the OptionDialog which will determine the icon that
        is in the dialog.
        
        :param jpype.JInt or int messageType: used to specify that this dialog is one of the set types.  See
        :obj:`OptionDialog` for the list of defined messageTypes.
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    def setTitle(self, title: typing.Union[java.lang.String, str]) -> OptionDialogBuilder:
        """
        Sets the title for the OptionDialog.
        
        :param java.lang.String or str title: the title for the dialog.
        :return: this builder object.
        :rtype: OptionDialogBuilder
        """

    @typing.overload
    def show(self) -> int:
        """
        Builds and shows an OptionDialog based on the values set in this builder.
        
        :return: the result returned from the OptionDialog after the user selected an option.
        :rtype: int
        """

    @typing.overload
    def show(self, parent: java.awt.Component) -> int:
        """
        Builds and shows an OptionDialog based on the values set in this builder.
        
        :param java.awt.Component parent: the component to use as the OptionDialog's parent when displaying it.
        :return: the result returned from the OptionDialog after the user selected an option.
        :rtype: int
        """


class FindDialogSearcher(java.lang.Object):
    """
    A simple interface for the :obj:`FindDialog` so that it can work for different search clients.
     
    
    The :obj:`CursorPosition` object used by this interface is one that implementations can extend 
    to add extra context to use when searching.  The implementation is responsible for creating the
    locations and these locations will later be handed back to the searcher.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearHighlights(self):
        """
        Clears any active highlights.
        """

    def dispose(self):
        """
        Disposes this searcher.  This does nothing by default.
        """

    def getCursorPosition(self) -> CursorPosition:
        """
        The current cursor position.  Used to search for the next item.
        
        :return: the cursor position.
        :rtype: CursorPosition
        """

    def getEnd(self) -> CursorPosition:
        """
        The end cursor position.  This is used when a search is wrapped while searching backwards to 
        start at the end position.
        
        :return: the end position.
        :rtype: CursorPosition
        """

    def getStart(self) -> CursorPosition:
        """
        Returns the start cursor position.  This is used when a search is wrapped to start at the 
        beginning of the search range.
        
        :return: the start position.
        :rtype: CursorPosition
        """

    def highlightSearchResults(self, location: SearchLocation):
        """
        Called to signal the implementor should highlight the given search location.
        
        :param SearchLocation location: the search result location.
        """

    def search(self, text: typing.Union[java.lang.String, str], cursorPosition: CursorPosition, searchForward: typing.Union[jpype.JBoolean, bool], useRegex: typing.Union[jpype.JBoolean, bool]) -> SearchLocation:
        """
        Perform a search for the next item in the given direction starting at the given cursor 
        position.
        
        :param java.lang.String or str text: the search text.
        :param CursorPosition cursorPosition: the current cursor position.
        :param jpype.JBoolean or bool searchForward: true if searching forward.
        :param jpype.JBoolean or bool useRegex: true if the search text is a regular expression; false if the texts is
        literal text.
        :return: the search result or null if no match was found.
        :rtype: SearchLocation
        """

    def searchAll(self, text: typing.Union[java.lang.String, str], useRegex: typing.Union[jpype.JBoolean, bool]) -> java.util.List[SearchLocation]:
        """
        Search for all matches.
        
        :param java.lang.String or str text: the search text.
        :param jpype.JBoolean or bool useRegex: true if the search text is a regular expression; false if the texts is
        literal text.
        :return: all search results or an empty list.
        :rtype: java.util.List[SearchLocation]
        """

    def setCursorPosition(self, position: CursorPosition):
        """
        Sets the cursor position after a successful search.
        
        :param CursorPosition position: the cursor position.
        """

    @property
    def cursorPosition(self) -> CursorPosition:
        ...

    @cursorPosition.setter
    def cursorPosition(self, value: CursorPosition):
        ...

    @property
    def start(self) -> CursorPosition:
        ...

    @property
    def end(self) -> CursorPosition:
        ...


class VariableHeightPanel(javax.swing.JPanel, javax.swing.Scrollable):
    """
    A panel that is scrollable and uses a VariableHeightLayoutManager that
    deals with components of varying heights.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pack: typing.Union[jpype.JBoolean, bool], hgap: typing.Union[jpype.JInt, int], vgap: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableHeigthPanel.
        
        :param jpype.JBoolean or bool pack: true means to fit as many components on a row, not worrying about lining up 
                columns; false means to fit as many components on a row, and line up the columns 
                as if in a grid
        :param jpype.JInt or int hgap: horizontal gap between components
        :param jpype.JInt or int vgap: vertical gap between components
        """

    def getPreferredLayoutSize(self) -> java.awt.Dimension:
        """
        Return the preferred size of the layout manager of this panel.
        """

    def setUseSingleLineLayout(self, singleLineLayout: typing.Union[jpype.JBoolean, bool]):
        """
        This method is in place because the clients of this panel are not the ones that 
        construct this panel and thus cannot create the desired type of layout at construction time.
        **This method has no effect if this panel was constructed with ``pack`` set to
        false, which makes this panel use a grid style layout.**
        
        :param jpype.JBoolean or bool singleLineLayout: True signals to put all children on a single row; false will use
                as many rows as are needed to layout all of the children.
        """

    @property
    def preferredLayoutSize(self) -> java.awt.Dimension:
        ...


class DefaultDropDownSelectionDataModel(DropDownTextFieldDataModel[T], typing.Generic[T]):

    @typing.type_check_only
    class ObjectStringComparator(java.util.Comparator[java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, data: java.util.List[T], searchConverter: DataToStringConverter[T]):
        ...

    @typing.overload
    def __init__(self, data: java.util.List[T], searchConverter: DataToStringConverter[T], descriptionConverter: DataToStringConverter[T]):
        ...

    @staticmethod
    def getStringModel(strings: java.util.List[java.lang.String]) -> DefaultDropDownSelectionDataModel[java.lang.String]:
        ...


@typing.type_check_only
class DropDownWindowVisibilityListener(java.lang.Object, typing.Generic[T]):
    """
    Simple interface for notifications related to showing and hiding the matching window 
    of the drop-down text field
    """

    class_: typing.ClassVar[java.lang.Class]

    def windowHidden(self, field: DropDownTextField[T]):
        ...

    def windowShown(self, field: DropDownTextField[T]):
        ...


class GComponent(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    HTML_DISABLE_STRING: typing.Final = "html.disable"

    def isHTMLRenderingEnabled(self) -> bool:
        """
        Returns the current HTML rendering enablement of this component.
        
        :return: boolean, true if HTML rendering is allowed
        :rtype: bool
        """

    def setHTMLRenderingEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Enables and disables the rendering of HTML content in this component.  If enabled, this
        component will interpret HTML content when the text this component is showing begins with
        ``<html>``
        
        :param jpype.JBoolean or bool enabled: true to enable HTML rendering; false to disable it
        """

    @staticmethod
    def setHTMLRenderingFlag(comp: javax.swing.JComponent, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the HTML rendering flag for the specified component.
        
        :param javax.swing.JComponent comp: the thing
        :param jpype.JBoolean or bool enabled: boolean, if true html rendering will be allowed
        """

    @staticmethod
    def warnAboutHtmlText(text: typing.Union[java.lang.String, str]):
        """
        Helper function that logs a warning about a string text that looks like it has HTML text.
         
        
        Use this when working with a string in a label that has already disabled HTML rendering.
        
        :param java.lang.String or str text: string to test for HTML and warn about
        """

    @property
    def hTMLRenderingEnabled(self) -> jpype.JBoolean:
        ...

    @hTMLRenderingEnabled.setter
    def hTMLRenderingEnabled(self, value: jpype.JBoolean):
        ...


class PasswordChangeDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], serverType: typing.Union[java.lang.String, str], serverName: typing.Union[java.lang.String, str], userID: typing.Union[java.lang.String, str]):
        ...

    def getPassword(self) -> jpype.JArray[jpype.JChar]:
        ...

    @property
    def password(self) -> jpype.JArray[jpype.JChar]:
        ...


class GHyperlinkComponent(javax.swing.JPanel):
    """
    A component that acts like a label, but adds the ability to render HTML links with a client
    callback for when the link is activated.  Links can be activated by mouse clicking or by
    focusing the link and then pressing Enter or Space.
     
    
    Users can make one simple text link by calling :meth:`addLink(String, Callback) <.addLink>`.  
    Alternatively, users can mix plain text and links by using both :meth:`addText(String) <.addText>` and 
    :meth:`addLink(String, Callback) <.addLink>`.
    """

    @typing.type_check_only
    class FixedSizeTextPane(javax.swing.JTextPane):
        """
        A text pane that can render links.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NonScrollingCaret(javax.swing.text.DefaultCaret):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addLink(self, text: typing.Union[java.lang.String, str], linkActivatedCallback: utility.function.Callback):
        """
        Uses the given text to create a link the user can click.
        
        :param java.lang.String or str text: the text
        :param utility.function.Callback linkActivatedCallback: the callback that will be called when the link is activated
        """

    def addText(self, text: typing.Union[java.lang.String, str]):
        """
        Adds text to this widget that will be displayed as plain text.
        
        :param java.lang.String or str text: the text
        """



__all__ = ["VariableHeightLayoutManager", "PasswordDialog", "DropDownTextFieldDataModel", "DataToStringConverter", "DropDownSelectionChoiceListener", "SearchLocation", "SingleRowLayoutManager", "SelectFromListDialog", "DropDownMultiSelectionTextField", "PopupWindow", "PopupKeyStorePasswordProvider", "EmptyBorderButton", "MultiLineLabel", "SideKickVerticalScrollbar", "InlineComponentTitledBorder", "TitledPanel", "AbstractGCellRenderer", "DialogRememberOption", "EventTrigger", "DropDownTextField", "InlineComponentTitledPanel", "FindDialog", "HyperlinkComponent", "ListSelectionTableDialog", "CursorPosition", "OptionDialog", "OkDialog", "DropDownMultiSelectionChoiceListener", "ListSelectionDialog", "TextComponentSearcher", "AutoLookup", "SmallBorderButton", "DropDownSelectionTextField", "GenericDateCellRenderer", "ScrollableTextArea", "JTreeMouseListenerDelegate", "OptionDialogBuilder", "FindDialogSearcher", "VariableHeightPanel", "DefaultDropDownSelectionDataModel", "DropDownWindowVisibilityListener", "GComponent", "PasswordChangeDialog", "GHyperlinkComponent"]
