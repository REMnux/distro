from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore


E = typing.TypeVar("E")
T = typing.TypeVar("T")


class GListAutoLookup(docking.widgets.AutoLookup, typing.Generic[T]):
    """
    :obj:`AutoLookup` implementation for :obj:`GList`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, list: GList[T]):
        ...


class GList(javax.swing.JList[T], docking.widgets.GComponent, typing.Generic[T]):
    """
    A sub-class of JList that provides an auto-lookup feature.
     
    
    The user can begin typing the first few letters of a desired
    list element and the selection will automatically navigate to it.
     
    
    HTML rendering is disabled by default.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructs a ``GhidraList`` with an empty model.
        """

    @typing.overload
    def __init__(self, listData: jpype.JArray[T]):
        """
        Constructs a ``GhidraList`` that displays the elements in
        the specified array.  This constructor just delegates to the
        ``ListModel`` constructor.
        
        :param jpype.JArray[T] listData: the array of Objects to be loaded into the data model
        """

    @typing.overload
    def __init__(self, listData: java.util.Vector[T]):
        """
        Constructs a ``GhidraList`` that displays the elements in
        the specified ``Vector``.  This constructor just
        delegates to the ``ListModel`` constructor.
        
        :param java.util.Vector[T] listData: the ``Vector`` to be loaded into the data model
        """

    @typing.overload
    def __init__(self, dataModel: javax.swing.ListModel[T]):
        """
        Constructs a ``GhidraList`` that displays the elements in the
        specified, non-``null`` model. 
        All ``GhidraList`` constructors delegate to this one.
        
        :param javax.swing.ListModel[T] dataModel: the data model for this list
        :raises IllegalArgumentException: if ``dataModel`` is ``null``
        """

    def setAutoLookupTimeout(self, timeout: typing.Union[jpype.JLong, int]):
        """
        Sets the delay between keystrokes after which each keystroke is considered a new lookup
        
        :param jpype.JLong or int timeout: the timeout
        
        .. seealso::
        
            | :obj:`AutoLookup.KEY_TYPING_TIMEOUT`
        """


class ListPanel(javax.swing.JPanel, typing.Generic[T]):
    """
    This class provides a panel that contains a JList component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new ListPanel.
        """

    def addListSelectionListener(self, listener: javax.swing.event.ListSelectionListener):
        """
        Adds a :obj:`ListSelectionListener`
        
        :param javax.swing.event.ListSelectionListener listener: the listener to add
        """

    def ensureIndexIsVisible(self, index: typing.Union[jpype.JInt, int]):
        """
        Scroll viewport such that the index is visible.
        
        :param jpype.JInt or int index: the index of the item in the list to make visible.
        """

    def getList(self) -> javax.swing.JList[T]:
        """
        Return the JList component.
        
        :return: the JList component.
        :rtype: javax.swing.JList[T]
        """

    def getListModel(self) -> javax.swing.ListModel[T]:
        """
        Get the list model for the list.
        
        :return: the list model for the list.
        :rtype: javax.swing.ListModel[T]
        """

    def getSelectedIndex(self) -> int:
        """
        Get the index of the selected item in the list.
        
        :return: the index of the selected item in the list.
        :rtype: int
        """

    def getSelectedValue(self) -> T:
        """
        Returns the first selected value in the list or null if nothing is selected.
        
        :return: the first selected value in the list or null if nothing is selected.
        :rtype: T
        """

    def getSelectedValues(self) -> java.util.List[T]:
        """
        Returns an array of all the selected items.
        
        :return: an array of all the selected items.
        :rtype: java.util.List[T]
        """

    def isSelectionEmpty(self) -> bool:
        """
        Returns true if no list items are selected.
        
        :return: true if no list items are selected.
        :rtype: bool
        """

    @typing.overload
    def issueWarning(self):
        """
        Displays a standard warning message about no selected objects
        in the list.
        """

    @typing.overload
    def issueWarning(self, msg: typing.Union[java.lang.String, str], title: typing.Union[java.lang.String, str]):
        """
        Displays any warning message.
        
        :param java.lang.String or str msg: the warning message to display.
        :param java.lang.String or str title: the title of the dialog to display.
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Simple test for ListPanel class.
        
        :param jpype.JArray[java.lang.String] args: test args not used
        """

    def refreshList(self, dataList: jpype.JArray[T]):
        """
        replaces the list contents with the new list.
        
        :param jpype.JArray[T] dataList: the new list for the contents.
        """

    def removeListSelectionListener(self, listener: javax.swing.event.ListSelectionListener):
        """
        Removes a :obj:`ListSelectionListener`
        
        :param javax.swing.event.ListSelectionListener listener: the listener to remove
        """

    def setCellRenderer(self, r: javax.swing.ListCellRenderer[T]):
        """
        Get the cell renderer for the list.
        
        :param javax.swing.ListCellRenderer[T] r: the cell renderer to use.
        """

    def setDoubleClickActionListener(self, listener: java.awt.event.ActionListener):
        """
        Sets the listener to be notified whenever a list item is doubleClicked.
        
        :param java.awt.event.ActionListener listener: the Listener to be notified.  If listener can be null, which
        means no one is to be notified.
        """

    def setKeyListener(self, l: java.awt.event.KeyListener):
        ...

    def setListData(self, data: jpype.JArray[T]):
        """
        Sets the list data
        
        :param jpype.JArray[T] data: the data
        """

    def setListModel(self, listModel: javax.swing.ListModel[T]):
        """
        Sets a list model for the internal list to use.
        
        :param javax.swing.ListModel[T] listModel: the list model to use.
        """

    def setListSelectionListener(self, listener: javax.swing.event.ListSelectionListener):
        """
        Sets the listener to be notified when the selection changes.
        
        :param javax.swing.event.ListSelectionListener listener: the Listener to be notified.  If listener can be null, which
        means no one is to be notified.
        """

    def setListTitle(self, listTitle: typing.Union[java.lang.String, str]):
        """
        Places a title just above the scrolling list.
        
        :param java.lang.String or str listTitle: the title to use.
        """

    def setMouseListener(self, l: java.awt.event.MouseListener):
        """
        Set the mouse listener for the list.
        
        :param java.awt.event.MouseListener l: the mouse listener to set.
        """

    def setSelectedIndex(self, i: typing.Union[jpype.JInt, int]):
        """
        Select the item at the given index.
        
        :param jpype.JInt or int i: the index at which to get the item.
        """

    def setSelectedValue(self, item: T):
        """
        Selects the item.
        
        :param T item: the item to select
        """

    def setSelectionMode(self, selectionMode: typing.Union[jpype.JInt, int]):
        """
        Sets the selection mode for the list.
        See JList for allowed Selection modes
        
        :param jpype.JInt or int selectionMode: the selectionMode to use.
        """

    @property
    def listModel(self) -> javax.swing.ListModel[T]:
        ...

    @listModel.setter
    def listModel(self, value: javax.swing.ListModel[T]):
        ...

    @property
    def selectedValues(self) -> java.util.List[T]:
        ...

    @property
    def list(self) -> javax.swing.JList[T]:
        ...

    @property
    def selectionEmpty(self) -> jpype.JBoolean:
        ...

    @property
    def selectedIndex(self) -> jpype.JInt:
        ...

    @selectedIndex.setter
    def selectedIndex(self, value: jpype.JInt):
        ...

    @property
    def selectedValue(self) -> T:
        ...

    @selectedValue.setter
    def selectedValue(self, value: T):
        ...


class ListRendererMouseEventForwarder(java.awt.event.MouseAdapter):
    """
    A listener designed to forward events from a JList to its renderer.  This listener allows
    renderers to embed components in the renderer and gives them the mouse events they need to 
    interact with the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GComboBoxCellRenderer(GListCellRenderer[E], typing.Generic[E]):
    """
    Provides a common implementation of a combo box drop-down list renderer, for use with 
    JComboBoxes.
     
    
    HTML rendering defaults to disabled.  See :meth:`setHTMLRenderingEnabled(boolean) <.setHTMLRenderingEnabled>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createDefaultTextRenderer(cellToTextMappingFunction: java.util.function.Function[E, java.lang.String]) -> GComboBoxCellRenderer[E]:
        """
        Returns a new GComboBoxCellRenderer that maps the list's data instance to a string used in 
        the cell.
         
        
        Use this if you only need to provide a way to get the string value from the type being shown
        in the list.
        
        :param java.util.function.Function[E, java.lang.String] cellToTextMappingFunction: a function that maps your custom type to a string value
        :return: new GComboBoxCellRenderer instance
        :rtype: GComboBoxCellRenderer[E]
        """


class GListCellRenderer(docking.widgets.AbstractGCellRenderer, javax.swing.ListCellRenderer[E], typing.Generic[E]):
    """
    Provides a common implementation of a list renderer, for use in both JList and JComboBox.
     
    
    HTML rendering defaults to disabled.  See :meth:`setHTMLRenderingEnabled(boolean) <.setHTMLRenderingEnabled>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a new GListCellRenderer.
        """

    @staticmethod
    def createDefaultTextRenderer(cellToTextMappingFunction: java.util.function.Function[E, java.lang.String]) -> GListCellRenderer[E]:
        """
        Returns a new ListCellRenderer that maps the list's data instance to a string used in the cell.
         
        
        Use this if you only need to provide a way to get the string value from the type being shown
        in the list.
        
        :param java.util.function.Function[E, java.lang.String] cellToTextMappingFunction: a function that maps your custom type to a string value
        :return: new GListCellRenderer instance
        :rtype: GListCellRenderer[E]
        """



__all__ = ["GListAutoLookup", "GList", "ListPanel", "ListRendererMouseEventForwarder", "GComboBoxCellRenderer", "GListCellRenderer"]
