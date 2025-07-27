from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.label
import docking.widgets.list
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore


T = typing.TypeVar("T")


class TabListPopup(javax.swing.JDialog, typing.Generic[T]):
    """
    Undecorated dialog for showing a popup window displaying a filterable, scrollable list of tabs
    in a :obj:`GTabPanel`.
    """

    @typing.type_check_only
    class TabListRenderer(docking.widgets.list.GListCellRenderer[docking.widgets.searchlist.SearchListEntry[T]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class GTabBorder(javax.swing.border.EmptyBorder):
    """
    Custom border for the :obj:`GTab`. For non selected tabs, it basically draws a variation of 
    a bevel border that is offset from the top by 2 pixels from the selected tab. Selected tabs
    are drawn at the very top of the component and doesn't draw the bottom border so that it appears
    to connect to the border of the overall tab panel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def paintBorder(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int]):
        """
        Paints the border, and also a bottom shadow border that isn't part of the insets, so that
        the area that doesn't have tabs, still paints a bottom border
        """


@typing.type_check_only
class GTab(javax.swing.JPanel, typing.Generic[T]):
    """
    Component for representing individual tabs within a :obj:`GTabPanel`.
    """

    @typing.type_check_only
    class GTabMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class GTabPanel(javax.swing.JPanel, typing.Generic[T]):
    """
    Component for displaying a list of items as a series of horizontal tabs where exactly one tab
    is selected. 
     
    
    If there are too many tabs to display horizontally, a "hidden tabs" control will be
    displayed that when activated, will display a popup dialog with a scrollable list of all 
    possible values.
     
    
    It also supports the idea of a highlighted tab which represents a value that is not selected,
    but is a candidate to be selected. For example, when the tab panel has focus, using the left
    and right arrows will highlight different tabs. Then pressing enter will cause the highlighted
    tab to be selected. 
     
    
    The clients of this component can also supply functions for customizing the name, icon, and 
    tooltip for values. They can also add consumers for when the selected value changes or a value
    is removed from the tab panel. Clients can also install a predicate for the close tab action so
    they can process it before the value is removed and possibly veto the remove.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tabTypeName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str tabTypeName: the name of the type of values in the tab panel. This will be used to 
        set accessible descriptions.
        """

    def addTab(self, value: T):
        """
        Add a new tab to the panel for the given value.
        
        :param T value: the value for the new tab
        """

    def addTabs(self, values: java.util.List[T]):
        """
        Add tabs for each value in the given list.
        
        :param java.util.List[T] values: the values to add tabs for
        """

    def getHiddenTabs(self) -> java.util.List[T]:
        """
        Returns a list of all tab values that are not visible.
        
        :return: a list of all tab values that are not visible
        :rtype: java.util.List[T]
        """

    def getHighlightedTabValue(self) -> T:
        """
        Returns the currently highlighted tab if a tab is highlighted. Note: the selected tab can
        never be highlighted.
        
        :return: the currently highlighted tab or null if no tab is highligted
        :rtype: T
        """

    def getSelectedTabValue(self) -> T:
        """
        Returns the currently selected tab. If the panel is not empty, there will always be a
        selected tab.
        
        :return: the currently selected tab or null if the panel is empty
        :rtype: T
        """

    def getTab(self, value: T) -> javax.swing.JPanel:
        ...

    def getTabCount(self) -> int:
        """
        Returns the total number of tabs both visible and hidden.
        
        :return: the total number of tabs both visible and hidden.
        :rtype: int
        """

    def getTabValues(self) -> java.util.List[T]:
        """
        Returns a list of values for all the tabs in the panel.
        
        :return: a list of values for all the tabs in the panel
        :rtype: java.util.List[T]
        """

    def getValueFor(self, event: java.awt.event.MouseEvent) -> T:
        """
        Returns the value of the tab that generated the given mouse event. If the mouse event
        is not from one of the tabs, then null is returned.
        
        :param java.awt.event.MouseEvent event: the MouseEvent to get a value for
        :return: the value of the tab that generated the mouse event
        :rtype: T
        """

    def getVisibleTabs(self) -> java.util.List[T]:
        """
        Returns a list of all tab values that are visible.
        
        :return: a list of all tab values that are visible
        :rtype: java.util.List[T]
        """

    def hasHiddenTabs(self) -> bool:
        """
        Returns true if not all tabs are visible in the tab panel.
        
        :return: true if not all tabs are visible in the tab panel
        :rtype: bool
        """

    def highlightNextPreviousTab(self, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Moves the highlight to the next or previous tab from the current highlight. If there is no
        current highlight, it will highlight the next or previous tab from the selected tab.
        
        :param jpype.JBoolean or bool forward: true moves the highlight to the right; otherwise move the highlight to the
        left
        """

    def highlightTab(self, value: T):
        """
        Sets the tab for the given value to be highlighted. If the value is selected, then the
        highlighted tab will be set to null.
        
        :param T value: the value to highlight its tab
        """

    def isShowingTabList(self) -> bool:
        """
        Returns true if the popup tab list is showing.
        
        :return: true if the popup tab list is showing
        :rtype: bool
        """

    def isVisibleTab(self, value: T) -> bool:
        """
        Returns true if the tab for the given value is visible on the tab panel.
        
        :param T value: the value to test if visible
        :return: true if the tab for the given value is visible on the tab panel
        :rtype: bool
        """

    def refreshTab(self, value: T):
        """
        Informs the tab panel that some displayable property about the value has changed and the
        tabs label, icon, and tooltip need to be updated.
        
        :param T value: the value that has changed
        """

    def removeTab(self, value: T):
        """
        Removes the tab with the given value.
        
        :param T value: the value for which to remove its tab
        """

    def removeTabs(self, values: collections.abc.Sequence):
        """
        Remove tabs for all values in the given list.
        
        :param collections.abc.Sequence values: the values to remove from the tab panel
        """

    def selectTab(self, value: T):
        """
        Makes the tab for the given value be the selected tab.
        
        :param T value: the value whose tab is to be selected
        """

    def setCloseTabConsumer(self, closeTabConsumer: java.util.function.Consumer[T]):
        """
        Sets the predicate that will be called before removing a tab via the gui close control. Note
        that that tab panel's default action is to remove the tab value, but if you set your own
        consumer, you have the responsibility to remove the value.
        
        :param java.util.function.Consumer[T] closeTabConsumer: the consumer called when the close gui control is clicked.
        """

    def setIconFunction(self, iconFunction: java.util.function.Function[T, javax.swing.Icon]):
        """
        Sets a function to be used to generated an icon for a given value.
        
        :param java.util.function.Function[T, javax.swing.Icon] iconFunction: the function to generate icons for values
        """

    def setIgnoreFocus(self, ignoreFocusLost: typing.Union[jpype.JBoolean, bool]):
        ...

    def setNameFunction(self, nameFunction: java.util.function.Function[T, java.lang.String]):
        """
        Sets a function to be used to generated a display name for a given value. The display name
        is used in the tab, the filter, and the accessible description.
        
        :param java.util.function.Function[T, java.lang.String] nameFunction: the function to generate display names for values
        """

    def setSelectedTabConsumer(self, selectedTabConsumer: java.util.function.Consumer[T]):
        """
        Sets the consumer to be notified when the selected tab changes.
        
        :param java.util.function.Consumer[T] selectedTabConsumer: the consumer to be notified when the selected tab changes
        """

    def setShowTabsAlways(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not tabs should be display when there is only one tab.
        
        :param jpype.JBoolean or bool b: true to show one tab; false collapses tab panel when only one tab exists
        """

    def setToolTipFunction(self, toolTipFunction: java.util.function.Function[T, java.lang.String]):
        """
        Sets a function to be used to generated an tooltip for a given value.
        
        :param java.util.function.Function[T, java.lang.String] toolTipFunction: the function to generate tooltips for values
        """

    def showTabList(self, show: typing.Union[jpype.JBoolean, bool]):
        """
        Shows a popup dialog window with a filterable and scrollable list of all tab values.
        
        :param jpype.JBoolean or bool show: true to show the popup list, false to close the popup list
        """

    @property
    def showingTabList(self) -> jpype.JBoolean:
        ...

    @property
    def highlightedTabValue(self) -> T:
        ...

    @property
    def valueFor(self) -> T:
        ...

    @property
    def selectedTabValue(self) -> T:
        ...

    @property
    def hiddenTabs(self) -> java.util.List[T]:
        ...

    @property
    def tab(self) -> javax.swing.JPanel:
        ...

    @property
    def tabValues(self) -> java.util.List[T]:
        ...

    @property
    def visibleTabs(self) -> java.util.List[T]:
        ...

    @property
    def visibleTab(self) -> jpype.JBoolean:
        ...

    @property
    def tabCount(self) -> jpype.JInt:
        ...


class HiddenValuesButton(docking.widgets.label.GDLabel):
    """
    Component displayed when not all tabs fit on the tab panel and is used to display a popup
    list of all tabs.
    """

    class_: typing.ClassVar[java.lang.Class]


class GTabPanelBorder(javax.swing.border.EmptyBorder):
    """
    Custom border for the :obj:`GTab`.
    """

    class_: typing.ClassVar[java.lang.Class]
    MARGIN_SIZE: typing.Final = 2
    BOTTOM_SOLID_COLOR_SIZE: typing.Final = 3

    def __init__(self):
        ...

    def paintBorder(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int]):
        """
        Paints the border, and also a bottom shadow border that isn't part of the insets, so that
        the area that doesn't have tabs, still paints a bottom border
        """



__all__ = ["TabListPopup", "GTabBorder", "GTab", "GTabPanel", "HiddenValuesButton", "GTabPanelBorder"]
