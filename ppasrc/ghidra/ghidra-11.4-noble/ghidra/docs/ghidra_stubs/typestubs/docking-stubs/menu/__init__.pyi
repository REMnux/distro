from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
import ghidra.util
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.plaf # type: ignore


T = typing.TypeVar("T")


class DockingMenuItemUI(javax.swing.plaf.MenuItemUI):
    """
    This class exists to make menu items display content with proper alignment whether or not
    they are displaying an icon.  That is, this class will introduce padding for absent icons
    within menu items so that the item lines up with those items that do contain icons.
     
    
    This class has an additional feature that allows clients to display menu item content in a
    tabular fashion.  A menu item using this UI can contain some combination of the of the following
    items, in the given order:
     
    [Checkbox][Icon][Menu Item Content][Menu Pull-right/Accelerator Text]
     
    To display the **Menu Item Content** in a tabular fashion, use the ``'\t'`` character
    to delimit the data into columns.  This class will align all menu items in the given menu
    based upon the largest number of columns in the group and the largest width for each column.
    """

    class MenuTabulator(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        @staticmethod
        def get(c: javax.swing.JMenuItem) -> DockingMenuItemUI.MenuTabulator:
            ...

        def getWidth(self) -> int:
            ...

        @staticmethod
        @typing.overload
        def tabulate(c: javax.swing.JMenuItem) -> DockingMenuItemUI.MenuTabulator:
            ...

        @typing.overload
        def tabulate(self, c: javax.swing.JComponent, tabularText: typing.Union[java.lang.String, str]):
            ...

        @property
        def width(self) -> jpype.JInt:
            ...


    class SwitchGraphics2D(java.awt.Graphics2D):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, g: java.awt.Graphics2D):
            ...

        def setDoDraw(self, doDraw: typing.Union[jpype.JBoolean, bool]):
            ...

        def setDoFill(self, doFill: typing.Union[jpype.JBoolean, bool]):
            ...

        def setDoImage(self, doImage: typing.Union[jpype.JBoolean, bool]):
            ...

        def setDoText(self, doText: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createUI(c: javax.swing.JComponent) -> DockingMenuItemUI:
        ...

    def paintText(self, sg: DockingMenuItemUI.SwitchGraphics2D, c: javax.swing.JMenuItem, t: DockingMenuItemUI.MenuTabulator):
        ...


class HorizontalRuleAction(docking.action.DockingAction):
    """
    An action that can be added to a menu in order to separate menu items into groups
    """

    @typing.type_check_only
    class LabeledSeparator(javax.swing.JSeparator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], topName: typing.Union[java.lang.String, str], bottomName: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str owner: the action owner
        :param java.lang.String or str topName: the name that will appear above the separator bar
        :param java.lang.String or str bottomName: the name that will appear below the separator bar
        """


class MultipleActionDockingToolbarButton(docking.widgets.EmptyBorderButton):

    @typing.type_check_only
    class IconWithDropDownArrow(javax.swing.Icon):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PopupMouseListener(java.awt.event.MouseAdapter, javax.swing.event.PopupMenuListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parentListeners: jpype.JArray[java.awt.event.MouseListener]):
            ...


    @typing.type_check_only
    class HoverChangeListener(javax.swing.event.ChangeListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, delegateAction: docking.action.DockingActionIf):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: docking.action.MultiActionDockingActionIf):
        ...

    def getPopupPoint(self) -> java.awt.Point:
        ...

    @property
    def popupPoint(self) -> java.awt.Point:
        ...


class MultiStateButton(javax.swing.JButton, typing.Generic[T]):
    """
    A button that has a drop-down list of choosable :obj:`ButtonState`s. When a state is selected,
    it changes the behavior of the action associated with the button. This code is based on code 
    for the :obj:`MultipleActionDockingToolbarButton`.
    """

    @typing.type_check_only
    class ArrowIcon(javax.swing.Icon):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PopupMouseListener(java.awt.event.MouseAdapter, javax.swing.event.PopupMenuListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parentListeners: jpype.JArray[java.awt.event.MouseListener]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, buttonStates: java.util.List[ButtonState[T]]):
        ...

    def getPopupPoint(self) -> java.awt.Point:
        ...

    def setButtonStates(self, buttonStates: java.util.List[ButtonState[T]]):
        ...

    def setCurrentButtonState(self, buttonState: ButtonState[T]):
        """
        Sets the active button state for this button.
        
        :param ButtonState[T] buttonState: the button state to be made active
        """

    def setSelectedStateByClientData(self, clientData: T):
        """
        Sets the active button state to the state that is associated with the given client data.
        
        :param T clientData: the client data to make its associated button state the active state
        """

    def setStateChangedListener(self, consumer: java.util.function.Consumer[ButtonState[T]]):
        """
        Sets a consumer to be called when the user changes the active :obj:`ButtonState`.
        
        :param java.util.function.Consumer[ButtonState[T]] consumer: the consumer to be called when the button state changes
        """

    @property
    def popupPoint(self) -> java.awt.Point:
        ...


class MenuGroupMap(java.lang.Object):
    """
    Maps menuPaths to groups
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMenuGroup(self, menuPath: jpype.JArray[java.lang.String]) -> str:
        """
        Returns the group for the given menu path
        
        :param jpype.JArray[java.lang.String] menuPath: the menu path for which to find its group
        :return: the menu group
        :rtype: str
        """

    def getMenuSubGroup(self, menuPath: jpype.JArray[java.lang.String]) -> str:
        """
        Returns the menu subgroup string for the given menu path.  This string is used to perform
        sorting of menu items that exist in the same group.
        
        :param jpype.JArray[java.lang.String] menuPath: the menu path for which to find its group
        :return: the menu sub-group
        :rtype: str
        """

    def setMenuGroup(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str], menuSubGroup: typing.Union[java.lang.String, str]):
        """
        Sets the group for the given menuPath
        
        :param jpype.JArray[java.lang.String] menuPath: the menuPath for which to assign a group
        :param java.lang.String or str group: the name of the group for the action with the given menu path
        :param java.lang.String or str menuSubGroup: the name used for sorting items in the same ``group``.  If this 
                value is :obj:`MenuData.NO_SUBGROUP`, then sorting is based upon the name of the
                menu item.
        """

    @property
    def menuSubGroup(self) -> java.lang.String:
        ...

    @property
    def menuGroup(self) -> java.lang.String:
        ...


class ToolBarManager(java.lang.Object):
    """
    Manages the actions to be displayed in the toolbar.  Organizes them by group.
    """

    @typing.type_check_only
    class GroupComparator(java.util.Comparator[java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolBarItemManagerComparator(java.util.Comparator[ToolBarItemManager]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: docking.DockingWindowManager):
        ...

    def addAction(self, action: docking.action.DockingActionIf):
        ...

    def clearActions(self):
        ...

    def dispose(self):
        """
        Releases all resources.  Makes this object unusable.
        """

    def getAction(self, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        ...

    def getToolBar(self) -> javax.swing.JComponent:
        """
        Returns a component to be used as a toolbar.
        
        :return: the toolbar component.
        :rtype: javax.swing.JComponent
        """

    def isEmpty(self) -> bool:
        ...

    def removeAction(self, action: docking.action.DockingActionIf):
        """
        Removes the action from the toolbar.
        
        :param docking.action.DockingActionIf action: the action to be removed.
        """

    @property
    def toolBar(self) -> javax.swing.JComponent:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MultiActionDockingAction(docking.action.DockingAction, docking.action.MultiActionDockingActionIf):
    """
    A class that supports multiple sub-actions, as well as a primary action.  This is useful for
    actions that perform navigation operations.
     
    
    Clients may add actions to this class with the intention that they will be accessible to the 
    user via a GUI; for example, from a popup menu.
     
    
    Actions added must have menu bar data set.
    
     
    This action has a drop-down button that shows a popup menu of all available actions for
    the user to execute.
    
     
    
    If the user executes this action directly (by clicking the non-popup section of the button), 
    then :meth:`actionPerformed(ActionContext) <.actionPerformed>` will be called.   By default, when the button is 
    clicked, the popup menu is shown.  To change this behavior, override 
    :meth:`actionPerformed(ActionContext) <.actionPerformed>`.   If an item of the popup menu is clicked, then the
    :meth:`DockingAction.actionPerformed(ActionContext) <DockingAction.actionPerformed>` method of the sub-action that was executed 
    will be called.
    
    
    .. seealso::
    
        | :obj:`MultiStateDockingAction`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...

    def actionPerformed(self, context: docking.ActionContext):
        """
        This method is called when the user clicks the button **when this action is used as part of
        the default :obj:`DockingAction` framework.** 
         
        This is the callback to be overridden when the child wishes to respond to user button
        presses that are on the button and not the drop-down.  The default behavior is to show the
        popup menu when the button is clicked.
        """

    @staticmethod
    def createSeparator() -> docking.action.DockingActionIf:
        ...

    def setActions(self, actionList: java.util.List[docking.action.DockingActionIf]):
        ...


class ButtonState(java.lang.Object, typing.Generic[T]):
    """
    Defines one "state" for a :obj:`MultiStateButton`. Each button state represents one choice from
    a drop-down list of choices on the button. Each state provides information on what the button
    text should be when it is the active state, the text in the drop-down for picking the state, text
    for a tooltip description, and finally client data that the client can use to store info for
    processing the action when that state is active.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, buttonText: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], clientData: T):
        """
        Constructor
        
        :param java.lang.String or str buttonText: the text to display as both the drop-down choice and the active button text
        :param java.lang.String or str description: the tooltip for this state
        :param T clientData: the client data for this state
        """

    @typing.overload
    def __init__(self, buttonText: typing.Union[java.lang.String, str], menuText: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], clientData: T):
        """
        Constructor
        
        :param java.lang.String or str buttonText: the text to display in the button when this state is active
        :param java.lang.String or str menuText: the text to display in the drop-down list
        :param java.lang.String or str description: the tooltip for this state
        :param T clientData: the client data for this state
        """

    def getButtonText(self) -> str:
        ...

    def getClientData(self) -> T:
        ...

    def getDescription(self) -> str:
        ...

    def getMenuText(self) -> str:
        ...

    @property
    def buttonText(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def clientData(self) -> T:
        ...

    @property
    def menuText(self) -> java.lang.String:
        ...


class MenuBarManager(MenuGroupListener):
    """
    Manages the main menu bar on the main frame
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, actionHandler: MenuHandler, menuGroupMap: MenuGroupMap):
        ...

    def addAction(self, action: docking.action.DockingActionIf):
        """
        Adds an action to the menu
        
        :param docking.action.DockingActionIf action: the action to be added
        """

    def clearActions(self):
        ...

    def dispose(self):
        """
        Releases all resources and makes this object unusable.
        """

    def getMenuBar(self) -> javax.swing.JMenuBar:
        ...

    def menuGroupChanged(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str]):
        """
        Handles changes to the Menu Group
        
        :param jpype.JArray[java.lang.String] menuPath: the menu path whose group changed.
        :param java.lang.String or str group: the new group for the given menuPath.
        """

    def removeAction(self, action: docking.action.DockingActionIf):
        """
        Removes an action from the menu.
        
        :param docking.action.DockingActionIf action: the action to be removed.
        """

    @property
    def menuBar(self) -> javax.swing.JMenuBar:
        ...


class NonToolbarMultiStateAction(MultiStateDockingAction[T], typing.Generic[T]):
    """
    A class for clients that wish to create a button that has multiple states, controlled by a
    drop-down menu.  Further, this action is not meant to be added to a toolbar.  If you wish 
    for this action to appear in the toolbar, then extend :obj:`MultiStateDockingAction` 
    instead.
     
     
    To use this class, extend it, overriding the 
    :meth:`actionStateChanged(ActionState, EventTrigger) <.actionStateChanged>` callback.  Call 
    :meth:`createButton() <.createButton>` and add the return value to your UI.
    
    
    .. seealso::
    
        | :obj:`MultiStateDockingAction`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...


class DockingCheckboxMenuItemUI(DockingMenuItemUI):
    """
    Overrides the painting behavior of the BasicCheckBoxMenuItemUI
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createUI(c: javax.swing.JComponent) -> DockingCheckboxMenuItemUI:
        ...


class DialogToolbarButton(docking.EmptyBorderToggleButton):
    """
    Toolbar buttons for Dialogs.
     
     
    This class exists because dialog actions are not added to the regular tool's toolbars.  This
    means that we have to create the dialog's toolbars outside of the tool.  Thus, this class
    mimics how the tool's toolbar buttons are created.
    """

    @typing.type_check_only
    class MouseOverMouseListener(java.awt.event.MouseAdapter):
        """
        Activates/deactivates this button's action for things like help
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: docking.action.DockingActionIf, contextProvider: docking.action.ActionContextProvider):
        ...

    def getDockingAction(self) -> docking.action.DockingActionIf:
        ...

    @property
    def dockingAction(self) -> docking.action.DockingActionIf:
        ...


@typing.type_check_only
class DockingToolBarUtils(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class MenuHandler(javax.swing.event.MenuListener, javax.swing.event.PopupMenuListener):
    """
    ``MenuHandler`` provides a listener interface for menus.
    This interface has been provided to allow the listener to
    manage focus and help behavior.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def menuCanceled(self, e: javax.swing.event.MenuEvent):
        """
        Invoked when a menu is cancelled (not sure if this is ever invoked)
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.MenuListener.menuCanceled(javax.swing.event.MenuEvent)`
        """

    def menuDeselected(self, e: javax.swing.event.MenuEvent):
        """
        Invoked when a menu is no longer selected.  This is always preceded
        by a menuSelected invocation.  This is invoked prior to the processMenuAction 
        if an action item is selected.
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.MenuListener.menuDeselected(javax.swing.event.MenuEvent)`
        """

    def menuItemEntered(self, action: docking.action.DockingActionIf):
        """
        Invoked when the mouse highlights a menu item.
        
        :param docking.action.DockingActionIf action: associated action.
        """

    def menuItemExited(self, action: docking.action.DockingActionIf):
        """
        Invoked when the mouse exits a menu item.
        
        :param docking.action.DockingActionIf action: associated action.
        """

    def menuSelected(self, e: javax.swing.event.MenuEvent):
        """
        Invoked when a menu is selected.
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.MenuListener.menuSelected(javax.swing.event.MenuEvent)`
        """

    def popupMenuCanceled(self, e: javax.swing.event.PopupMenuEvent):
        """
        This method is called when the popup menu is canceled
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.PopupMenuListener.popupMenuCanceled(javax.swing.event.PopupMenuEvent)`
        """

    def popupMenuWillBecomeInvisible(self, e: javax.swing.event.PopupMenuEvent):
        """
        This method is called before the popup menu becomes invisible
        Note that a JPopupMenu can become invisible any time
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.PopupMenuListener.popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent)`
        """

    def popupMenuWillBecomeVisible(self, e: javax.swing.event.PopupMenuEvent):
        """
        This method is called before the popup menu becomes visible
        
        
        .. seealso::
        
            | :obj:`javax.swing.event.PopupMenuListener.popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent)`
        """

    def processMenuAction(self, action: docking.action.DockingActionIf, event: java.awt.event.ActionEvent):
        """
        Invoked when a menu action item is selected.
        
        :param docking.action.DockingActionIf action: associated action.
        :param java.awt.event.ActionEvent event: event details.
        """


@typing.type_check_only
class ManagedMenuItem(java.lang.Object):
    """
    Common interface for MenuItemManager and MenuMangers that are sub-menus.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        """
        Releases all resources used by this object.
        """

    def getGroup(self) -> str:
        """
        Returns the group for this menu or menuItem.
        """

    def getMenuItem(self) -> javax.swing.JMenuItem:
        """
        Returns the MenuItem if this is a MenuItemManager or the Menu if this is a MenuManger.
        (Menus are MenuItems)
        """

    def getMenuItemText(self) -> str:
        """
        Returns the text of the menu item.
        
        :return: the text of the menu item.
        :rtype: str
        """

    def getSubGroup(self) -> str:
        """
        Returns a sub group string that species how this item should be grouped within its 
        primary group, as defined by :meth:`getGroup() <.getGroup>`.
        """

    def isEmpty(self) -> bool:
        ...

    def removeAction(self, action: docking.action.DockingActionIf) -> bool:
        ...

    @property
    def menuItemText(self) -> java.lang.String:
        ...

    @property
    def subGroup(self) -> java.lang.String:
        ...

    @property
    def menuItem(self) -> javax.swing.JMenuItem:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...

    @property
    def group(self) -> java.lang.String:
        ...


class MultiStateDockingAction(docking.action.DockingAction, typing.Generic[T]):
    """
    An action that can be in one of multiple states.
     
     
    
    The button of this action has a drop-down icon that allows users to change the state of the
    button. As the user changes the state of this action,
    :meth:`actionStateChanged(ActionState, EventTrigger) <.actionStateChanged>` will be called. Clients may also use the
    button of this action to respond to button presses by overriding
    :meth:`actionPerformed(ActionContext) <.actionPerformed>`.
    
     
    
    This action is intended primarily for use as toolbar actions. Alternatively, some clients use
    this action to add a button to custom widgets. In the custom use case, clients should use
    :obj:`NonToolbarMultiStateAction`.
    
    
    .. seealso::
    
        | :obj:`MultiActionDockingAction`
    """

    @typing.type_check_only
    class ActionStateToggleAction(docking.action.ToggleDockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionStateAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str name: the action name
        :param java.lang.String or str owner: the owner
        """

    def actionPerformed(self, context: docking.ActionContext):
        """
        This method is called when the user clicks the button **when this action is used as part of
        the default :obj:`DockingAction` framework.**
         
         
        
        This is the callback to be overridden when the child wishes to respond to user button presses
        that are on the button and not the drop-down. The default behavior is to show the popup menu
        when the button is clicked.
        """

    def actionStateChanged(self, newActionState: ActionState[T], trigger: docking.widgets.EventTrigger):
        """
        This method will be called as the user changes the selected button state
        
        :param ActionState[T] newActionState: the newly selected state
        :param docking.widgets.EventTrigger trigger: the source of the event
        """

    def addActionState(self, actionState: ActionState[T]):
        """
        Add the supplied ``ActionState``.
        
        :param ActionState[T] actionState: the ``ActionState`` to add
        """

    def getAllActionStates(self) -> java.util.List[ActionState[T]]:
        ...

    def getCurrentState(self) -> ActionState[T]:
        ...

    def getCurrentUserData(self) -> T:
        ...

    def getToolTipText(self) -> str:
        ...

    def setActionStates(self, newStates: java.util.List[ActionState[T]]):
        ...

    def setCurrentActionState(self, actionState: ActionState[T]):
        ...

    def setCurrentActionStateByUserData(self, t: T):
        ...

    def setCurrentActionStateWithTrigger(self, actionState: ActionState[T], trigger: docking.widgets.EventTrigger):
        ...

    def setDefaultIcon(self, icon: javax.swing.Icon):
        """
        Sets the icon to use if the active action state does not supply an icon.
         
         
        
        This is useful if you wish for your action states to not use icon, but desire the action
        itself to have an icon.
        
        :param javax.swing.Icon icon: the icon
        """

    def setGroup(self, group: typing.Union[java.lang.String, str]):
        ...

    def setSubGroup(self, subGroup: typing.Union[java.lang.String, str]):
        ...

    def setUseCheckboxForIcons(self, useCheckboxForIcons: typing.Union[jpype.JBoolean, bool]):
        """
        Overrides the default icons for actions shown in popup menu of the multi-state action.
         
         
        
        By default, the popup menu items will use the icons as provided by the :obj:`ActionState`.
        By passing true to this method, icons will not be used in the popup menu. Instead, a checkbox
        icon will be used to show the active action state.
        
        :param jpype.JBoolean or bool useCheckboxForIcons: true to use a checkbox
        """

    @property
    def currentUserData(self) -> T:
        ...

    @property
    def allActionStates(self) -> java.util.List[ActionState[T]]:
        ...

    @property
    def currentState(self) -> ActionState[T]:
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...


class MenuGroupListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def menuGroupChanged(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class InvertableImageIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, imageIcon: javax.swing.ImageIcon):
        ...

    def getIconHeight(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`javax.swing.Icon.getIconHeight()`
        """

    def getIconWidth(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`javax.swing.Icon.getIconWidth()`
        """

    def isInverted(self) -> bool:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`javax.swing.Icon.paintIcon(java.awt.Component, java.awt.Graphics, int, int)`
        """

    def setInverted(self, inverted: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...

    @property
    def inverted(self) -> jpype.JBoolean:
        ...

    @inverted.setter
    def inverted(self, value: jpype.JBoolean):
        ...


class DockingMenuUI(DockingMenuItemUI):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createUI(c: javax.swing.JComponent) -> DockingMenuUI:
        ...


class MenuManager(ManagedMenuItem):
    """
    Class to manage a hierarchy of menus.
    """

    @typing.type_check_only
    class GroupComparator(java.util.Comparator[java.lang.String]):
        """
        This comparator puts null grouped items at the bottom of menus for menu bar menus so that
        the ungrouped items will cluster at the end.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PopupGroupComparator(java.util.Comparator[java.lang.String]):
        """
        This comparator puts null grouped items at the top of the menu so that universal popup
        actions are always at the bottom (e.g., Copy for tables).
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ManagedMenuItemComparator(java.util.Comparator[ManagedMenuItem]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], mnemonicKey: typing.Union[jpype.JChar, int, str], group: typing.Union[java.lang.String, str], usePopupPath: typing.Union[jpype.JBoolean, bool], menuHandler: MenuHandler, menuGroupMap: MenuGroupMap):
        """
        Constructs a new MenuManager
        
        :param java.lang.String or str name: the name of the menu.
        :param jpype.JChar or int or str mnemonicKey: the key to use for the menu mnemonic
        :param java.lang.String or str group: the group of the menu.
        :param jpype.JBoolean or bool usePopupPath: if true, registers actions with popup paths as popup items.
        :param MenuHandler menuHandler: Listener to be notified of menu behavior.
        :param MenuGroupMap menuGroupMap: maps menu groups to menu paths
        """

    def addAction(self, action: docking.action.DockingActionIf):
        """
        Adds an action to this menu. Can create subMenus depending on the menuPath of the action
        
        :param docking.action.DockingActionIf action: the action to be added
        """

    def getAction(self, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        ...

    def getMenu(self) -> javax.swing.JMenu:
        """
        Returns a Menu hierarchy of all the actions
        
        :return: the menu
        :rtype: javax.swing.JMenu
        """

    def getMenuHandler(self) -> javax.swing.event.PopupMenuListener:
        ...

    @staticmethod
    def getMnemonicKey(str: typing.Union[java.lang.String, str]) -> str:
        """
        Parses the mnemonic key from the menu items text.
        
        :param java.lang.String or str str: the menu item text
        :return: the mnemonic key for encoded in the actions menu text. Returns 0 if there is none.
        :rtype: str
        """

    def getPopupMenu(self) -> javax.swing.JPopupMenu:
        """
        Returns a JPopupMenu for the action hierarchy
        
        :return: the popup menu
        :rtype: javax.swing.JPopupMenu
        """

    def isEmpty(self) -> bool:
        """
        Tests if this menu is empty.
        """

    def menuGroupChanged(self, theMenuPath: jpype.JArray[java.lang.String], i: typing.Union[jpype.JInt, int], localGroup: typing.Union[java.lang.String, str]):
        """
        Notification that a menu item has changed groups.
        
        :param jpype.JArray[java.lang.String] theMenuPath: the menu path of the item whose group changed.
        :param jpype.JInt or int i: the index into the menu path of the part that changed groups.
        :param java.lang.String or str localGroup: the new group.
        """

    @staticmethod
    def stripMnemonicAmp(text: typing.Union[java.lang.String, str]) -> str:
        """
        Removes the Mnemonic indicator character (&) from the text
        
        :param java.lang.String or str text: the text to strip
        :return: the stripped mnemonic
        :rtype: str
        """

    @property
    def menuHandler(self) -> javax.swing.event.PopupMenuListener:
        ...

    @property
    def popupMenu(self) -> javax.swing.JPopupMenu:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...

    @property
    def menu(self) -> javax.swing.JMenu:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class MenuItemManager(ManagedMenuItem, java.beans.PropertyChangeListener, java.awt.event.ActionListener):
    """
    Class to manage a JMenuItem for an action.  Handles property changes in the action
    and makes the corresponding change in the menuItem.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAction(self) -> docking.action.DockingActionIf:
        ...

    def getOwner(self) -> str:
        ...

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...


class ToolBarItemManager(java.beans.PropertyChangeListener, java.awt.event.ActionListener, java.awt.event.MouseListener):
    """
    Class to manager toolbar buttons.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: docking.action.DockingActionIf, windowManager: docking.DockingWindowManager):
        """
        Constructs a new ToolBarItemManager
        
        :param docking.action.DockingActionIf action: the action to be managed on the toolbar.
        :param docking.DockingWindowManager windowManager: the window manager.
        """

    def createButton(self, action: docking.action.DockingActionIf) -> javax.swing.JButton:
        ...

    def getAction(self) -> docking.action.DockingActionIf:
        """
        Returns the action being managed
        
        :return: the action
        :rtype: docking.action.DockingActionIf
        """

    def getButton(self) -> javax.swing.JButton:
        """
        Returns a button for this items action
        
        :return: the button
        :rtype: javax.swing.JButton
        """

    @property
    def button(self) -> javax.swing.JButton:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...


class ActionState(java.lang.Object, typing.Generic[T]):
    """
    Note: this class overrides the ``equals(Object)`` and relies upon the
    ``equals`` method of the ``userData`` object. Thus, if it is important that
    equals work for you in the non-standard identity way, then you must override ``equals``
    in your user data objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], icon: javax.swing.Icon, userData: T):
        ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    def getIcon(self) -> javax.swing.Icon:
        ...

    def getName(self) -> str:
        ...

    def getUserData(self) -> T:
        ...

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        ...

    @property
    def userData(self) -> T:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @helpLocation.setter
    def helpLocation(self, value: ghidra.util.HelpLocation):
        ...



__all__ = ["DockingMenuItemUI", "HorizontalRuleAction", "MultipleActionDockingToolbarButton", "MultiStateButton", "MenuGroupMap", "ToolBarManager", "MultiActionDockingAction", "ButtonState", "MenuBarManager", "NonToolbarMultiStateAction", "DockingCheckboxMenuItemUI", "DialogToolbarButton", "DockingToolBarUtils", "MenuHandler", "ManagedMenuItem", "MultiStateDockingAction", "MenuGroupListener", "InvertableImageIcon", "DockingMenuUI", "MenuManager", "MenuItemManager", "ToolBarItemManager", "ActionState"]
