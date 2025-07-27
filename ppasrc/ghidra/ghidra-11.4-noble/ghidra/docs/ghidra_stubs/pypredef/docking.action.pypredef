from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.options
import ghidra.util
import gui.event
import help
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class KeyBindingType(java.lang.Enum[KeyBindingType]):
    """
    Allows clients to signal their support for the assigning of key binding shortcut keys.  Most
    action clients need not be concerned with this class.   The default settings of 
    :obj:`DockingAction` work correctly for almost all cases, which is to have the action 
    support individual key bindings, which are managed by the system via the UI.
    
    
    .. seealso::
    
        | :obj:`DockingActionIf`
    """

    class_: typing.ClassVar[java.lang.Class]
    UNSUPPORTED: typing.Final[KeyBindingType]
    """
    Indicates the setting of key bindings through the UI is not supported
    """

    INDIVIDUAL: typing.Final[KeyBindingType]
    """
    Supports the assignment of key bindings via the UI.  Setting a key binding on an action 
    with this type will not affect any other action.
    """

    SHARED: typing.Final[KeyBindingType]
    """
    When the key binding is set via the UI, this action, and any action that shares a 
    name with this action, will be updated to the same key binding value whenever the key 
    binding options change.
     
     
    Most actions will not be shared.  If you are unsure if your action
    should use a shared keybinding, then do not do so.
    """


    def isManaged(self) -> bool:
        """
        A convenience method for clients to check whether this key binding type should be 
        managed directly by the system.
         
         
        Shared actions are not managed directly by the system, but are instead managed through
        a proxy action.
        
        :return: true if managed directly by the system; false if key binding are not supported 
                or are managed through a proxy
        :rtype: bool
        """

    def isShared(self) -> bool:
        """
        Convenience method for checking if this type is the :obj:`.SHARED` type
        
        :return: true if shared
        :rtype: bool
        """

    def supportsKeyBindings(self) -> bool:
        """
        Returns true if this type supports key bindings.  This is a convenience method for 
        checking that this type is not :obj:`.UNSUPPORTED`.
        
        :return: true if key bindings are supported
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> KeyBindingType:
        ...

    @staticmethod
    def values() -> jpype.JArray[KeyBindingType]:
        ...

    @property
    def shared(self) -> jpype.JBoolean:
        ...

    @property
    def managed(self) -> jpype.JBoolean:
        ...


class ToggleDockingAction(DockingAction, ToggleDockingActionIf):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], keyBindingType: KeyBindingType):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], supportsKeyBindings: typing.Union[jpype.JBoolean, bool]):
        ...


class PopupMenuData(MenuData):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ToggleDockingActionIf(DockingActionIf):
    """
    Interface for actions that have a toggle state
    """

    class_: typing.ClassVar[java.lang.Class]
    SELECTED_STATE_PROPERTY: typing.Final = "selectState"

    def isSelected(self) -> bool:
        """
        Returns true if the toggle state for this action is current selected.
        
        :return: true if the toggle state for this action is current selected.
        :rtype: bool
        """

    def setSelected(self, newValue: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the toggle state for this action.
        
        :param jpype.JBoolean or bool newValue: the new toggle state.
        """

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...


class ShowFocusInfoAction(DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractHelpAction(DockingAction):
    """
    A base system action used for actions that show help information.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], keyStroke: javax.swing.KeyStroke, isPrimary: typing.Union[jpype.JBoolean, bool]):
        ...


class ActionContextProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getActionContext(self, e: java.awt.event.MouseEvent) -> docking.ActionContext:
        ...

    @property
    def actionContext(self) -> docking.ActionContext:
        ...


class MenuBarData(MenuData):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ToolBarData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        ...

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, toolBarGroup: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, icon: javax.swing.Icon, toolBarGroup: typing.Union[java.lang.String, str], toolBarSubGroup: typing.Union[java.lang.String, str]):
        ...

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns the toolbar icon assigned to this toolbar data.
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getToolBarGroup(self) -> str:
        """
        Returns the group of this toolbar data.  Actions belonging to the same group will appear
        next to each other.
        
        :return: the group
        :rtype: str
        """

    def getToolBarSubGroup(self) -> str:
        """
        Returns the subgroup string.  This string is used to sort items within a 
        :meth:`toolbar group <.getToolBarGroup>`.  This value is not required.  If not specified, 
        then the value will effectively place this item at the end of its specified group.
        
        :return: the subgroup
        :rtype: str
        """

    def setIcon(self, newIcon: javax.swing.Icon):
        ...

    def setToolBarGroup(self, newGroup: typing.Union[java.lang.String, str]):
        ...

    def setToolBarSubGroup(self, newSubGroup: typing.Union[java.lang.String, str]):
        ...

    @property
    def toolBarSubGroup(self) -> java.lang.String:
        ...

    @toolBarSubGroup.setter
    def toolBarSubGroup(self, value: java.lang.String):
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @icon.setter
    def icon(self, value: javax.swing.Icon):
        ...

    @property
    def toolBarGroup(self) -> java.lang.String:
        ...

    @toolBarGroup.setter
    def toolBarGroup(self, value: java.lang.String):
        ...


class KeyBindingData(java.lang.Object):
    """
    A class for storing an action's key stroke, mouse binding or both.
     
    
    Note: this class creates key strokes that work on key ``pressed``.  This effectively
    normalizes all client key bindings to work on the same type of key stroke (pressed, typed or
    released).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, keyStroke: javax.swing.KeyStroke):
        ...

    @typing.overload
    def __init__(self, c: typing.Union[jpype.JChar, int, str], modifiers: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, keyCode: typing.Union[jpype.JInt, int], modifiers: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, mouseBinding: gui.event.MouseBinding):
        """
        Constructs an instance of this class that uses a mouse binding instead of a key stroke.
        
        :param gui.event.MouseBinding mouseBinding: the mouse binding.
        """

    @typing.overload
    def __init__(self, keyStrokeString: typing.Union[java.lang.String, str]):
        """
        Creates a key stroke from the given text.  See
        :meth:`KeyBindingUtils.parseKeyStroke(KeyStroke) <KeyBindingUtils.parseKeyStroke>`.   The key stroke created for this class
        will always be a key ``pressed`` key stroke.
        
        :param java.lang.String or str keyStrokeString: the key stroke string to parse
        """

    @typing.overload
    def __init__(self, actionTrigger: ghidra.framework.options.ActionTrigger):
        """
        Creates a key binding data with the given action trigger.
        
        :param ghidra.framework.options.ActionTrigger actionTrigger: the trigger; may not be null
        """

    @typing.overload
    def __init__(self, keyStroke: javax.swing.KeyStroke, precedence: docking.KeyBindingPrecedence):
        ...

    def getActionTrigger(self) -> ghidra.framework.options.ActionTrigger:
        """
        Creates a new action trigger with the values of this class
        
        :return: the action trigger
        :rtype: ghidra.framework.options.ActionTrigger
        """

    def getKeyBinding(self) -> javax.swing.KeyStroke:
        """
        Returns an accelerator keystroke to be associated with this action.
        
        :return: the binding
        :rtype: javax.swing.KeyStroke
        """

    def getKeyBindingPrecedence(self) -> docking.KeyBindingPrecedence:
        """
        Returns the keyBindingPrecedence for this action
        
        :return: the precedence
        :rtype: docking.KeyBindingPrecedence
        """

    def getMouseBinding(self) -> gui.event.MouseBinding:
        """
        Returns the mouse binding assigned to this key binding data.
        
        :return: the mouse binding; may be null
        :rtype: gui.event.MouseBinding
        """

    @staticmethod
    def update(kbData: KeyBindingData, newTrigger: ghidra.framework.options.ActionTrigger) -> KeyBindingData:
        """
        Returns a key binding data object that matches the given trigger.  If the existing key 
        binding object already matches the new trigger, then the existing key binding data is 
        returned.  If the new trigger is null, the null will be returned.
        
        :param KeyBindingData kbData: the existing key binding data; my be null
        :param ghidra.framework.options.ActionTrigger newTrigger: the new action trigger; may be null
        :return: a key binding data based on the new action trigger; may be null
        :rtype: KeyBindingData
        """

    @property
    def actionTrigger(self) -> ghidra.framework.options.ActionTrigger:
        ...

    @property
    def keyBinding(self) -> javax.swing.KeyStroke:
        ...

    @property
    def mouseBinding(self) -> gui.event.MouseBinding:
        ...

    @property
    def keyBindingPrecedence(self) -> docking.KeyBindingPrecedence:
        ...


class SystemKeyBindingAction(docking.DockingKeyBindingAction):
    """
    An :obj:`DockingKeyBindingAction` to signal that the given :obj:`DockingAction` gets priority
    over all other non-system actions in the system.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAction(self) -> DockingActionIf:
        ...

    @property
    def action(self) -> DockingActionIf:
        ...


@deprecated("use Tool")
class DockingActionProviderIf(java.lang.Object):
    """
    An interface for objects (really Components) to implement that signals they provide actions 
    for the Docking environment.  This interface will be called when the implementor is the source
    of a Java event, like a MouseEvent.
     
    
    As an example, a JTable that wishes to provide popup menu actions can implement this interface.
    When the user right-clicks on said table, then Docking system will ask this object for its
    actions.  Further, in this example, the actions given will be inserted into the popup menu
    that is shown.
    
    
    .. deprecated::
    
    use :obj:`Tool`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDockingActions(self) -> java.util.List[DockingActionIf]:
        """
        Returns actions that are compatible with the given context.
        
        :return: the actions
        :rtype: java.util.List[DockingActionIf]
        """

    @property
    def dockingActions(self) -> java.util.List[DockingActionIf]:
        ...


class NextPreviousWindowAction(DockingAction):
    """
    Action for transferring focus to the next or previous visible window in the application.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keybinding: javax.swing.KeyStroke, forward: typing.Union[jpype.JBoolean, bool]):
        ...


class KeyBindingsManager(java.beans.PropertyChangeListener):
    """
    A class that organizes system key bindings by mapping them to assigned :obj:`DockingActionIf`s.
    
     
    This class understands reserved system key bindings.  For non-reserved key bindings, this
    class knows how to map a single key binding to multiple actions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: docking.Tool):
        ...

    def addAction(self, optionalProvider: docking.ComponentProvider, action: DockingActionIf):
        ...

    def addSystemAction(self, action: DockingActionIf):
        ...

    def dispose(self):
        ...

    @typing.overload
    def getDockingAction(self, keyStroke: javax.swing.KeyStroke) -> javax.swing.Action:
        ...

    @typing.overload
    def getDockingAction(self, mouseBinding: gui.event.MouseBinding) -> javax.swing.Action:
        ...

    def getSystemAction(self, fullName: typing.Union[java.lang.String, str]) -> DockingActionIf:
        ...

    def getSystemActions(self) -> java.util.Set[DockingActionIf]:
        ...

    def isSystemAction(self, action: DockingActionIf) -> bool:
        ...

    def removeAction(self, action: DockingActionIf):
        ...

    def validateActionKeyBinding(self, dockingAction: DockingActionIf, ks: javax.swing.KeyStroke) -> str:
        ...

    @property
    def systemActions(self) -> java.util.Set[DockingActionIf]:
        ...

    @property
    def dockingAction(self) -> javax.swing.Action:
        ...

    @property
    def systemAction(self) -> DockingActionIf:
        ...


class HelpInfoAction(AbstractHelpAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keybinding: javax.swing.KeyStroke):
        ...


class MultiActionDockingActionIf(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getActionList(self, context: docking.ActionContext) -> java.util.List[DockingActionIf]:
        ...

    @property
    def actionList(self) -> java.util.List[DockingActionIf]:
        ...


class DockingAction(DockingActionIf):
    """
    ``DockingAction`` defines a user action associated with a toolbar icon and/or
    menu item.  All actions must specify an action name which will be used to associate key bindings
    and will be used as the popup menu item when needed.  This name should be unique across
    the entire application.
     
    
    DockingActions can be invoked from the global menu, a popup menu, a toolbar, and/or a keybinding,
    depending on whether or not menuBarData, popupMenuData, toolBarData, and/or keyBindingData have
    been set.
     
    
    **
    Implementors of this class should override :meth:`actionPerformed(ActionContext) <.actionPerformed>`.
    **
     
    
    Generally, implementors should also override :meth:`isEnabledForContext(ActionContext) <.isEnabledForContext>`.  This
    method is used to determine if an action if applicable to the current context.   Overriding this
    method allows actions to manage their own enablement.  Otherwise, the default behavior for this
    method is to return the current enabled property of the action.  This allows for the possibility
    for plugins to externally manage the enablement of its actions.
     
    
    NOTE: If you wish to do your own external enablement management for an action (which is highly
    discouraged), it is very important that you don't use any of the internal enablement mechanisms
    by setting the predicates :meth:`enabledWhen(Predicate) <.enabledWhen>`, :meth:`validContextWhen(Predicate) <.validContextWhen>`
    or overriding :meth:`isValidContext(ActionContext) <.isValidContext>`. These predicates and methods trigger
    internal enablement management which will interfere with you own calls to
    :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], kbType: KeyBindingType):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], supportsKeyBindings: typing.Union[jpype.JBoolean, bool]):
        ...

    def addToWindowWhen(self, addToWindowContextClass: java.lang.Class[docking.ActionContext]):
        """
        Sets the ActionContext class for when this action should be added to a window
         
        
        If this is set, then the action will only be added to windows that have providers
        that can produce an ActionContext that is appropriate for this action.
        
        :param java.lang.Class[docking.ActionContext] addToWindowContextClass: the ActionContext class required to be producible by a
        provider that is hosted in that window before this action is added to that
        window.
        """

    def dispose(self):
        """
        Cleans up any resources used by the action.
        """

    def enabledWhen(self, predicate: java.util.function.Predicate[docking.ActionContext]):
        """
        Sets a predicate for dynamically determining the action's enabled state.  If this
        predicate is not set, the action's enable state must be controlled directly using the
        :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` method. See
        :meth:`DockingActionIf.isEnabledForContext(ActionContext) <DockingActionIf.isEnabledForContext>`
        
        :param java.util.function.Predicate[docking.ActionContext] predicate: the predicate that will be used to dynamically determine an action's
        enabled state.
        """

    def firePropertyChanged(self, propertyName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for this action
        
        :return: the help location for this action
        :rtype: ghidra.util.HelpLocation
        """

    def markHelpUnnecessary(self):
        """
        Signals the help system that this action does not need a help entry.   Some actions
        are so obvious that they do not require help, such as an action that renames a file.
         
        
        The method should be sparsely used, as most actions should provide help.
        """

    def popupWhen(self, predicate: java.util.function.Predicate[docking.ActionContext]):
        """
        Sets a predicate for dynamically determining if this action should be included in
        an impending pop-up menu.  If this predicate is not set, the action's will be included
        in an impending pop-up, if it is enabled. See
        :meth:`DockingActionIf.isAddToPopup(ActionContext) <DockingActionIf.isAddToPopup>`
        
        :param java.util.function.Predicate[docking.ActionContext] predicate: the predicate that will be used to dynamically determine an action's
        enabled state.
        """

    def setAddToAllWindows(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Tells this action to add itself to all windows
        
        :param jpype.JBoolean or bool b: to add to all windows or not
        """

    def setDescription(self, newDescription: typing.Union[java.lang.String, str]):
        """
        Sets the description to be used in the tooltip.
        
        :param java.lang.String or str newDescription: the description to be set.
        """

    def setHelpLocation(self, location: ghidra.util.HelpLocation):
        """
        Set a specific Help location for this action.
        This will replace the default help location
        
        :param ghidra.util.HelpLocation location: the help location for the action.
        """

    def setMenuBarData(self, newMenuData: MenuData):
        """
        Sets the :obj:`MenuData` to be used to put this action on the tool's menu bar
        
        :param MenuData newMenuData: the MenuData to be used to put this action on the tool's menu bar
        """

    def setPopupMenuData(self, newMenuData: MenuData):
        """
        Sets the :obj:`MenuData` to be used to put this action in the tool's popup menu
        
        :param MenuData newMenuData: the MenuData to be used to put this action on the tool's popup menu
        """

    def setToolBarData(self, newToolBarData: ToolBarData):
        """
        Sets the :obj:`ToolBarData` to be used to put this action on the tool's toolbar
        
        :param ToolBarData newToolBarData: the ToolBarData to be used to put this action on the tool's toolbar
        """

    def shouldAddToWindow(self, isMainWindow: typing.Union[jpype.JBoolean, bool], contextTypes: java.util.Set[java.lang.Class[typing.Any]]) -> bool:
        """
        Determines if this action should be added to a window.
         
        
        If the client wants the action on all windows, then they can call :obj:`.shouldAddToAllWindows`
         
        
        If the client wants the action to be on a window only when the window can produce
        a certain context type, then the client should call
        :meth:`addToWindowWhen(Class) <.addToWindowWhen>`
         
        
        Otherwise, by default, the action will only be on the main window.
        """

    def validContextWhen(self, predicate: java.util.function.Predicate[docking.ActionContext]):
        """
        Sets a predicate for dynamically determining if this action is valid for the current
        :obj:`ActionContext`.  See :meth:`DockingActionIf.isValidContext(ActionContext) <DockingActionIf.isValidContext>`
        
        :param java.util.function.Predicate[docking.ActionContext] predicate: the predicate that will be used to dynamically determine an action's
        validity for a given :obj:`ActionContext`
        """

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @helpLocation.setter
    def helpLocation(self, value: ghidra.util.HelpLocation):
        ...


class ContextSpecificAction(DockingAction, typing.Generic[T]):
    """
    This class is used simplify DockingAction logic for actions that work with
    specific :obj:`ActionContext`.  It automatically checks the ActionContext
    and disables/invalidates/prevent popup, if the context is not the expected
    type.  If the context type is correct, it casts the context to the expected
    specific type and calls the equivalent method with the ActionContext already
    cast to the expected type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], contextClass: java.lang.Class[T]):
        """
        Constructor
        
        :param java.lang.String or str name: the name of the action.
        :param java.lang.String or str owner: the owner of the action.
        :param java.lang.Class[T] contextClass: the class of the expected ActionContext type.
        """


class MultipleKeyAction(docking.DockingKeyBindingAction):
    """
    Action that manages multiple :obj:`DockingAction`s mapped to a given key binding
    """

    @typing.type_check_only
    class ActionData(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getContextType(self) -> java.lang.Class[docking.ActionContext]:
            ...

        def supportsDefaultContext(self) -> bool:
            ...

        @property
        def contextType(self) -> java.lang.Class[docking.ActionContext]:
            ...


    @typing.type_check_only
    class MultiExecutableAction(docking.ExecutableAction):
        """
        An extension of :obj:`ExecutableAction` that itself contains 0 or more 
        :obj:`ExecutableAction`s.  This class is used to create a snapshot of all actions valid and
        enabled for a given keystroke.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: docking.Tool, provider: docking.ComponentProvider, action: DockingActionIf, keyStroke: javax.swing.KeyStroke):
        """
        Creates new MultipleKeyAction
        
        :param docking.Tool tool: used to determine context
        :param docking.ComponentProvider provider: the provider, if any, associated with the action
        :param DockingActionIf action: action that will be added to the list of actions bound to a keystroke
        :param javax.swing.KeyStroke keyStroke: the keystroke, if any, associated with the action
        """

    def addAction(self, provider: docking.ComponentProvider, action: DockingActionIf):
        ...

    def isEmpty(self) -> bool:
        ...

    def isEnabled(self) -> bool:
        """
        Returns the enabled state of the ``Action``. When enabled,
        any component associated with this object is active and
        able to fire this object's ``actionPerformed`` method.
        
        :return: true if this ``Action`` is enabled
        :rtype: bool
        """

    def removeAction(self, action: DockingActionIf):
        ...

    def setEnabled(self, newValue: typing.Union[jpype.JBoolean, bool]):
        """
        Enables or disables the action.  This affects all uses of the action.  Note that for popups,
        this affects whether or not the option is "grayed out", not whether the action is added
        to the popup.
        
        :param jpype.JBoolean or bool newValue: true to enable the action, false to disable it
        
        .. seealso::
        
            | :obj:`Action.setEnabled`
        """

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MenuData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    NO_MNEMONIC: typing.Final = -1
    NO_SUBGROUP: typing.Final[java.lang.String]

    @typing.overload
    def __init__(self, menuPath: jpype.JArray[java.lang.String]):
        ...

    @typing.overload
    def __init__(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, menuPath: jpype.JArray[java.lang.String], icon: javax.swing.Icon):
        ...

    @typing.overload
    def __init__(self, menuPath: jpype.JArray[java.lang.String], icon: javax.swing.Icon, menuGroup: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, menuPath: jpype.JArray[java.lang.String], icon: javax.swing.Icon, menuGroup: typing.Union[java.lang.String, str], mnemonic: typing.Union[jpype.JInt, int], menuSubGroup: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, menuData: MenuData):
        ...

    def clearMnemonic(self):
        ...

    def cloneData(self) -> MenuData:
        ...

    def getMenuGroup(self) -> str:
        """
        Returns the group for the menu item created by this data.   This value determines which
        section inside of the tool's popup menu the menu item will be placed.   If you need to
        control the ordering **within a section**, then provide a value for 
        :meth:`setMenuSubGroup(String) <.setMenuSubGroup>`.
        
        :return: the group
        :rtype: str
        """

    def getMenuIcon(self) -> javax.swing.Icon:
        """
        Returns the icon assigned to this action's menu. Null indicates that this action does not 
        have a menu icon
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getMenuItemName(self) -> str:
        ...

    def getMenuPath(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the menu path.
        
        :return: an array of strings where each string is an element of a higher level menu.
        :rtype: jpype.JArray[java.lang.String]
        """

    def getMenuPathAsString(self) -> str:
        """
        Returns the menu path as a string. This method includes accelerator characters in the path
        
        :return: the menu path as a string
        :rtype: str
        """

    def getMenuPathDisplayString(self) -> str:
        """
        Returns the menu path as a string. This method filters accelerator chars('&') from the
        path.
        
        :return: the menu path as a string without unescaped '&' chars
        :rtype: str
        """

    def getMenuSubGroup(self) -> str:
        """
        Returns the subgroup string.  This string is used to sort items within a 
        :meth:`toolbar group <.getMenuGroup>`.  This value is not required.  If not specified, 
        then the value will effectively place this item at the end of its specified group.
        
        :return: the sub-group
        :rtype: str
        """

    def getMnemonic(self) -> int:
        ...

    def getParentMenuGroup(self) -> str:
        """
        Returns the group for the parent menu of the menu item created by this data.   That is, 
        this value is effectively the same as :meth:`getMenuGroup() <.getMenuGroup>`, but for the parent menu
        item of this data's item.   Setting this value is only valid if the :meth:`getMenuPath() <.getMenuPath>`
        has a length greater than 1.
        
        :return: the parent group
        :rtype: str
        """

    def setIcon(self, newIcon: javax.swing.Icon):
        ...

    def setMenuGroup(self, newGroup: typing.Union[java.lang.String, str]):
        ...

    def setMenuItemName(self, newMenuItemName: typing.Union[java.lang.String, str]):
        """
        Sets the menu item name and the mnemonic, using the first unescaped '&' found in the text
        as a marker ("S&ave As").
         
        
        NOTE: do NOT use this method with strings that contain user-supplied text.  Instead, use
        :meth:`setMenuItemNamePlain(String) <.setMenuItemNamePlain>`, and then manually :meth:`set <.setMnemonic>`
        the mnemonic.
        
        :param java.lang.String or str newMenuItemName: the new name for this menu item, with an optional '&' to flag one
        of the characters of the name as the new mnemonic of this item
        """

    def setMenuItemNamePlain(self, newMenuItemName: typing.Union[java.lang.String, str]):
        """
        Sets the menu item name, without parsing the name for mnemonics ("&File").
         
        
        Use this method instead of :meth:`setMenuItemName(String) <.setMenuItemName>` when the name may have '&'
        characters that need to be preserved, which is typically any user supplied strings.
        
        :param java.lang.String or str newMenuItemName: the new name for this menu item
        """

    def setMenuPath(self, newPath: jpype.JArray[java.lang.String]):
        ...

    def setMenuSubGroup(self, newSubGroup: typing.Union[java.lang.String, str]):
        ...

    def setMnemonic(self, newMnemonic: typing.Union[java.lang.Character, int, str]):
        ...

    def setParentMenuGroup(self, newParentMenuGroup: typing.Union[java.lang.String, str]):
        """
        See the description in :meth:`getParentMenuGroup() <.getParentMenuGroup>`
        
        :param java.lang.String or str newParentMenuGroup: the parent group
        """

    @property
    def menuPath(self) -> jpype.JArray[java.lang.String]:
        ...

    @menuPath.setter
    def menuPath(self, value: jpype.JArray[java.lang.String]):
        ...

    @property
    def menuIcon(self) -> javax.swing.Icon:
        ...

    @property
    def parentMenuGroup(self) -> java.lang.String:
        ...

    @parentMenuGroup.setter
    def parentMenuGroup(self, value: java.lang.String):
        ...

    @property
    def menuItemName(self) -> java.lang.String:
        ...

    @menuItemName.setter
    def menuItemName(self, value: java.lang.String):
        ...

    @property
    def menuSubGroup(self) -> java.lang.String:
        ...

    @menuSubGroup.setter
    def menuSubGroup(self, value: java.lang.String):
        ...

    @property
    def mnemonic(self) -> jpype.JInt:
        ...

    @property
    def menuPathAsString(self) -> java.lang.String:
        ...

    @property
    def menuGroup(self) -> java.lang.String:
        ...

    @menuGroup.setter
    def menuGroup(self, value: java.lang.String):
        ...

    @property
    def menuPathDisplayString(self) -> java.lang.String:
        ...


class ShowFocusCycleAction(DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ComponentBasedDockingAction(DockingActionIf):
    """
    An interface to signal that the implementing action works with an individual Java 
    :obj:`Component`.   Standard Docking Actions are either global tool-based actions or local 
    :obj:`ComponentProvider` actions.   This interface allows us to have the concept of an 
    action that is effectively local to a specific Java component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isValidComponentContext(self, context: docking.ActionContext) -> bool:
        """
        Returns true if the given context contains this action's component
        
        :param docking.ActionContext context: the context
        :return: true if the given context contains this action's component
        :rtype: bool
        """

    @property
    def validComponentContext(self) -> jpype.JBoolean:
        ...


class ShowContextMenuAction(DockingAction):
    """
    An action to trigger a context menu over the focus owner.  This allows context menus to be
    triggered from the keyboard.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keyStroke: javax.swing.KeyStroke, isPrimary: typing.Union[jpype.JBoolean, bool]):
        ...


class HelpAction(AbstractHelpAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keyStroke: javax.swing.KeyStroke, isPrimary: typing.Union[jpype.JBoolean, bool]):
        ...


class DockingActionIf(help.HelpDescriptor):
    """
    The base interface for clients that wish to create commands to be registered with a tool.
     
    
    An action may appear in a primary menu, a popup menu or a toolbar.   Further, an action 
    may have a key binding assigned.
     
    
    The particular support for key bindings is defined by :obj:`KeyBindingType`.   Almost all
    client actions will use the default setting of :obj:`KeyBindingType.INDIVIDUAL`.   To control
    the level of key binding support, you can pass the desired :obj:`KeyBindingType` to the
    base implementation of this interface.
     
    
    :obj:`ActionContext` is a key concept for tool actions so that they can be context sensitive if 
    appropriate. The context provides a 
    consistent way for plugins and components to share tool state with actions. Actions can then
    use that context to make decisions, such as if they should be enabled or added to a popup menu.
    The context information is also typically used when the action is invoked.  For example, an
    action context from a table element may provide the row in a table component that is selected and
    then a "delete table row" action can use that information to be enabled when a table selection 
    exists and then delete that row if the action is invoked.
     
    
    Actions can optionally operate on a default context if the current active context is invalid
    for that action. This allows actions to work on a more global
    level than just the component that is focused (and yet give preference to the active context.)
    The idea is that if an action is not valid for the current focused context (and it has been
    configured to support default context using :meth:`setContextClass(Class, boolean) <.setContextClass>`), then it
    can be validated against a default action context for its specific action context type.  
    The source for the default context depends on the context type. Default context providers are
    registered on the tool for each specific ActionContext type. 
    See :meth:`DockingWindowManager.registerDefaultContextProvider(Class, ActionContextProvider) <DockingWindowManager.registerDefaultContextProvider>` for
    more details.
     
    
    The use of default context is primarily intended for tool-level actions which are the ones 
    that appear in the tool's main menu bar or toolbar.  This allows the tool actions to mostly
    work on the tool's main component context regardless of what has focus, and yet still work on the  
    focused component if appropriate (such as a snapshot of the main component).
    """

    class_: typing.ClassVar[java.lang.Class]
    ENABLEMENT_PROPERTY: typing.Final = "enabled"
    GLOBALCONTEXT_PROPERTY: typing.Final = "globalContext"
    DESCRIPTION_PROPERTY: typing.Final = "description"
    KEYBINDING_DATA_PROPERTY: typing.Final = "KeyBindings"
    MENUBAR_DATA_PROPERTY: typing.Final = "MenuBar"
    POPUP_MENU_DATA_PROPERTY: typing.Final = "PopupMenu"
    TOOLBAR_DATA_PROPERTY: typing.Final = "ToolBar"

    def actionPerformed(self, context: docking.ActionContext):
        """
        method to actually perform the action logic for this action.
        
        :param docking.ActionContext context: the :obj:`ActionContext` object that provides information about where and how
        this action was invoked.
        """

    def addPropertyChangeListener(self, listener: java.beans.PropertyChangeListener):
        """
        Adds a listener to be notified if any property changes
        
        :param java.beans.PropertyChangeListener listener: The property change listener that will be notified of
                property change events.
        
        .. seealso::
        
            | :obj:`Action.addPropertyChangeListener(java.beans.PropertyChangeListener)`
        """

    def createButton(self) -> javax.swing.JButton:
        """
        Returns a JButton that is suitable for this action.  For example, It creates a ToggleButton
        if the action is a :obj:`ToggleDockingActionIf`.
        
        :return: a JButton to be used in a toolbar or null if the action does not have ToolBarData set.
        :rtype: javax.swing.JButton
        """

    def createMenuComponent(self, isPopup: typing.Union[jpype.JBoolean, bool]) -> java.awt.Component:
        """
        Returns a component to represent this action in the menu.
         
        
        Typically, this is the menu item that triggers the action. However, some actions may wish to
        use components other than menu items. For example, they may produce component for helping to
        organize the menu visually.
        
        :param jpype.JBoolean or bool isPopup: true if the action should use its Popup MenuData, else it uses the MenuBar
        MenuData.
        :return: the component
        :rtype: java.awt.Component
        
        .. seealso::
        
            | :obj:`.createMenuItem(boolean)`
        """

    def createMenuItem(self, isPopup: typing.Union[jpype.JBoolean, bool]) -> javax.swing.JMenuItem:
        """
        Returns a JMenuItem that is suitable for this action.  For example, if the action is a 
        :obj:`ToggleDockingActionIf`, then a JCheckBoxMenuItem will be created.
        
        :param jpype.JBoolean or bool isPopup: true if the action should use its Popup MenuData, else it uses the MenuBar MenuData.
        :return: a JMenuItem for placement in either the menu bar or a popup menu.
        :rtype: javax.swing.JMenuItem
        """

    def dispose(self):
        """
        Called when the action's owner is removed from the tool
        """

    def getContextClass(self) -> java.lang.Class[docking.ActionContext]:
        """
        Returns the class of a specific action context that this action requires for it to
        operate. See :obj:`ActionContext` for details on the action context system.
        
        :return: the class of a specific action context that this action requires for it to
        operate
        :rtype: java.lang.Class[docking.ActionContext]
        """

    def getDefaultKeyBindingData(self) -> KeyBindingData:
        """
        Returns the default :obj:`KeyBindingData` to be used to assign this action to a 
        key binding.  The KeyBindingData will be null if the action is not set to have a keyBinding.
        The value of this method is that which is set from a call to 
        :meth:`setKeyBindingData(KeyBindingData) <.setKeyBindingData>`.
        
        :return: the :obj:`KeyBindingData` for the action or null if the action does not have a keyBinding.
        :rtype: KeyBindingData
        """

    def getDescription(self) -> str:
        """
        Returns a short description of this action. Generally used for a tooltip
        
        :return: the description
        :rtype: str
        """

    def getFullName(self) -> str:
        """
        Returns the full name (the action name combined with the owner name)
        
        :return: the full name
        :rtype: str
        """

    def getInceptionInformation(self) -> str:
        """
        Returns a string that includes source file and line number information of where 
        this action was created
        
        :return: the inception information
        :rtype: str
        """

    def getKeyBinding(self) -> javax.swing.KeyStroke:
        """
        Convenience method for getting the keybinding for this action.
        
        :return: the :obj:`KeyStroke` to be used as a keybinding for this action or null if there is no
        :rtype: javax.swing.KeyStroke
        """

    def getKeyBindingData(self) -> KeyBindingData:
        """
        Returns the :obj:`KeyBindingData` to be used to assign this action to a key binding.  The 
        KeyBindingData will be null if the action is not set to have a keyBinding.
        
        :return: the :obj:`KeyBindingData` for the action or null if the action does not have a keyBinding.
        :rtype: KeyBindingData
        """

    def getKeyBindingType(self) -> KeyBindingType:
        """
        Returns this actions level of support for key binding accelerator keys
         
         
        Actions support key bindings by default.  Some reserved actions do not support 
        key bindings, while others wish to share the same key bindings with multiple, equivalent
        actions (this allows the user to set one binding that works in many different contexts).
        
        :return: the key binding support
        :rtype: KeyBindingType
        """

    def getMenuBarData(self) -> MenuData:
        """
        Returns the :obj:`MenuData` to be used to put this action in the menu bar.  The MenuData will be
        null if the action in not set to be in the menu bar.
        
        :return: the :obj:`MenuData` for the menu bar or null if the action is not in the menu bar.
        :rtype: MenuData
        """

    def getName(self) -> str:
        """
        Returns the name of the action
        
        :return: the name
        :rtype: str
        """

    def getOwner(self) -> str:
        """
        Returns the owner of this action
        
        :return: the owner
        :rtype: str
        """

    def getOwnerDescription(self) -> str:
        """
        Returns a description of this actions owner.  For most actions this will return the 
        same value as :meth:`getOwner() <.getOwner>`.
        
        :return: the description
        :rtype: str
        """

    def getPopupMenuData(self) -> MenuData:
        """
        Returns the :obj:`MenuData` to be used to put this action in a popup menu.  The MenuData will be
        null if the action in not set to be in a popup menu.
        
        :return: the :obj:`MenuData` for a popup menu or null if the action is not to be in a popup menu.
        :rtype: MenuData
        """

    def getToolBarData(self) -> ToolBarData:
        """
        Returns the :obj:`ToolBarData` to be used to put this action in a toolbar.  The ToolBarData will be
        null if the action in not set to be in a toolbar.
        
        :return: the :obj:`ToolBarData` for the popup menu or null if the action is not in a popup menu.
        :rtype: ToolBarData
        """

    def isAddToPopup(self, context: docking.ActionContext) -> bool:
        """
        method is used to determine if this action should be displayed on the current popup.  This 
        method will only be called if the action has popup :obj:`PopupMenuData` set.
         
        
        Generally, actions don't need to override this method as the default implementation will 
        defer to the :meth:`isEnabledForContext(ActionContext) <.isEnabledForContext>`, which will have the effect 
        of adding the action to the popup only if it is enabled for a given context.  
        By overriding this method,
        you can change this behavior so that the action will be added to the popup, even if it is
        disabled for the context, by having this method return true even if the 
        :meth:`isEnabledForContext(ActionContext) <.isEnabledForContext>` method will return false, resulting in the 
        action appearing in the popup menu, but begin disabled.
        
        :param docking.ActionContext context: the :obj:`ActionContext` from the active provider.
        :return: true if this action is appropriate for the given context.
        :rtype: bool
        """

    def isEnabled(self) -> bool:
        """
        Returns true if the action is enabled.
        
        :return: true if the action is enabled, false otherwise
        :rtype: bool
        """

    def isEnabledForContext(self, context: docking.ActionContext) -> bool:
        """
        Method used to determine if this action should be enabled for the given context.  
         
        
        **This is the method implementors override to control when the action may be used.**
         
        
        This method
        will be called by the DockingWindowManager for actions on the global menuBar and toolBar
        and for actions that have a keyBinding. 
         
        
        This method will be called whenever
        one of the following events occur: 
         
        1. when the user invokes the action via its keyBinding,
        2. the user changes focus from one component provider to another,
        3. the user moves a component to another position in the window or into another window,
        4. a component provider reports a change in it's context,
        5. any plugin or software component reports a general change in context (calls the 
        tool.contextChanged(ComponentProvider) with a null parameter).
        
        The default implementation will simply return this action's enablement state.
        
        :param docking.ActionContext context: the current :obj:`ActionContext` for the window.
        :return: true if the action should be enabled for the context or false otherwise.
        :rtype: bool
        """

    def isValidContext(self, context: docking.ActionContext) -> bool:
        """
        Method that actions implement to indicate if this action is valid (knows how to work with, is
        appropriate for) for the given context.  This method is used
        to determine if the action should be enabled based on the either the local context or the
        global context.  The action is first asked if it is valid for the local context and if not,
        then it is asked if it is valid for the global context.  If a context is valid, then it will
        then be asked if it is enabled for that context.
        
        :param docking.ActionContext context: the :obj:`ActionContext` from the active provider.
        :return: true if this action is appropriate for the given context.
        :rtype: bool
        """

    def removePropertyChangeListener(self, listener: java.beans.PropertyChangeListener):
        """
        Removes a listener to be notified of property changes.
        
        :param java.beans.PropertyChangeListener listener: The property change listener that will be notified of
                property change events.
        
        .. seealso::
        
            | :obj:`.addPropertyChangeListener(PropertyChangeListener)`
        
            | :obj:`Action.addPropertyChangeListener(java.beans.PropertyChangeListener)`
        """

    def setContextClass(self, type: java.lang.Class[docking.ActionContext], supportsDefaultContext: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the specific action context class that this action works on and if the action
        supports default context. See :obj:`ActionContext` for details on how the action 
        context system works.
        
        :param java.lang.Class[docking.ActionContext] type: the :obj:`ActionContext` class that this action works on.
        :param jpype.JBoolean or bool supportsDefaultContext: if true, then this action also support operating on a 
        default context other than the active (focused) provider's context.
        """

    def setEnabled(self, newValue: typing.Union[jpype.JBoolean, bool]):
        """
        Enables or disables the action
        
        :param jpype.JBoolean or bool newValue: true to enable the action, false to disable it
        """

    def setKeyBindingData(self, keyBindingData: KeyBindingData):
        """
        Sets the :obj:`KeyBindingData` on an action to either assign a keybinding or remove it
        (keyBindingData = null).
        
        :param KeyBindingData keyBindingData: if non-null, assigns a keybinding to the action. Otherwise, removes
        any keybinding from the action.
        """

    def setUnvalidatedKeyBindingData(self, newKeyBindingData: KeyBindingData):
        """
        **Users creating actions should not call this method, but should instead call
        :meth:`setKeyBindingData(KeyBindingData) <.setKeyBindingData>`.**
         
        
        Call this method when you wish to bypass the validation of 
        :meth:`setKeyBindingData(KeyBindingData) <.setKeyBindingData>` so that keybindings are set exactly as they
        are given (such as when set by the user and not by the programmer).
        
        :param KeyBindingData newKeyBindingData: the KeyBindingData to be used to assign this action to a keybinding
        """

    def shouldAddToWindow(self, isMainWindow: typing.Union[jpype.JBoolean, bool], contextTypes: java.util.Set[java.lang.Class[typing.Any]]) -> bool:
        """
        Determines whether this action should be added to a window (either the main window or a
        secondary detached window).  By default, this method will return true for the main window
        and false otherwise.
        
        :param jpype.JBoolean or bool isMainWindow: true if the window in question is the main window
        :param java.util.Set[java.lang.Class[typing.Any]] contextTypes: a list of contextTypes (Classes) based on the providers that are currently
        in the window.
        :return: true if this action should be added to the window, false otherwise.
        :rtype: bool
        """

    def supportsDefaultContext(self) -> bool:
        """
        Returns true if this action also supports operating on a default context
        other then the active (focused) provider's context. See the class header for more
        details.
        
        :return: true if this action also supports operating on a default context other then
        the active (focused) provider's context.
        :rtype: bool
        """

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def enabledForContext(self) -> jpype.JBoolean:
        ...

    @property
    def keyBinding(self) -> javax.swing.KeyStroke:
        ...

    @property
    def addToPopup(self) -> jpype.JBoolean:
        ...

    @property
    def keyBindingType(self) -> KeyBindingType:
        ...

    @property
    def toolBarData(self) -> ToolBarData:
        ...

    @property
    def fullName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def popupMenuData(self) -> MenuData:
        ...

    @property
    def menuBarData(self) -> MenuData:
        ...

    @property
    def keyBindingData(self) -> KeyBindingData:
        ...

    @keyBindingData.setter
    def keyBindingData(self, value: KeyBindingData):
        ...

    @property
    def contextClass(self) -> java.lang.Class[docking.ActionContext]:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def validContext(self) -> jpype.JBoolean:
        ...

    @property
    def inceptionInformation(self) -> java.lang.String:
        ...

    @property
    def defaultKeyBindingData(self) -> KeyBindingData:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def ownerDescription(self) -> java.lang.String:
        ...


class ComponentThemeInspectorAction(DockingAction):

    @typing.type_check_only
    class Entry(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def toString(self, buffy: java.lang.StringBuilder, indent: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class TableEntry(ComponentThemeInspectorAction.Entry):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TreeEntry(ComponentThemeInspectorAction.Entry):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ShowActionChooserDialogAction(DockingAction):
    """
    Action for displaying the :obj:`ActionChooserDialog`. This action determines the focused 
    :obj:`ComponentProvider` or :obj:`DialogComponentProvider` and displays the 
    :obj:`ActionChooserDialog` with actions relevant to that focused component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GlobalFocusTraversalAction(DockingAction):
    """
    Action for global focus traversal. 
     
    
    The Java focus system suggests that both TAB and <CTRL> TAB move the focus to the next
    component in the focus traversal cycle. It also suggests that both <SHIFT> TAB and
    <CTRL><SHIFT> TAB move the focus to the previous component in the focus traversal
    cycle. 
     
    
    However, the implementation across Look And Feels and some components within those Look and 
    Feels are inconsistent with regards the <CTRL> version of these keys. Rather than try 
    and find and fix all the inconsistencies across all components
    and Look And Feels, we process the <CTRL> version of focus traversal using global
    reserved actions. We can't take the same approach for the base TAB and <SHIFT> TAB because 
    these really do need to be component specific as some components use these keys for some other
    purpose other than focus traversal.
     
    
    This global processing of <CTRL> TAB and <CTRL><SHIFT> TAB can be disabled by
    setting the system property :obj:`.GLOBAL_FOCUS_TRAVERSAL_PROPERTY` to "false"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keybinding: javax.swing.KeyStroke, forward: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["KeyBindingType", "ToggleDockingAction", "PopupMenuData", "ToggleDockingActionIf", "ShowFocusInfoAction", "AbstractHelpAction", "ActionContextProvider", "MenuBarData", "ToolBarData", "KeyBindingData", "SystemKeyBindingAction", "DockingActionProviderIf", "NextPreviousWindowAction", "KeyBindingsManager", "HelpInfoAction", "MultiActionDockingActionIf", "DockingAction", "ContextSpecificAction", "MultipleKeyAction", "MenuData", "ShowFocusCycleAction", "ComponentBasedDockingAction", "ShowContextMenuAction", "HelpAction", "DockingActionIf", "ComponentThemeInspectorAction", "ShowActionChooserDialogAction", "GlobalFocusTraversalAction"]
