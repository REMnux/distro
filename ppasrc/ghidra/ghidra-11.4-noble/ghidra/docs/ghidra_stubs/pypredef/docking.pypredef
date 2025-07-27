from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.actions
import docking.event.mouse
import docking.menu
import docking.widgets
import docking.widgets.label
import docking.widgets.table
import docking.widgets.textfield
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util
import ghidra.util.bean
import ghidra.util.task
import gui.event
import help
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.plaf # type: ignore
import javax.swing.text # type: ignore
import javax.swing.undo # type: ignore
import org.jdom # type: ignore


T = typing.TypeVar("T")


class WindowPosition(java.lang.Enum[WindowPosition]):
    """
    An enum used to signal where windows should be placed **when shown for the first time.**
    After being shown, a window's location is remembered, so that values is no longer used.
    """

    class_: typing.ClassVar[java.lang.Class]
    TOP: typing.Final[WindowPosition]
    BOTTOM: typing.Final[WindowPosition]
    LEFT: typing.Final[WindowPosition]
    RIGHT: typing.Final[WindowPosition]
    WINDOW: typing.Final[WindowPosition]
    """
    Signals that window should not be placed next to windows in other groups, but should 
    be placed into their own window.
     
    
    **This position is ignored when used with components that share the same group (a.k.a., 
    when used as an intragroup positioning item).**
    """

    STACK: typing.Final[WindowPosition]
    """
    Signals that windows should be stacked with other windows within  
    the same group.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> WindowPosition:
        ...

    @staticmethod
    def values() -> jpype.JArray[WindowPosition]:
        ...


@typing.type_check_only
class MySplitPane(javax.swing.JSplitPane):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, orientation: typing.Union[jpype.JInt, int], comp1: javax.swing.JComponent, comp2: javax.swing.JComponent):
        ...


class TaskScheduler(java.lang.Runnable):
    """
    Schedules tasks to be run in the :obj:`DialogComponentProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCurrentThread(self) -> java.lang.Thread:
        """
        Get the currently running thread.
        
        :return: null if no thread is running.
        :rtype: java.lang.Thread
        """

    def isBusy(self) -> bool:
        """
        Returns true if this task scheduler is running a task or has a pending task.
        
        :return: true if this task scheduler is running a task or has a pending task.
        :rtype: bool
        """

    def waitForCurrentTask(self):
        """
        Blocks until the current task completes.
        """

    @property
    def currentThread(self) -> java.lang.Thread:
        ...

    @property
    def busy(self) -> jpype.JBoolean:
        ...


class ActionToGuiHelper(java.lang.Object):
    """
    A class that exists primarily to provide access to action-related package-level methods of the
    :obj:`DockingWindowManager`.  This allows the manager's interface to hide methods that 
    don't make sense for public consumption.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: DockingWindowManager):
        ...

    def addLocalAction(self, provider: ComponentProvider, action: docking.action.DockingActionIf):
        """
        Adds an action that will be associated with the given provider.  These actions will
        appear in the local header for the component as a toolbar button or a drop-down menu
        item if it has an icon and menu path respectively.
        
        :param ComponentProvider provider: the provider whose header on which the action is to be placed
        :param docking.action.DockingActionIf action: the action to add to the providers header bar
        """

    def addToolAction(self, action: docking.action.DockingActionIf):
        """
        Adds an action to the global menu or toolbar which appear in the main frame. If the action 
        has a menu path, it will be in the menu.  If it has an icon, it will appear in the toolbar.
        
        :param docking.action.DockingActionIf action: the action to be added
        """

    def getComponentActions(self, provider: ComponentProvider) -> java.util.Iterator[docking.action.DockingActionIf]:
        """
        Get an iterator over the actions for the given provider
        
        :param ComponentProvider provider: the component provider for which to iterate over all its owned actions
        :return: null if the provider does not exist in the window manager
        :rtype: java.util.Iterator[docking.action.DockingActionIf]
        """

    def getGlobalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    def getLocalActions(self, provider: ComponentProvider) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    def keyBindingsChanged(self):
        """
        Call this method to signal that key bindings for one or more actions have changed
        """

    def removeProviderAction(self, provider: ComponentProvider, action: docking.action.DockingActionIf):
        """
        Removes the action from the given provider's header bar.
        
        :param ComponentProvider provider: the provider whose header bar from which the action should be removed.
        :param docking.action.DockingActionIf action: the action to be removed from the provider's header bar.
        """

    def removeToolAction(self, action: docking.action.DockingActionIf):
        """
        Removes the given action from the global menu and toolbar
        
        :param docking.action.DockingActionIf action: the action to be removed
        """

    @property
    def localActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def componentActions(self) -> java.util.Iterator[docking.action.DockingActionIf]:
        ...

    @property
    def globalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...


class ActionToGuiMapper(java.lang.Object):
    """
    Manages the global actions for the menu and toolbar.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMenuGroupMap(self) -> docking.menu.MenuGroupMap:
        ...

    def showPopupMenu(self, componentInfo: ComponentPlaceholder, popupContext: PopupMenuContext):
        ...

    @property
    def menuGroupMap(self) -> docking.menu.MenuGroupMap:
        ...


@typing.type_check_only
class ComponentTransferableData(java.io.Serializable):
    """
    Simple holder object for an owner string and name string.
    """

    class_: typing.ClassVar[java.lang.Class]


class SystemExecutableAction(ExecutableAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: docking.action.DockingActionIf, context: ActionContext):
        ...


class DockingMouseBindingAction(javax.swing.AbstractAction):
    """
    A class for using actions associated with mouse bindings. This class is meant to only by used by
    internal Ghidra mouse event processing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, action: docking.action.DockingActionIf, mouseBinding: gui.event.MouseBinding):
        ...

    def getFullActionName(self) -> str:
        ...

    @property
    def fullActionName(self) -> java.lang.String:
        ...


class ComponentProvider(help.HelpDescriptor, docking.action.ActionContextProvider):
    """
    Abstract base class for creating dockable GUI components within a tool.
     
    
    The one method that must be implemented is :meth:`getComponent() <.getComponent>` which is where the top level
    Swing JComponent is returned to be docked into the tool.  Typically, the GUI components are
    created in the constructor along with any local actions for the provider.  The getComponent()
    method then simply returns the top level component previously created by this provider.
     
    
    There are many other methods for configuring how to dock the component, set title information,
    configure grouping, set the help, add actions, and receive show/hide notifications, some
    of which are highlighted below.  Typically, implementers will use these methods to configure
    how the GUI component behaves within the tool, and then add the business logic that uses and reacts
    to the GUI components created in this provider.
     
    
    To effectively use this class you merely need to create your component, add your actions to
    this class (:meth:`addLocalAction(DockingActionIf) <.addLocalAction>`) and then add this provider to the tool
    (:meth:`addToTool() <.addToTool>`).
     
    
    This also provides several useful convenience methods:
     
    * :meth:`addLocalAction(DockingActionIf) <.addLocalAction>`
    * :meth:`addToTool() <.addToTool>`
    * :meth:`setVisible(boolean) <.setVisible>`
    * :meth:`setTitle(String) <.setTitle>`
    * :meth:`setIcon(Icon) <.setIcon>`
    
     
    
    There are a handful of stub methods that can be overridden as desired:
     
    * :meth:`componentActivated() <.componentActivated>` and :meth:`componentDeactived() <.componentDeactived>`
    * :meth:`componentHidden() <.componentHidden>` and :meth:`componentShown() <.componentShown>`
    
    
     
    
    **Show Provider Action** - Each provider has an action to show the provider.  For
    typical, non-transient providers (see :meth:`setTransient() <.setTransient>`) the action will appear in
    the tool's **Window** menu.   You can have your provider also appear in the tool's toolbar
    by calling :meth:`addToTool() <.addToTool>`.
     
    
    Historical Note: This class was created so that implementors could add local actions within the constructor
    without having to understand that they must first add themselves to the WindowManager.
    """

    @typing.type_check_only
    class ComponentProviderHierachyListener(java.awt.event.HierarchyListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ShowProviderAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_WINDOW_GROUP: typing.Final = "Default"

    @typing.overload
    def __init__(self, tool: Tool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Creates a new component provider with a default location of :obj:`WindowPosition.WINDOW`.
        
        :param Tool tool: The tool will manage and show this provider
        :param java.lang.String or str name: The providers name.  This is used to group similar providers into a tab within
                the same window.
        :param java.lang.String or str owner: The owner of this provider, usually a plugin name.
        """

    @typing.overload
    def __init__(self, tool: Tool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], contextType: java.lang.Class[typing.Any]):
        """
        Creates a new component provider with a default location of :obj:`WindowPosition.WINDOW`.
        
        :param Tool tool: The tool that will manage and show this provider.
        :param java.lang.String or str name: The providers name.  This is used to group similar providers into a tab within
                the same window.
        :param java.lang.String or str owner: The owner of this provider, usually a plugin name.
        :param java.lang.Class[typing.Any] contextType: the type of context supported by this provider; may be null (see
                :meth:`getContextType() <.getContextType>`
        """

    def addLocalAction(self, action: docking.action.DockingActionIf):
        """
        Adds the given action to the system and associates it with this provider.
        
        :param docking.action.DockingActionIf action: The action to add.
        """

    def addToTool(self):
        """
        Adds this provider to the tool in a new window that is not initially visible.  The provider
        will then show up in the "Windows" menu of the tool
        """

    def adjustFontSize(self, bigger: typing.Union[jpype.JBoolean, bool]):
        """
        Tells the provider to adjust the font size for this provider. By default, this method
        will adjust the font for the registered font id if it has been registered using
        :obj:`.registeredFontId`. Subclasses can override this method to a more comprehensive
        adjustment to multiple fonts if necessary.
        
        :param jpype.JBoolean or bool bigger: if true, the font should be made bigger, otherwise the font should be made
        smaller
        """

    def canBeParent(self) -> bool:
        """
        Returns true if the window containing this provider can be used as a parent window when
        showing system windows.   All providers will return true from this method by default.  This
        method is intended for short-lived providers to signal that their window should not be made
        the parent of new windows.
        
        :return: true if this provider can be a parent
        :rtype: bool
        """

    def closeComponent(self):
        """
        This is the callback that will happen when the user presses the 'X' button of a provider.
        Transient providers will be removed from the tool completely.   Non-transient providers
        will merely be hidden.
        
         
        Subclasses may override this method to prevent a provider from being closed; for
        example, if an editor has unsaved changes, then this method could prevent the close from
        happening.
        """

    def componentActivated(self):
        """
        Notifies the component provider that it is now the active provider
        """

    def componentDeactived(self):
        """
        Notifies the component provider that it is no longer the active provider
        """

    def componentHidden(self):
        """
        Notifies the provider that the component is being hidden.  This happens when the
        provider is being closed.
        """

    def componentMadeDisplayable(self):
        """
        Notifies the provider that the component has been made displayable.  When this method is 
        called, the component is part of the visible GUI hierarchy.  This is in contrast to 
        :meth:`componentShown() <.componentShown>`, which is called when the provider is part of the Docking 
        framework's hierarchy, but not necessarily visible to the user.
        
        
        .. seealso::
        
            | :obj:`.componentShown()`
        """

    def componentShown(self):
        """
        Notifies the provider that the component is being shown.   This method will be called as the
        component hierarchy is being created, which means that this provider may not actually be 
        visible to the user at the time of this call.
        
        
        .. seealso::
        
            | :obj:`.componentMadeDisplayable()`
        """

    def contextChanged(self):
        """
        Kicks the tool to let it know the context for this provider has changed.
        """

    def getActionContext(self, event: java.awt.event.MouseEvent) -> ActionContext:
        """
        Returns the context object which corresponds to the
        area of focus within this provider's component.  Null
        is returned when there is no context.
        
        :param java.awt.event.MouseEvent event: popup event which corresponds to this request.
        May be null for key-stroke or other non-mouse event.
        """

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the component to be displayed
        
        :return: the component to be displayed
        :rtype: javax.swing.JComponent
        """

    def getContextType(self) -> java.lang.Class[typing.Any]:
        """
        A signal used when installing actions.  Some actions are only added to a given window
        if there is a provider in that window that can work with that action.  Providers can return
        a context class from this method to control whether dependent actions get added.  Most
        providers return null for this method, which means they will not have any dependent
        actions added to windows other than the primary application window.
        
        :return: a class representing the desired context type or null;
        :rtype: java.lang.Class[typing.Any]
        """

    def getDefaultWindowPosition(self) -> WindowPosition:
        """
        The initial :obj:`WindowPosition` of this provider.  If a :meth:`window
        group <.getWindowGroup>` is provided, then this position is relative to that provider.  Otherwise, this
        position is relative to the tool window.
        
        :return: The initial :obj:`WindowPosition` of this provider.
        :rtype: WindowPosition
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the general HelpLocation for this provider.  Should return null only if no
        help documentation exists.
        
        :return: the help location
        :rtype: ghidra.util.HelpLocation
        """

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns the Icon associated with the component view
        
        :return: the Icon associated with the component view
        :rtype: javax.swing.Icon
        """

    def getInstanceID(self) -> int:
        """
        A unique ID for this provider
        
        :return: unique ID for this provider
        :rtype: int
        """

    def getIntraGroupPosition(self) -> WindowPosition:
        """
        The position of this provider when being placed with other members of the same group.  As
        an example, assume this provider is being shown for the first time while there is another
        member of its :meth:`window group <.getWindowGroup>` already visible.  Further, assume
        that this method will return :obj:`WindowPosition.STACK`.  This provider will then be
        stacked upon the already showing provider.
         
        
        To determine where this provider should be initially shown,
        see :meth:`getDefaultWindowPosition() <.getDefaultWindowPosition>`.
        
        :return: The position of this provider when being placed with other members of the same group.
        :rtype: WindowPosition
        """

    def getLocalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all the local actions registered for this component provider.
        
        :return: all the local actions registered for this component provider
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def getMappedName(oldOwner: typing.Union[java.lang.String, str], oldName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns any registered new provider owner for the oldName/oldOwner pair.
        
        :param java.lang.String or str oldOwner: the old owner name
        :param java.lang.String or str oldName: the old provider name
        :return: the new provider owner for that oldOwner/oldName
        :rtype: str
        """

    @staticmethod
    def getMappedOwner(oldOwner: typing.Union[java.lang.String, str], oldName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns any registered new provider name for the oldName/oldOwner pair.
        
        :param java.lang.String or str oldOwner: the old owner name
        :param java.lang.String or str oldName: the old provider name
        :return: the new provider name for that oldOwner/oldName
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of this provider
        
        :return: the name of this provider
        :rtype: str
        """

    def getOwner(self) -> str:
        """
        Returns the owner of this provider (usually a plugin)
        
        :return: the owner of this provider
        :rtype: str
        """

    def getSubTitle(self) -> str:
        """
        Returns the provider's current sub-title (Sub-titles don't show up
        in the window menu).
        
        :return: the provider's current sub-title.
        :rtype: str
        """

    def getTabText(self) -> str:
        """
        Returns the optionally set text to display in the tab for a component provider.   The
        text returned from :meth:`getTitle() <.getTitle>` will be used by default.
        
        :return: the optionally set text to display in the tab for a component provider.
        :rtype: str
        
        .. seealso::
        
            | :obj:`.setTabText(String)`
        """

    def getTitle(self) -> str:
        """
        Returns the provider's current title.
        
        :return: the provider's current title.
        :rtype: str
        """

    def getTool(self) -> Tool:
        ...

    def getWindowGroup(self) -> str:
        """
        Returns an optional group designator that, if non-null, the docking window manager uses to
        determine the initial location of the new component relative to any existing instances
        of this component Provider.
         
        
        The docking window manager will use :meth:`Intra-group Position <.getIntraGroupPosition>`
        to decide where to place this provider inside of the already open instances of the
        same group.  The default position is 'stack', which results in the new instance being
        stacked with other instances of this provider that have the same group unless that instance is
        the active provider or is currently stacked with the active provider. (This is to prevent
        new windows from covering the active window).
        
        :return: the window group
        :rtype: str
        """

    def getWindowSubMenuName(self) -> str:
        """
        Returns the name of a cascading sub-menu name to use when showing this provider in the
        "Window" menu. If the group name is null, the item will appear in the top-level menu.
        
        :return: the menu group for this provider or null if this provider should appear in the
        top-level menu.
        :rtype: str
        """

    def isActive(self) -> bool:
        """
        Convenience method to indicate if this provider is the active provider (has focus)
        
        :return: true if this provider is active.
        :rtype: bool
        """

    def isFocusedProvider(self) -> bool:
        """
        Returns true if this provider has focus
        
        :return: true if this provider has focus
        :rtype: bool
        """

    def isInTool(self) -> bool:
        ...

    def isShowing(self) -> bool:
        """
        Returns true if this provider is visible and is showing.  See :meth:`Component.isShowing() <Component.isShowing>`.
        
        :return: true if this provider is visible and is showing.
        :rtype: bool
        """

    def isSnapshot(self) -> bool:
        """
        A special marker that indicates this provider is a snapshot of a primary provider,
        somewhat like a picture of the primary provider.
        
        :return: true if a snapshot
        :rtype: bool
        """

    def isTransient(self) -> bool:
        """
        Returns true if this component goes away during a user session (most providers remain in
        the tool all session long, visible or not)
        
        :return: true if transient
        :rtype: bool
        """

    def isVisible(self) -> bool:
        """
        Convenience method to indicate if this provider is showing.
        
        :return: true if this provider is showing.
        :rtype: bool
        """

    @staticmethod
    def registerProviderNameOwnerChange(oldName: typing.Union[java.lang.String, str], oldOwner: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], newOwner: typing.Union[java.lang.String, str]):
        """
        Register a name and/or owner change to a provider so that old tools can restore those
        provider windows to their old position and size. Note you must supply all four
        arguments. If the name or owner did not change, use the name or owner that did not change
        for both the old and new values.
        
         
        Note: when you make use of this method, please signal when it is safe to remove
        its usage.
        
        :param java.lang.String or str oldName: the old name of the provider.
        :param java.lang.String or str oldOwner: the old owner of the provider.
        :param java.lang.String or str newName: the new name of the provider. If the name did not change, use the old name here.
        :param java.lang.String or str newOwner: the new owner of the provider. If the owner did not change, use the old owner here.
        """

    def removeFromTool(self):
        """
        Removes this provider from the tool.
        """

    def requestFocus(self):
        ...

    def resetFontSize(self):
        """
        Tells the provider to reset the font size for this provider.
         
        
        See :meth:`adjustFontSize(boolean) <.adjustFontSize>`
        """

    def setCustomSubTitle(self, subTitle: typing.Union[java.lang.String, str]):
        """
        The new custom sub-title.  Setting the sub-title here prevents future calls to 
        :meth:`setSubTitle(String) <.setSubTitle>` from having any effect.   This is done to preserve the custom 
        sub-title.
        
        :param java.lang.String or str subTitle: the sub-title
        """

    def setCustomTabText(self, tabText: typing.Union[java.lang.String, str]):
        """
        The new custom tab text.  Setting the text here prevents future calls to 
        :meth:`setTabText(String) <.setTabText>` from having any effect.   This is done to preserve the custom 
        tab text.
        
        :param java.lang.String or str tabText: the text
        """

    def setCustomTitle(self, title: typing.Union[java.lang.String, str]):
        """
        The new custom title.  Setting the title here prevents future calls to 
        :meth:`setTitle(String) <.setTitle>` from having any effect.   This is done to preserve the custom 
        title.
        
        :param java.lang.String or str title: the title
        """

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        ...

    def setIntraGroupPosition(self, position: WindowPosition):
        """
        See :meth:`getIntraGroupPosition() <.getIntraGroupPosition>`.
        
        :param WindowPosition position: the new position
        """

    def setSubTitle(self, subTitle: typing.Union[java.lang.String, str]):
        """
        Sets the provider's sub-title (Sub-titles don't show up
        in the window menu).
        
        :param java.lang.String or str subTitle: the sub-title string to use.
        """

    def setTabText(self, tabText: typing.Union[java.lang.String, str]):
        """
        Sets the text to be displayed on tabs when provider is stacked with other providers.
        
        :param java.lang.String or str tabText: the tab text.
        """

    def setTitle(self, title: typing.Union[java.lang.String, str]):
        """
        Sets the provider's title.
        
        :param java.lang.String or str title: the title string to use.
        """

    def setVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Convenience method to show or hide this provider.
        
        :param jpype.JBoolean or bool visible: True shows the provider; false hides the provider
        """

    def toFront(self):
        ...

    @property
    def windowSubMenuName(self) -> java.lang.String:
        ...

    @property
    def tabText(self) -> java.lang.String:
        ...

    @tabText.setter
    def tabText(self, value: java.lang.String):
        ...

    @property
    def icon(self) -> javax.swing.Icon:
        ...

    @property
    def title(self) -> java.lang.String:
        ...

    @title.setter
    def title(self, value: java.lang.String):
        ...

    @property
    def subTitle(self) -> java.lang.String:
        ...

    @subTitle.setter
    def subTitle(self, value: java.lang.String):
        ...

    @property
    def contextType(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def windowGroup(self) -> java.lang.String:
        ...

    @property
    def defaultWindowPosition(self) -> WindowPosition:
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @visible.setter
    def visible(self, value: jpype.JBoolean):
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @property
    def focusedProvider(self) -> jpype.JBoolean:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @helpLocation.setter
    def helpLocation(self, value: ghidra.util.HelpLocation):
        ...

    @property
    def tool(self) -> Tool:
        ...

    @property
    def actionContext(self) -> ActionContext:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def instanceID(self) -> jpype.JLong:
        ...

    @property
    def transient(self) -> jpype.JBoolean:
        ...

    @property
    def localActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def showing(self) -> jpype.JBoolean:
        ...

    @property
    def snapshot(self) -> jpype.JBoolean:
        ...

    @property
    def intraGroupPosition(self) -> WindowPosition:
        ...

    @intraGroupPosition.setter
    def intraGroupPosition(self, value: WindowPosition):
        ...

    @property
    def inTool(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class DropCode(java.lang.Enum[DropCode]):
    """
    An enum that represents available drag-n-drop options for a docking tool.  There are also
    convenience methods for translating this drop code into a cursor and window position.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID: typing.Final[DropCode]
    STACK: typing.Final[DropCode]
    LEFT: typing.Final[DropCode]
    RIGHT: typing.Final[DropCode]
    TOP: typing.Final[DropCode]
    BOTTOM: typing.Final[DropCode]
    ROOT: typing.Final[DropCode]
    WINDOW: typing.Final[DropCode]

    def getCursor(self) -> java.awt.Cursor:
        ...

    def getWindowPosition(self) -> WindowPosition:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DropCode:
        ...

    @staticmethod
    def values() -> jpype.JArray[DropCode]:
        ...

    @property
    def cursor(self) -> java.awt.Cursor:
        ...

    @property
    def windowPosition(self) -> WindowPosition:
        ...


@typing.type_check_only
class DetachedWindowNode(WindowNode):
    """
    Node class for managing a component hierarchy in its own sub-window. (currently uses a JDialog)
    """

    class_: typing.ClassVar[java.lang.Class]

    def clearStatusMessages(self):
        ...

    def getRootPane(self) -> javax.swing.JRootPane:
        """
        Returns the root pane if window has been created, otherwise null
        
        :return: the root pane if window has been created, otherwise null
        :rtype: javax.swing.JRootPane
        """

    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the status text
        
        :param java.lang.String or str text: the text
        """

    @property
    def rootPane(self) -> javax.swing.JRootPane:
        ...


class EmptyBorderToggleButton(docking.widgets.EmptyBorderButton):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        ...

    @typing.overload
    def __init__(self, action: docking.action.DockingActionIf):
        ...

    def toggle(self):
        """
        Changes the button's state to the opposite of its current state.  Calling this method 
        will also trigger a callback to the button's :meth:`Action.actionPerformed(ActionEvent) <Action.actionPerformed>`
        method.
        """


@typing.type_check_only
class ShowWindowAction(docking.action.DockingAction, docking.actions.AutoGeneratedDockingAction, java.lang.Comparable[ShowWindowAction]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ErrLogExpandableDialog(AbstractErrDialog):

    @typing.type_check_only
    class NodeWithText(java.lang.Object):

        class Util(java.lang.Object):

            class_: typing.ClassVar[java.lang.Class]
            INDENTATION: typing.Final = "    "

            def __init__(self):
                ...

            @staticmethod
            def collectReportText(cur: docking.widgets.tree.GTreeNode, included: collections.abc.Sequence, indent: typing.Union[jpype.JInt, int]) -> str:
                ...

            @staticmethod
            def containsAny(included: collections.abc.Sequence, allChildren: collections.abc.Sequence) -> bool:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def collectReportText(self, included: collections.abc.Sequence, indent: typing.Union[jpype.JInt, int]) -> str:
            ...

        def doesIndent(self) -> bool:
            ...

        def getReportText(self) -> str:
            ...

        @property
        def reportText(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class ReportRootNode(docking.widgets.tree.GTreeNode, ErrLogExpandableDialog.NodeWithText):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, title: typing.Union[java.lang.String, str], report: collections.abc.Sequence):
            ...


    @typing.type_check_only
    class ReportExceptionNode(docking.widgets.tree.GTreeLazyNode, ErrLogExpandableDialog.NodeWithText):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cause: java.lang.Throwable):
            ...


    @typing.type_check_only
    class ReportStackTraceNode(docking.widgets.tree.GTreeLazyNode, ErrLogExpandableDialog.NodeWithText):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cause: java.lang.Throwable):
            ...


    @typing.type_check_only
    class ReportCauseNode(ErrLogExpandableDialog.ReportExceptionNode):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cause: java.lang.Throwable):
            ...


    @typing.type_check_only
    class ReportStackFrameNode(docking.widgets.tree.GTreeNode, ErrLogExpandableDialog.NodeWithText):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, te: java.lang.StackTraceElement):
            ...


    @typing.type_check_only
    class ExcTreeTransferHandler(javax.swing.TransferHandler, docking.widgets.tree.support.GTreeDragNDropHandler):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, root: ErrLogExpandableDialog.ReportRootNode):
            ...


    class_: typing.ClassVar[java.lang.Class]
    IMG_REPORT: typing.ClassVar[javax.swing.Icon]
    IMG_EXCEPTION: typing.ClassVar[javax.swing.Icon]
    IMG_FRAME_ELEMENT: typing.ClassVar[javax.swing.Icon]
    IMG_STACK: typing.ClassVar[javax.swing.Icon]
    IMG_CAUSE: typing.ClassVar[javax.swing.Icon]


class CloseIcon(javax.swing.Icon):
    """
    Icon for a close button
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, isSmall: typing.Union[jpype.JBoolean, bool], color: java.awt.Color):
        """
        Creates a close icon.
        
        :param jpype.JBoolean or bool isSmall: false signals to use a 16x16 size; true signals to use an 8x8 size
        :param java.awt.Color color: the color of the "x"
        """


class StatusBar(javax.swing.JPanel):
    """
    Provides a status bar panel which has a text area to the left.  The status bar may
    customized with additional status components added to the right of the status text.
    """

    @typing.type_check_only
    class FadeTimer(javax.swing.Timer, java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AnimationDelayTimer(javax.swing.Timer, java.awt.event.ActionListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FlashTimer(javax.swing.Timer, java.awt.event.ActionListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StatusPanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def clearStatusMessages(self):
        ...

    def getStatusText(self) -> str:
        """
        Returns the current text in this status bar
        
        :return: the text
        :rtype: str
        """

    def getToolTipText(self) -> str:
        """
        Overridden to update the tooltip text to display a small history of
        status messages.
        
        :return: The new tooltip text.
        :rtype: str
        
        .. seealso::
        
            | :obj:`javax.swing.JComponent.getToolTipText()`
        """

    def removeStatusItem(self, c: javax.swing.JComponent):
        """
        Remove the specified status item.
        
        :param javax.swing.JComponent c: status component previously added.
        """

    @typing.overload
    @deprecated("Call setStatusText(String) instead.  Remove after 9.3")
    def setStatusText(self, text: typing.Union[java.lang.String, str], isActiveWindow: typing.Union[jpype.JBoolean, bool]):
        """
        Deprecated.  Call :meth:`setStatusText(String) <.setStatusText>` instead.
        
        :param java.lang.String or str text: the text
        :param jpype.JBoolean or bool isActiveWindow: this parameter is ignored
        
        .. deprecated::
        
        Call :meth:`setStatusText(String) <.setStatusText>` instead.  Remove after 9.3
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the status text
        
        :param java.lang.String or str text: the text
        """

    @property
    def statusText(self) -> java.lang.String:
        ...

    @statusText.setter
    def statusText(self, value: java.lang.String):
        ...

    @property
    def toolTipText(self) -> java.lang.String:
        ...


class MultiActionDialog(DialogComponentProvider):
    """
    Dialog to show multiple actions that are mapped to the same keystroke;
    allows the user to select which action to do.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, keystrokeName: typing.Union[java.lang.String, str], actions: java.util.List[docking.action.DockingActionIf], context: ActionContext):
        """
        Constructor
        
        :param java.lang.String or str keystrokeName: keystroke name
        :param java.util.List[docking.action.DockingActionIf] actions: list of actions
        :param ActionContext context: the context
        """


@typing.type_check_only
class ComponentTransferable(java.awt.datatransfer.Transferable, java.awt.datatransfer.ClipboardOwner):
    """
    Defines data that is available for drag/drop and clipboard transfers.
    The data is a CompProv object which is just a holder for a owner and name for a component.
    """

    class_: typing.ClassVar[java.lang.Class]
    localComponentProviderFlavor: typing.ClassVar[java.awt.datatransfer.DataFlavor]

    def getTransferData(self, f: java.awt.datatransfer.DataFlavor) -> java.lang.Object:
        """
        Return the transfer data with the given data flavor.
        """

    def getTransferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        """
        Return all data flavors that this class supports.
        """

    def isDataFlavorSupported(self, f: java.awt.datatransfer.DataFlavor) -> bool:
        """
        Return whether the specifed data flavor is supported.
        """

    def lostOwnership(self, clipboard: java.awt.datatransfer.Clipboard, contents: java.awt.datatransfer.Transferable):
        """
        ClipboardOwner interface method.
        """

    def toString(self) -> str:
        """
        Get the string representation for this transferable.
        """

    @property
    def transferData(self) -> java.lang.Object:
        ...

    @property
    def transferDataFlavors(self) -> jpype.JArray[java.awt.datatransfer.DataFlavor]:
        ...

    @property
    def dataFlavorSupported(self) -> jpype.JBoolean:
        ...


class DockingErrorDisplay(ghidra.util.ErrorDisplay):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ActionContext(java.lang.Object):
    """
    ActionContext is an interface used by :obj:`DockingActionIf`s that contains tool and
    plugin state information that allows an action to operate. Actions can use the context to get the
    information it needs to perform its intended purpose. Context is also used to determine if
    an action should be enabled, should be added to a popup menu, or if it is even valid for the 
    current context.
     
     
    
    The concept of an action being valid or invalid is critical to how the action system works. The
    reason is that actions can get their context from two different sources. The first
    source of action context is the current active (focused) :obj:`ComponentProvider`. This is
    always the preferred source of context for an action. However, if that context is not valid
    for an action, the action has the option of specifying that it works on default context. In this
    case, the tool will use the action's declared context type to see if anyone has registered a
    default  provider for that type. If so, the action will be given that context 
    to work on instead of the active context.
    
     
    
    Whenever the user moves the focus around by clicking on different components or locations in 
    the tool, all actions are given the opportunity to change their enablement state. The tool 
    calls each action's :meth:`DockingActionIf.isEnabledForContext(ActionContext) <DockingActionIf.isEnabledForContext>` method
    with the new active context (or default context as explained above).  Thus, toolbar 
    buttons and menu items will enable and disable as the user interacts with the system.
    
     
    
    When the user executes an action, the current context will be passed to the 
    :obj:`DockingActionIf`, again using a possible default context if the active context isn't valid
    for that action.  Ultimately, context serves to manage actions and to 
    allow plugins to share state with actions without them being directly coupled together.
    
     
    
    :obj:`ComponentProvider`s are required to return ActionContext objects in their 
    :meth:`ComponentProvider.getActionContext(MouseEvent) <ComponentProvider.getActionContext>` methods.  Generally, ComponentProviders 
    have two ways to use this class. They can either create an :obj:`DefaultActionContext` instance
    and pass in a contextObject that will be useful to its actions or, subclass the ActionContext
    object to include specific methods to provide the information that actions will require. If 
    actions want to work with default context, then they must declare a action context type that is
    more specific than just ActionContext.
     
     
    
    The generic data that all instances of ActionContxt provide is as follows:
     
     
    * provider - the component provider to which this context belongs; the provider that
                        contains the component that is the source of the user action
    
    * contextObject - client-defined data object.  This allows clients to save any 
                            information desired to be used when the action is performed.
    
    * sourceObject - when checking enablement, this is the item that was clicked or 
    activated; when performing an action this is either the active
    object or the component that was clicked.  This value may change
    between the check for
    :meth:`enablement <DockingActionIf.isEnabledForContext>`
    and:meth:`execution <DockingActionIf.actionPerformed>`.
    
    * sourceComponent - this value is the component that is the source of the current 
    context.  Whereas thesourceObject is the actual
    clicked item, this value is the focused/active component and
    will not change between
    :meth:`enablement <DockingActionIf.isEnabledForContext>`
    and:meth:`execution <DockingActionIf.actionPerformed>`.
    
    * mouseEvent - the mouse event that triggered the action; null if the action was
                            triggered by a key binding.
    
    
     
    
    Typically, component providers will define more specific types of ActionContext where they 
    can include any additional information that an action might need to work with that component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponentProvider(self) -> ComponentProvider:
        ...

    def getContextObject(self) -> java.lang.Object:
        """
        Returns the object that was included by the ComponentProvider when this context was created.
        
        :return: the object that was included by the ComponentProvider when this context was created.
        :rtype: java.lang.Object
        """

    def getEventClickModifiers(self) -> int:
        """
        Returns the click modifiers for this event.
         
        
        Only present for some mouse assisted events, e.g. clicking on a toolbar button or choosing
        a menu item in a popup menu.
        
        :return: bit-masked int, see :obj:`InputEvent.SHIFT_MASK`, etc
        :rtype: int
        """

    def getMouseEvent(self) -> java.awt.event.MouseEvent:
        """
        Returns the context's mouse event.  Contexts that are based upon key events will have no 
        mouse event.
        
        :return: the mouse event that triggered this context; null implies a key event-based context
        :rtype: java.awt.event.MouseEvent
        """

    def getSourceComponent(self) -> java.awt.Component:
        """
        Returns the component that is the target of this context.   This value should not change
        whether the context is triggered by a key binding or mouse event.
        
        :return: the component; may be null
        :rtype: java.awt.Component
        """

    def getSourceObject(self) -> java.lang.Object:
        """
        Returns the sourceObject from the actionEvent that triggered this context to be generated.
        
        :return: the sourceObject from the actionEvent that triggered this context to be generated.
        :rtype: java.lang.Object
        """

    def hasAnyEventClickModifiers(self, modifiersMask: typing.Union[jpype.JInt, int]) -> bool:
        """
        Tests the click modifiers for this event to see if they contain any bit from the
        specified modifiersMask parameter.
        
        :param jpype.JInt or int modifiersMask: bitmask to test
        :return: boolean true if any bit in the eventClickModifiers matches the mask
        :rtype: bool
        """

    def setContextObject(self, contextObject: java.lang.Object) -> ActionContext:
        """
        Sets the context object for this context.  This can be any object of the creator's 
        choosing that can be provided for later retrieval.
        
        :param java.lang.Object contextObject: Sets the context object for this context.
        :return: this context
        :rtype: ActionContext
        """

    def setEventClickModifiers(self, modifiers: typing.Union[jpype.JInt, int]):
        """
        Sets the modifiers for this event that were present when the item was clicked on.
        
        :param jpype.JInt or int modifiers: bit-masked int, see :meth:`ActionEvent.getModifiers() <ActionEvent.getModifiers>` or
        :meth:`MouseEvent.getModifiersEx() <MouseEvent.getModifiersEx>`
        """

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> ActionContext:
        """
        Updates the context's mouse event.  Contexts that are based upon key events will have no 
        mouse event.   This method is really for the framework to use.  Client calls to this 
        method will be overridden by the framework when menu items are clicked.
        
        :param java.awt.event.MouseEvent e: the event that triggered this context.
        :return: this context
        :rtype: ActionContext
        """

    def setSourceComponent(self, sourceComponent: java.awt.Component) -> ActionContext:
        """
        Sets the source component for this ActionContext.
        
        :param java.awt.Component sourceComponent: the source component
        :return: this context
        :rtype: ActionContext
        """

    def setSourceObject(self, sourceObject: java.lang.Object) -> ActionContext:
        """
        Sets the sourceObject for this ActionContext.  This method is used internally by the 
        DockingWindowManager. ComponentProvider and action developers should only use this 
        method for testing.
        
        :param java.lang.Object sourceObject: the source object
        :return: this context
        :rtype: ActionContext
        """

    @property
    def mouseEvent(self) -> java.awt.event.MouseEvent:
        ...

    @property
    def eventClickModifiers(self) -> jpype.JInt:
        ...

    @eventClickModifiers.setter
    def eventClickModifiers(self, value: jpype.JInt):
        ...

    @property
    def sourceComponent(self) -> java.awt.Component:
        ...

    @property
    def sourceObject(self) -> java.lang.Object:
        ...

    @property
    def contextObject(self) -> java.lang.Object:
        ...

    @property
    def componentProvider(self) -> ComponentProvider:
        ...


class DockableHeader(GenericHeader, java.awt.dnd.DragGestureListener, java.awt.dnd.DragSourceListener):
    """
    Component for providing component titles and toolbar. Also provides Drag
    source functionality.
    """

    @typing.type_check_only
    class DragCursorManager(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MacDragCursorManager(DockableHeader.DragCursorManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class EmphasizeDockableComponentAnimationDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percentComplete: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class EmphasizeDockableComponentPainter(ghidra.util.bean.GGlassPanePainter):

        @typing.type_check_only
        class ComponentPaintInfo(java.lang.Object):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class MenuBarMenuHandler(docking.menu.MenuHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: DockingWindowManager):
        ...


class DockingWindowListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dockingWindowAdded(self, windowNode: WindowNode):
        ...

    def dockingWindowChanged(self, windowNode: WindowNode):
        ...

    def dockingWindowFocusChanged(self, windowNode: WindowNode):
        ...

    def dockingWindowRemoved(self, windowNode: WindowNode):
        ...


class ComponentLoadedListener(java.lang.Object):
    """
    A listener interface to know when a component has been 
    made :meth:`displayable <Component.isDisplayable>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def componentLoaded(self, windowManager: DockingWindowManager, provider: ComponentProvider):
        """
        Called when the component is made displayable
        
        :param DockingWindowManager windowManager: the window manager associated with the loaded component; null if the
                component for this listener is not parented by a docking window manager
        :param ComponentProvider provider: the provider that is the parent of the given component; null if the
                component for this listener is not the child of a component provider
        """


class PlaceholderInstaller(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def installPlaceholder(self, placeholder: ComponentPlaceholder, position: WindowPosition):
        ...

    def uninstallPlaceholder(self, placeholder: ComponentPlaceholder, keepAround: typing.Union[jpype.JBoolean, bool]):
        ...


class SplitPanel(javax.swing.JPanel):

    @typing.type_check_only
    class SplitPanelLayout(java.awt.LayoutManager):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Divider(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, splitNode: SplitNode, leftComp: java.awt.Component, rightComp: java.awt.Component, isHorizontal: typing.Union[jpype.JBoolean, bool]):
        ...

    def isLeft(self, c: java.awt.Component) -> bool:
        ...

    def setDividerPosition(self, newPosition: typing.Union[jpype.JFloat, float]):
        ...

    @property
    def left(self) -> jpype.JBoolean:
        ...


class DockingKeyBindingAction(javax.swing.AbstractAction):
    """
    A class that can be used as an interface for using actions associated with keybindings. This
    class is meant to only by used by internal Ghidra key event processing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: Tool, action: docking.action.DockingActionIf, keyStroke: javax.swing.KeyStroke):
        ...

    def getActions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    def getExecutableAction(self, focusOwner: java.awt.Component) -> ExecutableAction:
        ...

    def isSystemKeybindingPrecedence(self) -> bool:
        ...

    @property
    def systemKeybindingPrecedence(self) -> jpype.JBoolean:
        ...

    @property
    def executableAction(self) -> ExecutableAction:
        ...

    @property
    def actions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...


class DialogComponentProviderPopupActionManager(java.lang.Object):

    @typing.type_check_only
    class PopupMenuHandler(docking.menu.MenuHandler):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, context: ActionContext):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DialogComponentProvider):
        ...


class ReusableDialogComponentProvider(DialogComponentProvider):
    """
    A version of :obj:`DialogComponentProvider` for clients to extend when they intend for their
    dialog to be reused.   Typically, dialogs are used once and then no longer referenced.
    Alternatively, some clients create a dialog and use it for the lifetime of their code.  This
    is typical of non-modal plugins.
     
    
    If you extend this class, then you must call the :meth:`dispose() <.dispose>` method when you are done
    with the dialog, such as in your plugin's ``dispose()`` method.
     
    
    The primary benefit of using this dialog is that any updates to the current theme will update
    this dialog, even when the dialog is not visible.  For dialogs that extend
    :obj:`DialogComponentProvider` directly, they only receive theme updates if they are visible.
    
    
    .. seealso::
    
        | :obj:`DialogComponentProvider`
    """

    class_: typing.ClassVar[java.lang.Class]


class UndoRedoKeeper(java.lang.Object):
    """
    Handles tracking undo and redo events.   Clients may wish to hold on to this class in order
    to clear the undo/redo queue.
     
     
    **Style Edits**
    
    :obj:`JTextPane`s allow for styles (color, bold, etc) to be applied to their text.  The
    default undo/redo events may arrive singly, not in bulk.   Thus, when the user presses undo, 
    each style change is undo, one at a time.   This is intuitive when the user controls the 
    application of style.  However, when style is applied programmatically, it can be odd to 
    see that the user-type text does not change, but just the coloring applied to that text.
     
    
    To address this issue, this class takes the approach of combining all style edits into a 
    single bulk edit.  Then, as the user presses undo, all style edits can be removed together, as
    well as any neighboring text edits.   **Put simply, this class tracks style edits such 
    that an undo operation will undo all style changes, as well as a single text edit.**
    """

    @typing.type_check_only
    class StyleCompoundEdit(javax.swing.undo.CompoundEdit):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def clear(self):
        ...


class KeyEntryListener(java.lang.Object):
    """
    Interface used to notify listener when a keystroke has changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def processEntry(self, keyStroke: javax.swing.KeyStroke):
        ...


@typing.type_check_only
class TransferActionListener(java.awt.event.ActionListener, java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Tool(ghidra.framework.plugintool.ServiceProvider):
    """
    Generic tool interface for managing :obj:`ComponentProvider`s and :obj:`actions <DockingActionIf>`
    """

    class_: typing.ClassVar[java.lang.Class]

    def addAction(self, action: docking.action.DockingActionIf):
        """
        Adds the action to the tool.
        
        :param docking.action.DockingActionIf action: the action to be added.
        """

    def addComponentProvider(self, componentProvider: ComponentProvider, show: typing.Union[jpype.JBoolean, bool]):
        """
        Adds the ComponentProvider to the tool, optionally making it visible.
        
        :param ComponentProvider componentProvider: the provider to add to the tool
        :param jpype.JBoolean or bool show: if true, the component is made visible.
        """

    def addContextListener(self, listener: DockingContextListener):
        """
        Adds the given context listener to this tool
        
        :param DockingContextListener listener: the listener to add
        """

    def addLocalAction(self, componentProvider: ComponentProvider, action: docking.action.DockingActionIf):
        """
        Adds the action to the given provider as a local action.
        
        :param ComponentProvider componentProvider: the provider to add the action to.
        :param docking.action.DockingActionIf action: the DockingAction to add to the componentProvider.
        """

    def addPopupActionProvider(self, provider: docking.actions.PopupActionProvider):
        """
        Adds the given popup action provider to this tool. This provider will be called each time the
        popup menu is about to be shown.
        
        :param docking.actions.PopupActionProvider provider: the provider
        """

    def clearStatusInfo(self):
        """
        Clear the status information
        """

    def close(self):
        """
        Suggests the tool to attempt to close(). This will be as though the user selected the close
        menu option on the tool or hit the closeWindow x button in the upper corner (Windows
        systems).
        """

    def contextChanged(self, provider: ComponentProvider):
        """
        Signals to the tool that the provider's context has changed. This lets toolbar and menu
        actions update enablement based on current context.
         
         
        
        Pass ``null`` to signal that the entire tool's context has changed
        
        :param ComponentProvider provider: the provider whose context changed; null to signal the tool's context
        """

    def getActiveComponentProvider(self) -> ComponentProvider:
        """
        Returns the active component provider, that which has focus
        
        :return: the active provider
        :rtype: ComponentProvider
        """

    def getAllActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Return a set of all actions in the tool.
         
         
        
        Note: the result may contain conceptually duplicate actions, which is when multiple actions
        exist that share the same full name (the full name is the action name with the owner name,
        such as "My Action (MyPlugin)".
        
        :return: set of all actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getComponentProvider(self, name: typing.Union[java.lang.String, str]) -> ComponentProvider:
        """
        Gets the ComponentProvider with the given name.
        
        :param java.lang.String or str name: the name of the provider to get
        :return: the provider
        :rtype: ComponentProvider
        """

    def getDockingActionsByOwnerName(self, owner: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all actions for the given owner
         
         
        
        Note: the result may contain conceptually duplicate actions, which is when multiple actions
        exist that share the same full name (the full name is the action name with the owner name,
        such as "My Action (MyPlugin)".
        
        :param java.lang.String or str owner: the action owner's name
        :return: the actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getGlobalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Return a set of all global actions in the tool.
         
         
        
        Note: the result may contain conceptually duplicate actions, which is when multiple actions
        exist that share the same full name (the full name is the action name with the owner name,
        such as "My Action (MyPlugin)".
        
        :return: set of all global actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getIcon(self) -> javax.swing.ImageIcon:
        """
        Get the icon that the tool is using
        
        :return: the icon that the tool is using
        :rtype: javax.swing.ImageIcon
        """

    def getLocalActions(self, componentProvider: ComponentProvider) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Return a set of all local actions for the given :obj:`ComponentProvider`.
        
        :param ComponentProvider componentProvider: the component provider from which to get local actions
        :return: set of all local actions for the given provider
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getName(self) -> str:
        """
        Returns a combination of the tool name and the instance name of the form tool name(instance
        name), e.g., SomeTool(2)
        
        :return: the tool name
        :rtype: str
        """

    def getOptions(self, categoryName: typing.Union[java.lang.String, str]) -> ghidra.framework.options.ToolOptions:
        """
        Get the options for the given category name; if no options exist with the given name, then
        one is created.
        
        :param java.lang.String or str categoryName: the category name
        :return: the options
        :rtype: ghidra.framework.options.ToolOptions
        """

    def getProviderWindow(self, componentProvider: ComponentProvider) -> java.awt.Window:
        """
        Returns the parent window for the given provider
        
        :param ComponentProvider componentProvider: the provider
        :return: the window
        :rtype: java.awt.Window
        """

    def getStatusInfo(self) -> str:
        """
        Get the status information
        
        :return: the string displayed in the Status area
        :rtype: str
        """

    def getToolActions(self) -> docking.actions.DockingToolActions:
        """
        Returns the class that manages actions for the tool.
         
         
        
        Most clients will not need to use this methods. Instead, actions should be added to the tool
        via :meth:`addAction(DockingActionIf) <.addAction>` and
        :meth:`addLocalAction(ComponentProvider, DockingActionIf) <.addLocalAction>`.
        
        :return: the action manager
        :rtype: docking.actions.DockingToolActions
        """

    def getWindowManager(self) -> DockingWindowManager:
        """
        Returns the DockingWindowManger for this tool.
        
        :return: the DockingWindowManger for this tool.
        :rtype: DockingWindowManager
        """

    def hasConfigChanged(self) -> bool:
        """
        Return true if the tool's configuration has changed
        
        :return: true if the tool's configuration has changed
        :rtype: bool
        """

    def isActive(self, componentProvider: ComponentProvider) -> bool:
        """
        Returns true if the ComponentProvider is the currently active provider. The active provider
        is the provider that has keyboard focus and provides the current action context.
        
        :param ComponentProvider componentProvider: the provider to check for active.
        :return: true if the ComponentProvider is the currently active provider.
        :rtype: bool
        """

    @typing.overload
    def isVisible(self) -> bool:
        """
        Returns true if tool is visible
        
        :return: true if tool is visible
        :rtype: bool
        """

    @typing.overload
    def isVisible(self, componentProvider: ComponentProvider) -> bool:
        """
        Returns true if the given ComponentProvider is currently visible.
        
        :param ComponentProvider componentProvider: the provider to check for visibility.
        :return: true if the given ComponentProvider is currently visible.
        :rtype: bool
        """

    def removeAction(self, action: docking.action.DockingActionIf):
        """
        Removes the given action from the tool. When an action is removed from the tool it will be
        disposed and should not be reused.
        
        :param docking.action.DockingActionIf action: the action to be removed.
        """

    def removeComponentProvider(self, componentProvider: ComponentProvider):
        """
        Removes the given ComponentProvider from the tool. When a provider has been removed from the
        tool it is considered disposed and should not be reused.
        
        :param ComponentProvider componentProvider: the provider to remove from the tool
        """

    def removeContextListener(self, listener: DockingContextListener):
        """
        Removes the given context listener to this tool
        
        :param DockingContextListener listener: the listener to add
        """

    def removeLocalAction(self, componentProvider: ComponentProvider, action: docking.action.DockingActionIf):
        """
        Removes the action from the provider
        
        :param ComponentProvider componentProvider: the component provider from which to remove the action.
        :param docking.action.DockingActionIf action: the action to remove.
        """

    def removePopupActionProvider(self, provider: docking.actions.PopupActionProvider):
        """
        Removes the given popup action provider
        
        :param docking.actions.PopupActionProvider provider: the provider
        """

    def setConfigChanged(self, changed: typing.Union[jpype.JBoolean, bool]):
        """
        Toggles the "change" state of the tool...
        
        :param jpype.JBoolean or bool changed: true indicates that the tool config has changed.
        """

    def setMenuGroup(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str], menuSubGroup: typing.Union[java.lang.String, str]):
        """
        Set the menu group associated with a cascaded submenu. This allows a cascading menu item to
        be grouped with a specific set of actions.
         
        
        The default group for a cascaded submenu is the name of the submenu.
        
        :param jpype.JArray[java.lang.String] menuPath: menu name path where the last element corresponds to the specified group
                    name.
        :param java.lang.String or str group: group name
        :param java.lang.String or str menuSubGroup: the name used to sort the cascaded menu within other menu items at its
                    level
        """

    @typing.overload
    def setStatusInfo(self, text: typing.Union[java.lang.String, str]):
        """
        Set the status information
        
        :param java.lang.String or str text: non-html string to be displayed in the Status display area
        """

    @typing.overload
    def setStatusInfo(self, text: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Set the status information
        
        :param java.lang.String or str text: string to be displayed in the Status display area
        :param jpype.JBoolean or bool beep: whether to be or not
        """

    def setVisible(self, visibility: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the tool visible or invisible. This method is used by the Project to make it's tools
        visible or invisible depending on whether this tool is in is the active workspace.
        
        :param jpype.JBoolean or bool visibility: true specifies that the tool should be visible
        """

    def showComponentProvider(self, componentProvider: ComponentProvider, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Shows or hides the component provider in the tool
        
        :param ComponentProvider componentProvider: the provider to either show or hide.
        :param jpype.JBoolean or bool visible: true to show the provider, false to hide it.
        """

    def showDialog(self, dialogComponent: DialogComponentProvider):
        """
        Shows the dialog using the tool's root frame as a parent. Also, remembers any size and
        location adjustments made by the user for the next time the dialog is shown.
        
        :param DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        """

    @typing.overload
    def toFront(self):
        """
        Brings this tool to the front. Places this tool at the top of the stacking order and shows it
        in front of any other tools.
        """

    @typing.overload
    def toFront(self, componentProvider: ComponentProvider):
        """
        Makes the given ComponentProvider move to the front if it is tabbed with other components.
        
        :param ComponentProvider componentProvider: the provider to move to the top of its stacking order.
        """

    def updateTitle(self, componentProvider: ComponentProvider):
        """
        Indicates to the tool that the given componentProvider's title has changed.
        
        :param ComponentProvider componentProvider: the componentProvider whose title has changed.
        """

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @visible.setter
    def visible(self, value: jpype.JBoolean):
        ...

    @property
    def statusInfo(self) -> java.lang.String:
        ...

    @statusInfo.setter
    def statusInfo(self, value: java.lang.String):
        ...

    @property
    def icon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @property
    def activeComponentProvider(self) -> ComponentProvider:
        ...

    @property
    def dockingActionsByOwnerName(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def globalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def windowManager(self) -> DockingWindowManager:
        ...

    @property
    def localActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def allActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def options(self) -> ghidra.framework.options.ToolOptions:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def toolActions(self) -> docking.actions.DockingToolActions:
        ...

    @property
    def providerWindow(self) -> java.awt.Window:
        ...

    @property
    def componentProvider(self) -> ComponentProvider:
        ...


class WindowActionManager(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class KeyBindingOverrideKeyEventDispatcher(java.awt.KeyEventDispatcher):
    """
    Allows Ghidra to give preference to its key event processing over the default Java key event
    processing.  See :meth:`dispatchKeyEvent(KeyEvent) <.dispatchKeyEvent>` for a more detailed explanation of how
    Ghidra processes key events.
     
    
    :meth:`install() <.install>` must be called in order to install this ``Singleton`` into Java's
    key event processing system.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispatchKeyEvent(self, event: java.awt.event.KeyEvent) -> bool:
        """
        Overridden to change the Java's key event processing to insert Ghidra's top level tool
        key bindings into the event processing.  Java's normal key event processing is:
         
        1. KeyListeners on the focused Component
        2. InputMap and ActionMap actions for the Component
        3. InputMap and ActionMap actions for the Component's parent, and so on up the
        Swing hierarchy
        
        Ghidra has altered this flow to be:
         
        1. Reserved keybinding actions
        2. KeyListeners on the focused Component
        3. InputMap and ActionMap actions for the Component
        4. Ghidra tool-level actions
        5. InputMap and ActionMap actions for the Component's parent, and so on up the
        Swing hierarchy
        
        This updated key event processing allows individual components to handle key events first,
        but then allows global Ghidra key bindings to be processed, allowing normal Java processing
        after Ghidra has had its chance to process the event.
         
        
        There are some exceptions to this processing chain:
         
        1. We don't do any processing when the focused component is an instance of
        JTextComponent.
        2. We don't do any processing if the active window is an instance of
        DockingDialog.
        
        
        
        .. seealso::
        
            | :obj:`java.awt.KeyEventDispatcher.dispatchKeyEvent(java.awt.event.KeyEvent)`
        """


class StatusBarSpacer(docking.widgets.label.GIconLabel):
    """
    A class to handle the space requirements on the status bar that vary for different OSes.  For 
    example, the Mac requires extra space on the status bar, due to the drag icon the Mac uses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class KeyEntryTextField(docking.widgets.textfield.HintTextField):
    """
    Text field captures key strokes and notifies a listener to process the key entry.
    """

    @typing.type_check_only
    class MyKeyListener(java.awt.event.KeyListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], listener: KeyEntryListener):
        """
        Construct a new entry text field.
        
        :param jpype.JInt or int columns: number of columns in the text field
        :param KeyEntryListener listener: listener that is notified when the a key is pressed
        """

    def clearField(self):
        """
        Clears the state of this class, but does not notify listeners.  This allows clients to 
        control the state of the field without having a callback change the client state.
        """

    def clearKeyStroke(self):
        """
        Clears the state of this class and notifies this client.  This effectively allows for the
        programmatic setting of the keystroke in use to be null, or in the 'no keystroke set' state.
        """

    def getKeyStroke(self) -> javax.swing.KeyStroke:
        """
        Get the current key stroke
        
        :return: the key stroke
        :rtype: javax.swing.KeyStroke
        """

    def setDisabledHint(self, disabledHint: typing.Union[java.lang.String, str]):
        """
        Sets the hint text that will be displayed when this field is disabled
        
        :param java.lang.String or str disabledHint: the hint text
        """

    def setKeyStroke(self, ks: javax.swing.KeyStroke):
        """
        Sets the current key stroke
        
        :param javax.swing.KeyStroke ks: the new key stroke
        """

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...

    @keyStroke.setter
    def keyStroke(self, value: javax.swing.KeyStroke):
        ...


class MouseBindingMouseEventDispatcher(java.lang.Object):
    """
    Allows Ghidra to give preference to its mouse event processing over the default Java mouse event
    processing.  This class allows us to assign mouse bindings to actions.
     
    
    :meth:`install() <.install>` must be called in order to install this ``Singleton`` into Java's
    mouse event processing system.
    
    
    .. seealso::
    
        | :obj:`KeyBindingOverrideKeyEventDispatcher`
    """

    @typing.type_check_only
    class PendingActionInfo(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def action(self) -> DockingMouseBindingAction:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def mouseBinding(self) -> gui.event.MouseBinding:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]


class PopupMenuHandler(docking.menu.MenuHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: DockingWindowManager, context: ActionContext):
        ...


class DockingWindowManager(java.beans.PropertyChangeListener, PlaceholderInstaller):
    """
    Manages the "Docking" arrangement of a set of components and actions. The components can be
    "docked" together or exist in their own window. Actions can be associated with components so they
    "move" with the component as it moved from one location to another.
     
    
    Components are added via ComponentProviders. A ComponentProvider is an interface for getting a
    component and its related information. The docking window manager will get the component from the
    provider as needed. It is up to the provider if it wants to reuse the component or recreate a new
    one when the component is requested. When the user hides a component (by using the x button on
    the component header), the docking window manager removes all knowledge of the component and will
    request it again from the provider if the component is again shown. The provider is also notified
    whenever a component is hidden and shown.
    """

    class_: typing.ClassVar[java.lang.Class]
    DOCKING_WINDOWS_OWNER: typing.Final = "DockingWindows"
    """
    The owner name for docking windows actions.
     
    
    Warning: Any action with this owner will get removed every time the 'Window' menu is rebuilt,
    with the exception if reserved key bindings.
    """

    TOOL_PREFERENCES_XML_NAME: typing.Final = "PREFERENCES"

    @typing.overload
    def __init__(self, tool: Tool, images: java.util.List[java.awt.Image]):
        """
        Constructs a new DockingWindowManager
        
        :param Tool tool: the tool
        :param java.util.List[java.awt.Image] images: the images to use for windows in this window manager
        """

    @typing.overload
    def __init__(self, tool: Tool, images: java.util.List[java.awt.Image], modal: typing.Union[jpype.JBoolean, bool], isDocking: typing.Union[jpype.JBoolean, bool], hasStatusBar: typing.Union[jpype.JBoolean, bool], factory: DropTargetFactory):
        """
        Constructs a new DockingWindowManager
        
        :param Tool tool: the tool
        :param java.util.List[java.awt.Image] images: the list of icons to set on the window
        :param jpype.JBoolean or bool modal: if true then the root window will be a modal dialog instead of a frame
        :param jpype.JBoolean or bool isDocking: true for normal operation, false to suppress docking support(removes
                    component headers and window menu)
        :param jpype.JBoolean or bool hasStatusBar: if true a status bar will be created for the main window
        :param DropTargetFactory factory: the drop target factory
        """

    @typing.overload
    def addComponent(self, provider: ComponentProvider):
        """
        Adds a new component (via the provider) to be managed by this docking window manager. The
        component is initially hidden.
        
        :param ComponentProvider provider: the component provider
        """

    @typing.overload
    def addComponent(self, provider: ComponentProvider, show: typing.Union[jpype.JBoolean, bool]):
        """
        Adds a new component (via the provider) to be managed by this docking window manager. The
        component will be initially shown or hidden based on the "show" parameter.
        
        :param ComponentProvider provider: the component provider.
        :param jpype.JBoolean or bool show: indicates whether or not the component should be initially shown.
        """

    def addContextListener(self, listener: DockingContextListener):
        ...

    def addPopupActionProvider(self, provider: docking.actions.PopupActionProvider):
        """
        Adds the given popup action provider to this tool. This provider will be called each time the
        popup menu is about to be shown.
        
        :param docking.actions.PopupActionProvider provider: the provider
        """

    def addStatusItem(self, c: javax.swing.JComponent, addBorder: typing.Union[jpype.JBoolean, bool], rightSide: typing.Union[jpype.JBoolean, bool]):
        """
        Add a new status item component to the status area. The preferred height and border for the
        component will be altered. The components preferred width will be preserved.
        
        :param javax.swing.JComponent c: the status item component to add
        :param jpype.JBoolean or bool addBorder: True signals to add a border to the status area
        :param jpype.JBoolean or bool rightSide: component will be added to the right-side of the status area if true, else
                    it will be added immediately after the status text area if false.
        """

    @staticmethod
    def beep():
        """
        A convenience method to make an attention-grabbing noise to the user
        """

    @staticmethod
    def clearMouseOverHelp():
        ...

    def containsProvider(self, provider: ComponentProvider) -> bool:
        """
        Returns true if this manager contains the given provider.
        
        :param ComponentProvider provider: the provider for which to check
        :return: true if this manager contains the given provider.
        :rtype: bool
        """

    def contextChanged(self, provider: ComponentProvider):
        ...

    def createActionContext(self, action: docking.action.DockingActionIf) -> ActionContext:
        """
        Creates the :obj:`ActionContext` appropriate for the given action. This will normally be the
        context from the currently focused :obj:`ComponentProvider`. If that context is not valid
        for the given action and the action supports using the default tool context, then the default
        tool context will be returned. Otherwise, returns a generic ActionContext.
        
        :param docking.action.DockingActionIf action: the action for which to get an :obj:`ActionContext`
        :return: the :obj:`ActionContext` appropriate for the given action or null
        :rtype: ActionContext
        """

    @staticmethod
    def createSharedActions(tool: Tool, toolActions: docking.actions.ToolActions, owner: typing.Union[java.lang.String, str]):
        """
        Called by the framework during startup to register actions that are shared throughout the 
        tool.  See :obj:`SharedActionRegistry`.
        
        :param Tool tool: the tool
        :param docking.actions.ToolActions toolActions: the class to which the actions should be added
        :param java.lang.String or str owner: the shared action owner
        """

    def dispose(self):
        """
        Releases all resources used by this docking window manager. Once the dispose method is
        called, no other calls to this object should be made.
        """

    def getActiveComponent(self) -> java.awt.Component:
        """
        Returns the current active component.
        
        :return: the current active component.
        :rtype: java.awt.Component
        """

    def getActiveComponentProvider(self) -> ComponentProvider:
        ...

    @staticmethod
    def getActiveInstance() -> DockingWindowManager:
        """
        Returns the last active docking window manager which is visible.
        
        :return: the last active docking window manager which is visible.
        :rtype: DockingWindowManager
        """

    def getActiveWindow(self) -> java.awt.Window:
        """
        Returns the active window (or the root window if nobody has yet been made active).
        
        :return: the active window.
        :rtype: java.awt.Window
        """

    @staticmethod
    def getAllDockingWindowManagers() -> java.util.List[DockingWindowManager]:
        """
        Returns a new list of all DockingWindowManager instances known to exist, ordered from least
        to most-recently active.
        
        :return: a new list of all DockingWindowManager instances know to exist.
        :rtype: java.util.List[DockingWindowManager]
        """

    def getComponentActions(self, provider: ComponentProvider) -> java.util.Iterator[docking.action.DockingActionIf]:
        """
        Get the local actions installed on the given provider
        
        :param ComponentProvider provider: the provider
        :return: an iterator over the actions
        :rtype: java.util.Iterator[docking.action.DockingActionIf]
        """

    @typing.overload
    def getComponentProvider(self, name: typing.Union[java.lang.String, str]) -> ComponentProvider:
        """
        Returns the ComponentProvider with the given name. If more than one provider exists with the
        name, one will be returned, but it could be any one of them.
        
        :param java.lang.String or str name: the name of the provider to return.
        :return: a provider with the given name, or null if no providers with that name exist.
        :rtype: ComponentProvider
        """

    @typing.overload
    def getComponentProvider(self, clazz: java.lang.Class[T]) -> T:
        """
        The **first** provider instance with a class equal to that of the given class
        
        :param java.lang.Class[T] clazz: the class of the desired provider
        :return: the **first** provider instance with a class equal to that of the given class.
        :rtype: T
        
        .. seealso::
        
            | :obj:`.getComponentProviders(Class)`
        """

    @typing.overload
    def getComponentProvider(self, component: java.awt.Component) -> ComponentProvider:
        """
        Returns the component provider that is the conceptual parent of the given component. More
        precisely, this will return the component provider whose
        :meth:`component <ComponentProvider.getComponent>` is the parent of the given component.
        
        :param java.awt.Component component: the component for which to find a provider
        :return: the provider; null if the component is not the child of a provider
        :rtype: ComponentProvider
        """

    def getComponentProviders(self, clazz: java.lang.Class[T]) -> java.util.List[T]:
        """
        Gets all components providers with a matching class. Some component providers will have
        multiple instances in the tool
        
        :param java.lang.Class[T] clazz: The class of the provider
        :return: all found provider instances
        :rtype: java.util.List[T]
        """

    def getDefaultActionContext(self, contextType: java.lang.Class[ActionContext]) -> ActionContext:
        """
        Returns the default :obj:`ActionContext` for the given context type
        
        :param java.lang.Class[ActionContext] contextType: the class of the ActionContext to get a default value for
        :return: the default :obj:`ActionContext` for the given context type
        :rtype: ActionContext
        """

    def getDefaultActionContextMap(self) -> java.util.Map[java.lang.Class[ActionContext], ActionContext]:
        """
        Returns a map containing a default :obj:`ActionContext` for each registered type.
        
        :return: a map containing a default :obj:`ActionContext` for each registered type
        :rtype: java.util.Map[java.lang.Class[ActionContext], ActionContext]
        """

    def getFocusedComponent(self) -> ComponentPlaceholder:
        """
        Returns the component which has focus
        
        :return: the placeholder
        :rtype: ComponentPlaceholder
        """

    def getGlobalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns the set of global tool actions
        
        :return: the set of global tool actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def getHelpService() -> help.HelpService:
        """
        Returns the global help service.
        
        :return: the global help service.
        :rtype: help.HelpService
        """

    @staticmethod
    def getInstance(component: java.awt.Component) -> DockingWindowManager:
        """
        A convenience method for getting the window for ``component`` and then calling
        :meth:`getInstanceForWindow(Window) <.getInstanceForWindow>`.
        
        :param java.awt.Component component: The component for which to get the associated :obj:`DockingWindowManager`
                    instance.
        :return: The :obj:`DockingWindowManager` instance associated with ``component``
        :rtype: DockingWindowManager
        """

    def getMainWindow(self) -> java.awt.Window:
        """
        Returns the root window.
        
        :return: the root window.
        :rtype: java.awt.Window
        """

    @staticmethod
    def getMouseOverAction() -> docking.action.DockingActionIf:
        ...

    @staticmethod
    def getMouseOverObject() -> java.lang.Object:
        ...

    def getPreferenceState(self, key: typing.Union[java.lang.String, str]) -> ghidra.framework.options.PreferenceState:
        """
        Gets a preferences state object stored with the given key. The state objects are loaded from
        persistent storage when the tool using this window manager has its state loaded.
        
        :param java.lang.String or str key: The key with which to store the preferences.
        :return: the PrefrenceState object stored by the given key, or null if one does not exist
        :rtype: ghidra.framework.options.PreferenceState
        
        .. seealso::
        
            | :obj:`.putPreferenceState(String, PreferenceState)`
        """

    def getProvider(self, c: java.awt.Component) -> ComponentProvider:
        """
        Get the provider that contains the specified component
        
        :param java.awt.Component c: the component
        :return: the provider; null if now containing provider is found
        :rtype: ComponentProvider
        """

    def getProviderWindow(self, provider: ComponentProvider) -> java.awt.Window:
        """
        Get the window that contains the specified Provider's component
        
        :param ComponentProvider provider: component provider
        :return: window or null if component is not visible or not found
        :rtype: java.awt.Window
        """

    def getRootFrame(self) -> javax.swing.JFrame:
        """
        Returns the root window frame.
        
        :return: the root window frame.
        :rtype: javax.swing.JFrame
        """

    def getStatusText(self) -> str:
        """
        Get the status text in the active component window
        
        :return: string currently displayed in the Status display area
        :rtype: str
        """

    def getSubTitle(self, provider: ComponentProvider) -> str:
        """
        Returns the current subtitle for the component for the given provider.
        
        :param ComponentProvider provider: the component provider of the component for which to get its subtitle.
        :return: the current subtitle for the component for the given provider.
        :rtype: str
        """

    def getTool(self) -> Tool:
        """
        Returns the tool that owns this manager
        
        :return: the tool
        :rtype: Tool
        """

    def getWindows(self, includeMain: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.awt.Window]:
        """
        Returns a list with all the windows in the windowStack. Used for testing.
        
        :param jpype.JBoolean or bool includeMain: if true, include the main root window.
        :return: a list with all the windows in the windowStack. Used for testing.
        :rtype: java.util.List[java.awt.Window]
        """

    def hasStatusBar(self) -> bool:
        """
        Returns true if a status bar is present.
        
        :return: true if a status bar is present.
        :rtype: bool
        """

    def isActiveProvider(self, provider: ComponentProvider) -> bool:
        ...

    def isLastComponentInWindow(self, provider: ComponentProvider) -> bool:
        """
        Returns true if the given provider is the last provider in its window.
        
        :param ComponentProvider provider: the provider
        :return: true if the given provider is the last provider in its window.
        :rtype: bool
        """

    def isLastProviderInDetachedWindow(self, provider: ComponentProvider) -> bool:
        """
        Returns true if the given provider is in a non-main window (a :obj:`DetachedWindowNode`)
        and is the last component provider in that window.
        
        :param ComponentProvider provider: the provider
        :return: true if the last provider in a non-main window
        :rtype: bool
        """

    @typing.overload
    def isVisible(self) -> bool:
        """
        Returns true if the set of windows associated with this window manager are visible.
        
        :return: true if the set of windows associated with this window manager are visible.
        :rtype: bool
        """

    @typing.overload
    def isVisible(self, provider: ComponentProvider) -> bool:
        """
        Returns true if the specified provider's component is or soon will be visible.
        
        :param ComponentProvider provider: component provider
        :return: true if the specified provider's component is visible
        :rtype: bool
        """

    def isWindowsOnTop(self) -> bool:
        """
        Returns true if the window mode is "satellite windows always on top of root window".
        
        :return: true if the window mode is "satellite windows always on top of root window".
        :rtype: bool
        """

    def ownerRemoved(self, owner: typing.Union[java.lang.String, str]):
        ...

    def putPreferenceState(self, key: typing.Union[java.lang.String, str], state: ghidra.framework.options.PreferenceState):
        """
        Adds a PreferenceState object to this window manager instance that is bound to the given key.
        When the state of the tool using this window manager is saved, then the mapped preferences
        will also be saved.
        
        :param java.lang.String or str key: The key with which to store the preferences.
        :param ghidra.framework.options.PreferenceState state: The state object to store.
        
        .. seealso::
        
            | :obj:`.getPreferenceState(String)`
        """

    @staticmethod
    def registerComponentLoadedListener(component: java.awt.Component, listener: ComponentLoadedListener):
        """
        Registers a callback to be notified when the given component has been parented to a docking
        window manager
        
        :param java.awt.Component component: the component that will be parented in a docking window system
        :param ComponentLoadedListener listener: the listener to be notified the component was parented
        """

    def registerDefaultContextProvider(self, type: java.lang.Class[ActionContext], provider: docking.action.ActionContextProvider):
        """
        Registers an action context provider as the default provider for a specific action
        context type. Note that this registers a default provider for exactly
        that type and not a subclass of that type. If the provider want to support a hierarchy of
        types, then it must register separately for each type. See :obj:`ActionContext` for details
        on how the action context system works.
        
        :param java.lang.Class[ActionContext] type: the ActionContext class to register a default provider for
        :param docking.action.ActionContextProvider provider: the ActionContextProvider that provides default tool context for actions
        that consume the given ActionContext type
        """

    def registerPreferenceStateSupplier(self, key: typing.Union[java.lang.String, str], supplier: java.util.function.Supplier[ghidra.framework.options.PreferenceState]):
        """
        Registers a supplier of the preference state for the given key.  Using this method allows the
        window manager to query the supplier when the tool is saved.  Clients can then decide whether
        they have any state that needs saving at that time.
        
        :param java.lang.String or str key: the key with which to store the preferences.
        :param java.util.function.Supplier[ghidra.framework.options.PreferenceState] supplier: the supplier of the state object to store.
        """

    def removeComponent(self, provider: ComponentProvider):
        """
        Removes the ComponentProvider (component) from the docking windows manager. The location of
        the window will be remember and reused if the provider is added back in later.
        
        :param ComponentProvider provider: the provider to be removed.
        """

    def removeContextListener(self, listener: DockingContextListener):
        ...

    def removePopupActionProvider(self, provider: docking.actions.PopupActionProvider):
        """
        Removes the given popup action provider
        
        :param docking.actions.PopupActionProvider provider: the provider
        """

    def removePreferenceState(self, key: typing.Union[java.lang.String, str]):
        """
        Removes the Preferences state for the given key.
        
        :param java.lang.String or str key: the key to the preference state to be removed
        """

    def removePreferenceStateSupplier(self, key: typing.Union[java.lang.String, str]):
        """
        Removes the supplier of the preference state for the given key.
        
        :param java.lang.String or str key: the key with which to store the preferences.
        
        .. seealso::
        
            | :obj:`.registerPreferenceStateSupplier(String, Supplier)`
        """

    def removeStatusItem(self, c: javax.swing.JComponent):
        """
        Remove the specified status item.
        
        :param javax.swing.JComponent c: status component previously added.
        """

    def restoreFromXML(self, rootXMLElement: org.jdom.Element):
        """
        Restores the docking window managers state from the XML information.
        
        :param org.jdom.Element rootXMLElement: JDOM element from which to extract the state information.
        """

    def restorePreferencesFromXML(self, rootElement: org.jdom.Element):
        ...

    def restoreWindowDataFromXml(self, rootXMLElement: org.jdom.Element):
        """
        Restore to the docking window manager the layout and positioning information from XML.
        
        :param org.jdom.Element rootXMLElement: JDOM element from which to extract the state information.
        """

    def saveToXML(self, rootXMLElement: org.jdom.Element):
        """
        Generates a JDOM element object for saving the window managers state to XML.
        
        :param org.jdom.Element rootXMLElement: The root element to which to save XML data.
        """

    def saveWindowingDataToXml(self) -> org.jdom.Element:
        """
        Save this docking window manager's window layout and positioning information as XML.
        
        :return: An XML element with the above information.
        :rtype: org.jdom.Element
        """

    def setDefaultComponent(self, provider: ComponentProvider):
        """
        Sets the provider that should get the default focus when no component has focus.
        
        :param ComponentProvider provider: the provider that should get the default focus when no component has focus.
        """

    @staticmethod
    def setHelpLocation(c: javax.swing.JComponent, helpLocation: ghidra.util.HelpLocation):
        """
        Register a specific Help content URL for a component. The DocWinListener will be notified
        with the helpURL if the specified component 'c' has focus and the help key is pressed.
        
        :param javax.swing.JComponent c: component on which to set help.
        :param ghidra.util.HelpLocation helpLocation: help content location
        """

    def setHomeButton(self, icon: javax.swing.Icon, callback: java.lang.Runnable):
        """
        Sets the icon for this window's 'home button'. This button, when pressed, will show the
        tool's main application window.
        
        :param javax.swing.Icon icon: the button's icon
        :param java.lang.Runnable callback: the callback to execute when the button is pressed by the user
        """

    @typing.overload
    def setIcon(self, icon: javax.swing.ImageIcon):
        """
        Set the Icon for all windows.
        
        :param javax.swing.ImageIcon icon: image icon
        """

    @typing.overload
    def setIcon(self, provider: ComponentProvider, icon: javax.swing.Icon):
        ...

    def setMenuGroup(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str], menuSubGroup: typing.Union[java.lang.String, str]):
        """
        Set the menu group associated with a cascaded submenu. This allows a cascading menu item to
        be grouped with a specific set of actions.
         
        
        The default group for a cascaded submenu is the name of the submenu.
        
        :param jpype.JArray[java.lang.String] menuPath: menu name path where the last element corresponds to the specified group
                    name.
        :param java.lang.String or str group: group name
        :param java.lang.String or str menuSubGroup: the name used to sort the cascaded menu within other menu items at its
                    level
        """

    @staticmethod
    def setMouseOverAction(action: docking.action.DockingActionIf):
        ...

    @staticmethod
    def setMouseOverObject(object: java.lang.Object):
        ...

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        """
        Set the status text in the active component window
        
        :param java.lang.String or str text: status text
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Set the status text in the active component window
        
        :param java.lang.String or str text: string to be displayed in the Status display area
        :param jpype.JBoolean or bool beep: whether to beep or not
        """

    def setToolName(self, toolName: typing.Union[java.lang.String, str]):
        """
        Set the tool name which is displayed as the title for all windows.
        
        :param java.lang.String or str toolName: tool name / title
        """

    def setVisible(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the visible state of the set of docking windows.
        
        :param jpype.JBoolean or bool state: if true the main window and all sub-windows are set to be visible. If state is
                    false, then all windows are set to be invisible.
        """

    def setWindowsOnTop(self, windowsOnTop: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the mode such that all satellite docking windows always appear on top of the root window
        
        :param jpype.JBoolean or bool windowsOnTop: true to set mode to on top, false to disable on top mode.
        """

    def showComponent(self, provider: ComponentProvider, visibleState: typing.Union[jpype.JBoolean, bool]):
        """
        Hides or shows the component associated with the given provider.
         
        
         
        
        **Note: ** This method will not show the given provider if it has not previously been
        added via ``addComponent(...)``.
        
        :param ComponentProvider provider: the provider of the component to be hidden or shown.
        :param jpype.JBoolean or bool visibleState: true to show the component, false to hide it.
        
        .. seealso::
        
            | :obj:`.addComponent(ComponentProvider)`
        
            | :obj:`.addComponent(ComponentProvider, boolean)`
        """

    def showComponentHeader(self, provider: ComponentProvider, b: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether a component's header should be shown; the header is the component that is dragged
        in order to move the component within the tool, or out of the tool into a separate window.
        
        :param ComponentProvider provider: provider of the visible component in the tool
        :param jpype.JBoolean or bool b: true means to show the header
        """

    @staticmethod
    def showContextMenu(component: java.awt.Component):
        """
        Shows a popup menu over the given component. If this given component is not part of the
        docking windows hierarchy, then no action is taken.
        
        :param java.awt.Component component: the component
        """

    @staticmethod
    @typing.overload
    def showDialog(dialogComponent: DialogComponentProvider):
        """
        Shows the dialog using the tool's currently active window as a parent
        
        :param DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog
        """

    @typing.overload
    def showDialog(self, dialogComponent: DialogComponentProvider, centeredOnProvider: ComponentProvider):
        """
        Shows the dialog using the window containing the given componentProvider as its parent window
        
        :param DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        :param ComponentProvider centeredOnProvider: the component provider that is used to find a parent window for
                    this dialog. The dialog is centered on this component provider's component.
        """

    @staticmethod
    @typing.overload
    def showDialog(parent: java.awt.Component, dialogComponent: DialogComponentProvider):
        """
        Shows the dialog using the given parent component to find a parent window and to position the
        dialog. If a Window can be found containing the given component, it will be used as the
        parent window for the dialog. If the component is null or not contained in a window, the
        current active window manager will be used to parent the dialog. If there are no active
        tools, then a frame will be created to parent the dialog.
        
        :param java.awt.Component parent: the component whose window over which the given dialog will be shown; null
                    signals to use the active window
        :param DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        
        .. seealso::
        
            | :obj:`.getParentWindow(Component)`for parenting notes
        """

    @staticmethod
    @typing.overload
    def showDialog(parent: java.awt.Window, dialogComponent: DialogComponentProvider, centeredOnComponent: java.awt.Component):
        """
        Shows the dialog using the given parent window using the optional component for positioning.
        
         
        
        Warning: this method allows user to explicitly pass a parent window and component over which
        to be centered. There is no reason to use this method in the standard workflow. This method
        exists strictly to handle future unforeseen use cases. Use at your own risk of incorrectly
        parenting dialogs.
        
        :param java.awt.Window parent: the component whose window over which the given dialog will be shown; cannot be
                    null
        :param DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog
        :param java.awt.Component centeredOnComponent: the component over which the dialog will be centered; cannot be
                    null
        """

    @typing.overload
    def toFront(self, provider: ComponentProvider):
        ...

    @typing.overload
    def toFront(self, window: java.awt.Window):
        ...

    def unregisterDefaultContextProvider(self, type: java.lang.Class[ActionContext], provider: docking.action.ActionContextProvider):
        """
        Removes the default provider for the given ActionContext type.
        
        :param java.lang.Class[ActionContext] type: the subclass of ActionContext to remove a provider for
        :param docking.action.ActionContextProvider provider: the ActionContextProvider to remove for the given ActionContext type
        """

    def updateTitle(self, provider: ComponentProvider):
        ...

    @property
    def activeComponentProvider(self) -> ComponentProvider:
        ...

    @property
    def globalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def activeProvider(self) -> jpype.JBoolean:
        ...

    @property
    def subTitle(self) -> java.lang.String:
        ...

    @property
    def provider(self) -> ComponentProvider:
        ...

    @property
    def rootFrame(self) -> javax.swing.JFrame:
        ...

    @property
    def componentProvider(self) -> ComponentProvider:
        ...

    @property
    def activeComponent(self) -> java.awt.Component:
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @visible.setter
    def visible(self, value: jpype.JBoolean):
        ...

    @property
    def preferenceState(self) -> ghidra.framework.options.PreferenceState:
        ...

    @property
    def mainWindow(self) -> java.awt.Window:
        ...

    @property
    def defaultActionContext(self) -> ActionContext:
        ...

    @property
    def lastProviderInDetachedWindow(self) -> jpype.JBoolean:
        ...

    @property
    def focusedComponent(self) -> ComponentPlaceholder:
        ...

    @property
    def windows(self) -> java.util.List[java.awt.Window]:
        ...

    @property
    def windowsOnTop(self) -> jpype.JBoolean:
        ...

    @windowsOnTop.setter
    def windowsOnTop(self, value: jpype.JBoolean):
        ...

    @property
    def tool(self) -> Tool:
        ...

    @property
    def componentProviders(self) -> java.util.List[T]:
        ...

    @property
    def lastComponentInWindow(self) -> jpype.JBoolean:
        ...

    @property
    def statusText(self) -> java.lang.String:
        ...

    @statusText.setter
    def statusText(self, value: java.lang.String):
        ...

    @property
    def providerWindow(self) -> java.awt.Window:
        ...

    @property
    def componentActions(self) -> java.util.Iterator[docking.action.DockingActionIf]:
        ...

    @property
    def defaultActionContextMap(self) -> java.util.Map[java.lang.Class[ActionContext], ActionContext]:
        ...

    @property
    def activeWindow(self) -> java.awt.Window:
        ...


class DialogComponentProvider(docking.action.ActionContextProvider, ghidra.util.StatusListener, ghidra.util.task.TaskListener):
    """
    Base class used for creating dialogs in Ghidra. Subclass this to create a dialog provider that has
    all the gui elements to appear in the dialog, then use tool.showDialog() to display your dialog.
    """

    @typing.type_check_only
    class PopupHandler(docking.event.mouse.GMouseListenerAdapter, java.awt.event.ContainerListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DialogActionProxy(DockingActionProxy):
        """
        A placeholder action that we register with the tool in order to get key event management
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, provider: DialogComponentProvider, dockingAction: docking.action.DockingActionIf):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addAction(self, action: docking.action.DockingActionIf):
        """
        Add an action to this dialog.  Only actions with icons are added to the toolbar.
        Note, if you add an action to this dialog, do not also add the action to
        the tool, as this dialog will do that for you.
        
        :param docking.action.DockingActionIf action: the action
        """

    def clearStatusText(self):
        """
        Clears the text from the dialog's status line.
        """

    def close(self):
        ...

    @staticmethod
    def createSharedActions(tool: Tool, toolActions: docking.actions.ToolActions, owner: typing.Union[java.lang.String, str]):
        """
        Called by the framework during startup to register actions that are shared throughout the 
        tool.  See :obj:`SharedActionRegistry`.
        
        :param Tool tool: the tool
        :param docking.actions.ToolActions toolActions: the class to which the actions should be added
        :param java.lang.String or str owner: the shared action owner
        """

    def dispose(self):
        """
        Disposes this dialog.  Only call this when the dialog is no longer used.  Calling this method
        will close the dialog if it is open.
        """

    def getActionContext(self, event: java.awt.event.MouseEvent) -> ActionContext:
        """
        An optional extension point for subclasses to provider action context for the actions used by
        this provider.
        
        :param java.awt.event.MouseEvent event: The mouse event used (may be null) to generate a popup menu
        """

    def getActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    def getBackground(self) -> java.awt.Color:
        """
        Gets the background color of this component.
        
        :return: The background color of this component.
        :rtype: java.awt.Color
        """

    def getComponent(self) -> javax.swing.JComponent:
        ...

    def getDefaultButton(self) -> javax.swing.JButton:
        """
        Returns the default button for the dialog.
        
        :return: the button
        :rtype: javax.swing.JButton
        """

    def getDefaultSize(self) -> java.awt.Dimension:
        ...

    def getFocusComponent(self) -> java.awt.Component:
        """
        Returns the component that will receive focus when the dialog is shown
        
        :return: the component
        :rtype: java.awt.Component
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for this dialog
        
        :return: the help location
        :rtype: ghidra.util.HelpLocation
        """

    def getId(self) -> int:
        ...

    def getInitialLocation(self) -> java.awt.Point:
        """
        Returns the initial location for the dialog or null if none was set
        
        :return: the point
        :rtype: java.awt.Point
        """

    def getPreferredSize(self) -> java.awt.Dimension:
        """
        Returns the preferred size of this component.
        
        :return: the preferred size of this component.
        :rtype: java.awt.Dimension
        """

    def getRememberLocation(self) -> bool:
        """
        Returns true if this dialog remembers its location from one invocation to the next.
        
        :return: true if this dialog remembers its location from one invocation to the next.
        :rtype: bool
        """

    def getRememberSize(self) -> bool:
        """
        Returns true if this dialog remembers its size from one invocation to the next.
        
        :return: true if this dialog remembers its size from one invocation to the next.
        :rtype: bool
        """

    def getStatusText(self) -> str:
        """
        Returns the current status in the dialogs status line
        
        :return: the status text
        :rtype: str
        """

    def getTitle(self) -> str:
        """
        Returns the title for this component
        
        :return: the title
        :rtype: str
        """

    def getUseSharedLocation(self) -> bool:
        """
        Returns true if this dialog uses shared location and size information.
        
        :return: true if this dialog uses shared location and size information.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setUseSharedLocation(boolean)`
        """

    def hideTaskMonitorComponent(self):
        """
        Will hide the progress panel if it was showing.
        
        
        .. seealso::
        
            | :obj:`.showTaskMonitorComponent(String, boolean, boolean)`
        """

    def isDialogKeyBindingAction(self, action: docking.action.DockingActionIf) -> bool:
        """
        Returns true if the given action is one that has been registered by this dialog.
        
        :param docking.action.DockingActionIf action: the action
        :return: true if the given action is one that has been registered by this dialog
        :rtype: bool
        """

    def isModal(self) -> bool:
        """
        Returns true if this component should be displayed in a modal dialog
        
        :return: true if this component should be displayed in a modal dialog
        :rtype: bool
        """

    def isResizeable(self) -> bool:
        ...

    def isRunningTask(self) -> bool:
        """
        Returns true if this dialog is running a task.
        
        :return: true if this dialog is running a task.
        :rtype: bool
        """

    def isShowing(self) -> bool:
        ...

    def isTransient(self) -> bool:
        """
        Returns true if this dialog is intended to be shown and hidden relatively quickly.  This
        is used to determine if this dialog should be allowed to parent other components.   The
        default is false.
        
        :return: true if this dialog is transient
        :rtype: bool
        """

    def isVisible(self) -> bool:
        ...

    def removeAction(self, action: docking.action.DockingActionIf):
        ...

    def setAccessibleDescription(self, description: typing.Union[java.lang.String, str]):
        """
        Sets a description of the dialog that will be read by screen readers when the dialog
        is made visible.
        
        :param java.lang.String or str description: a description of the dialog
        """

    def setBackground(self, color: java.awt.Color):
        """
        Sets the background on this component.
        
        :param java.awt.Color color: The color to set.
        """

    def setCursor(self, cursor: java.awt.Cursor):
        """
        Sets the cursor on the root panel for the dialog component.
        
        :param java.awt.Cursor cursor: the cursor to use.
        """

    def setDefaultButton(self, button: javax.swing.JButton):
        """
        Sets the button to make "Default" when the dialog is shown.  If no default button is
        desired, then pass ``null`` as the ``button`` value.
        
        :param javax.swing.JButton button: the button to make default enabled.
        """

    def setDefaultSize(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    def setFocusComponent(self, focusComponent: java.awt.Component):
        """
        Sets the component that should be given focus when the dialog is activated.
         
        
        Implementation Note:  If the given component is a JButton, then that component will be
        made the default button.
        
        :param java.awt.Component focusComponent: the component that should receive default focus.
        
        .. seealso::
        
            | :obj:`.setFocusComponent(Component)`
        """

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation):
        """
        Set the help Location for this dialog.
        
        :param ghidra.util.HelpLocation helpLocation: the helpLocation for this dialog.
        """

    def setInitialLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        Sets the initial location for the dialog
        
        :param jpype.JInt or int x: the x coordinate
        :param jpype.JInt or int y: the y coordinate
        """

    @typing.overload
    def setMinimumSize(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setMinimumSize(self, minSize: java.awt.Dimension):
        """
        Sets the minimum size of the dialog
        
        :param java.awt.Dimension minSize: the min size of the dialog
        """

    def setPreferredSize(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Sets the preferred size of the dialog.  Note that if you set the preferred size, the
        dialog will ignore any natural preferred size of your components.
        
        :param jpype.JInt or int width: the preferred width
        :param jpype.JInt or int height: the preferred height;
        """

    def setRememberLocation(self, rememberLocation: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this dialog to remember its location from one invocation to the next. The default is to
        remember location.
        
        :param jpype.JBoolean or bool rememberLocation: true to remember, false otherwise.
        """

    def setRememberSize(self, rememberSize: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this dialog to remember its size from one invocation to the next. The default is to
        remember size.
        
        :param jpype.JBoolean or bool rememberSize: true to remember, false otherwise.
        """

    def setResizable(self, resizeable: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the resizable property for the corresponding dialog.
        
        :param jpype.JBoolean or bool resizeable: if false the user will not be able to resize the dialog.
        """

    def setStatusJustification(self, justification: typing.Union[jpype.JInt, int]):
        """
        Sets the horizontal position of the status label.
        
        :param jpype.JInt or int justification: One of the following constants
                defined in ``SwingConstants``:
                ``LEFT``,
                ``CENTER`` (the default for image-only labels),
                ``RIGHT``,
        """

    @typing.overload
    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        """
        Sets the text in the dialog's status line using the default color
        
        :param java.lang.String or str text: the text to display in the status line
        """

    @typing.overload
    def setStatusText(self, message: typing.Union[java.lang.String, str], type: ghidra.util.MessageType):
        """
        Sets the text in the dialog's status line using the specified message type to control
        the color.
        
        :param java.lang.String or str message: the message
        :param ghidra.util.MessageType type: the message type
        """

    def setTitle(self, title: typing.Union[java.lang.String, str]):
        """
        Sets the title to be displayed in the dialogs title bar
        
        :param java.lang.String or str title: the title
        """

    def setTransient(self, isTransient: typing.Union[jpype.JBoolean, bool]):
        """
        Sets this dialog to be transient (see :meth:`isTransient() <.isTransient>`
        
        :param jpype.JBoolean or bool isTransient: true for transient; false is the default
        """

    def setUseSharedLocation(self, useSharedLocation: typing.Union[jpype.JBoolean, bool]):
        """
        Specifies whether or not this dialog component should use the same remembered location (and
        size) no matter which window this dialog is launched from.  The default is not to use
        shared location and size, which means that there is a remembered location and size for this
        dialog for each window that has launched it (i.e. the window is the parent of the dialog).
        
        :param jpype.JBoolean or bool useSharedLocation: true to share locations
        """

    def showTaskMonitorComponent(self, localTitle: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool], canCancel: typing.Union[jpype.JBoolean, bool]) -> ghidra.util.task.TaskMonitor:
        """
        Shows the progress bar for this dialog.
        
        :param java.lang.String or str localTitle: the name of the task
        :param jpype.JBoolean or bool hasProgress: true if the progress bar should show progress; false to be indeterminate
        :param jpype.JBoolean or bool canCancel: true if the task can be cancelled
        :return: the :obj:`TaskMonitor` used by to communicate progress
        :rtype: ghidra.util.task.TaskMonitor
        
        .. seealso::
        
            | :obj:`.hideTaskMonitorComponent()`
        """

    def taskCancelled(self, task: ghidra.util.task.Task):
        """
        Notification that the task was canceled; the progress panel is
        removed.
        
        :param ghidra.util.task.Task task: task that was canceled
        """

    def taskCompleted(self, task: ghidra.util.task.Task):
        """
        Notification that the given task completed so that the progress
        panel can be removed.
        
        :param ghidra.util.task.Task task: task that completed
        """

    def toFront(self):
        """
        Moves the dialog associated with this provider to the front.
        """

    def waitForCurrentTask(self):
        """
        Blocks the calling thread until the current task has completed; used
        by JUnit tests.
        """

    @property
    def useSharedLocation(self) -> jpype.JBoolean:
        ...

    @useSharedLocation.setter
    def useSharedLocation(self, value: jpype.JBoolean):
        ...

    @property
    def defaultButton(self) -> javax.swing.JButton:
        ...

    @defaultButton.setter
    def defaultButton(self, value: javax.swing.JButton):
        ...

    @property
    def rememberSize(self) -> jpype.JBoolean:
        ...

    @rememberSize.setter
    def rememberSize(self, value: jpype.JBoolean):
        ...

    @property
    def title(self) -> java.lang.String:
        ...

    @title.setter
    def title(self, value: java.lang.String):
        ...

    @property
    def rememberLocation(self) -> jpype.JBoolean:
        ...

    @rememberLocation.setter
    def rememberLocation(self, value: jpype.JBoolean):
        ...

    @property
    def defaultSize(self) -> java.awt.Dimension:
        ...

    @property
    def preferredSize(self) -> java.awt.Dimension:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def modal(self) -> jpype.JBoolean:
        ...

    @property
    def focusComponent(self) -> java.awt.Component:
        ...

    @focusComponent.setter
    def focusComponent(self, value: java.awt.Component):
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def runningTask(self) -> jpype.JBoolean:
        ...

    @property
    def initialLocation(self) -> java.awt.Point:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @helpLocation.setter
    def helpLocation(self, value: ghidra.util.HelpLocation):
        ...

    @property
    def dialogKeyBindingAction(self) -> jpype.JBoolean:
        ...

    @property
    def actionContext(self) -> ActionContext:
        ...

    @property
    def component(self) -> javax.swing.JComponent:
        ...

    @property
    def transient(self) -> jpype.JBoolean:
        ...

    @transient.setter
    def transient(self, value: jpype.JBoolean):
        ...

    @property
    def background(self) -> java.awt.Color:
        ...

    @background.setter
    def background(self, value: java.awt.Color):
        ...

    @property
    def statusText(self) -> java.lang.String:
        ...

    @statusText.setter
    def statusText(self, value: java.lang.String):
        ...

    @property
    def resizeable(self) -> jpype.JBoolean:
        ...

    @property
    def showing(self) -> jpype.JBoolean:
        ...

    @property
    def actions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...


class DockingActionPerformer(java.lang.Object):
    """
    A simple class to handle executing the given action.  This class will generate the action context
    as needed and validate the context before executing the action.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def perform(action: docking.action.DockingActionIf, event: java.awt.event.ActionEvent):
        """
        Executes the given action later on the Swing thread.
        
        :param docking.action.DockingActionIf action: the action.
        :param java.awt.event.ActionEvent event: the event that triggered the action.
        """

    @staticmethod
    @typing.overload
    def perform(action: docking.action.DockingActionIf, event: java.awt.event.ActionEvent, windowManager: DockingWindowManager):
        """
        Executes the given action later on the Swing thread.
        
        :param docking.action.DockingActionIf action: the action.
        :param java.awt.event.ActionEvent event: the event that triggered the action.
        :param DockingWindowManager windowManager: the window manager containing the action being processed.
        """


class PopupMenuContext(java.lang.Object):
    """
    A class that holds information used to show a popup menu
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> java.awt.Component:
        ...

    def getEvent(self) -> java.awt.event.MouseEvent:
        ...

    def getPoint(self) -> java.awt.Point:
        ...

    def getSource(self) -> java.lang.Object:
        ...

    @property
    def component(self) -> java.awt.Component:
        ...

    @property
    def source(self) -> java.lang.Object:
        ...

    @property
    def event(self) -> java.awt.event.MouseEvent:
        ...

    @property
    def point(self) -> java.awt.Point:
        ...


class WindowNode(Node):

    class_: typing.ClassVar[java.lang.Class]

    def componentAdded(self, placeholder: ComponentPlaceholder):
        ...

    def componentRemoved(self, placeholder: ComponentPlaceholder):
        ...

    def getContextTypes(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...

    def getLastFocusedProviderInWindow(self) -> ComponentPlaceholder:
        ...

    def setLastFocusedProviderInWindow(self, lastFocusedInWindow: ComponentPlaceholder):
        ...

    @property
    def contextTypes(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...

    @property
    def lastFocusedProviderInWindow(self) -> ComponentPlaceholder:
        ...

    @lastFocusedProviderInWindow.setter
    def lastFocusedProviderInWindow(self, value: ComponentPlaceholder):
        ...


@typing.type_check_only
class ShowComponentAction(docking.action.DockingAction, docking.actions.AutoGeneratedDockingAction, java.lang.Comparable[ShowComponentAction]):
    """
    Action for showing components.  If the component is hidden it will be made visible.
    If it is tabbed, it will become the top tab. In all cases it will receive focus.
    """

    class_: typing.ClassVar[java.lang.Class]


class FocusOwnerProvider(java.lang.Object):
    """
    An interface to provided the current focus owner.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActiveWindow(self) -> java.awt.Window:
        """
        Returns the active window
        
        :return: the active window
        :rtype: java.awt.Window
        """

    def getFocusOwner(self) -> java.awt.Component:
        """
        Returns the current focus owner
        
        :return: the current focus owner
        :rtype: java.awt.Component
        """

    @property
    def focusOwner(self) -> java.awt.Component:
        ...

    @property
    def activeWindow(self) -> java.awt.Window:
        ...


class DockingCheckBoxMenuItem(javax.swing.JCheckBoxMenuItem):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, isSelected: typing.Union[jpype.JBoolean, bool]):
        ...


class ExecutableAction(java.lang.Object):
    """
    A class used by the :obj:`KeyBindingOverrideKeyEventDispatcher`.  It represents an action and 
    the context in which that action should operate if :meth:`execute() <.execute>` is called.   This class is
    created for each keystroke that maps to a tool action.
     
    
    This is not meant to be used outside of this API.
    """

    class_: typing.ClassVar[java.lang.Class]

    def execute(self):
        ...

    def getKeyBindingPrecedence(self) -> KeyBindingPrecedence:
        ...

    def isEnabled(self) -> bool:
        ...

    def isValid(self) -> bool:
        ...

    def reportNotEnabled(self, focusOwner: java.awt.Component):
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def keyBindingPrecedence(self) -> KeyBindingPrecedence:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...


class DockingMenuItem(javax.swing.JMenuItem, docking.widgets.GComponent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class KeyBindingPrecedence(java.lang.Enum[KeyBindingPrecedence]):
    """
    An enum that holds the values for order of keybinding precedence, in order from 
    highest priority to lowest.  For a more detailed description of how Ghidra processes
    key events see :meth:`KeyBindingOverrideKeyEventDispatcher.dispatchKeyEvent(KeyEvent) <KeyBindingOverrideKeyEventDispatcher.dispatchKeyEvent>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    SystemActionsLevel: typing.Final[KeyBindingPrecedence]
    """
    Actions at this level will be processed before all others, including Java components'.
    """

    KeyListenerLevel: typing.Final[KeyBindingPrecedence]
    """
    Actions with this precedence will be processed before key listener on Java components.
    """

    ActionMapLevel: typing.Final[KeyBindingPrecedence]
    """
    Actions with this precedence will be processed before actions on Java components.
    """

    DefaultLevel: typing.Final[KeyBindingPrecedence]
    """
    This level of precedence is the default level of precedence and gets processed after
    Java components' key listeners and actions.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> KeyBindingPrecedence:
        ...

    @staticmethod
    def values() -> jpype.JArray[KeyBindingPrecedence]:
        ...


class AbstractDockingTool(Tool):
    """
    A partial implementation of :obj:`Tool` that serves as a place to share common functionality
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getToolFrame(self) -> javax.swing.JFrame:
        ...

    def setMenuGroup(self, menuPath: jpype.JArray[java.lang.String], group: typing.Union[java.lang.String, str]):
        """
        Set the menu group associated with a cascaded submenu. This allows a cascading menu item to
        be grouped with a specific set of actions. The default group for a cascaded submenu is the
        name of the submenu.
        
        :param jpype.JArray[java.lang.String] menuPath: menu name path where the last element corresponds to the specified group
                    name.
        :param java.lang.String or str group: group name
        
        .. seealso::
        
            | :obj:`.setMenuGroup(String[], String, String)`
        """

    @property
    def toolFrame(self) -> javax.swing.JFrame:
        ...


class GlobalMenuAndToolBarManager(DockingWindowListener):
    """
    Class to manage all the global actions that show up on the main tool menubar or toolbar
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: DockingWindowManager, menuHandler: docking.menu.MenuHandler, menuGroupMap: docking.menu.MenuGroupMap):
        ...

    def addAction(self, action: docking.action.DockingActionIf):
        ...

    def contextChanged(self):
        ...

    def dispose(self):
        ...

    def getToolbarAction(self, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        ...

    def removeAction(self, action: docking.action.DockingActionIf):
        ...

    def update(self):
        ...

    @property
    def toolbarAction(self) -> docking.action.DockingActionIf:
        ...


class EditListener(java.lang.Object):
    """
    Provides notification when a text edit is completed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def editCompleted(self, newText: typing.Union[java.lang.String, str]):
        """
        Notifies the listener of the text entered by the user
        when a text edit is completed.
        
        :param java.lang.String or str newText:
        """


class DropDownMenuIcon(javax.swing.Icon):
    """
    Icon for a drop down menu button  (triangle pointing down)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, color: java.awt.Color):
        """
        Creates a drop down menu icon.
        
        :param java.awt.Color color: the color of the triangle
        """


@typing.type_check_only
class RootNode(WindowNode):
    """
    Root node for the nodes managing the component hierarchy.
    """

    @typing.type_check_only
    class SwingWindowWrapper(java.lang.Object):
        """
        Interface to wrap JDialog and JFrame so that they can be used by one handle
        """

        class_: typing.ClassVar[java.lang.Class]

        def getLastBounds(self) -> java.awt.Rectangle:
            """
            Returns the last non-maximized frame bounds
            
            :return: the bounds
            :rtype: java.awt.Rectangle
            """

        def setLastBounds(self, bounds: java.awt.Rectangle):
            """
            Stores the given bounds if they are not the maximized bounds
            
            :param java.awt.Rectangle bounds: the bounds
            """

        @property
        def lastBounds(self) -> java.awt.Rectangle:
            ...

        @lastBounds.setter
        def lastBounds(self, value: java.awt.Rectangle):
            ...


    @typing.type_check_only
    class JDialogWindowWrapper(RootNode.SwingWindowWrapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parentFrame: RootNode.SwingWindowWrapper, dialog: javax.swing.JDialog):
            ...


    @typing.type_check_only
    class JFrameWindowWrapper(RootNode.SwingWindowWrapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, wrappedFrame: javax.swing.JFrame):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addDockingWindowListener(self, listener: DockingWindowListener):
        ...

    def addStatusItem(self, c: javax.swing.JComponent, addBorder: typing.Union[jpype.JBoolean, bool], rightSide: typing.Union[jpype.JBoolean, bool]):
        ...

    def clearStatusMessages(self):
        ...

    def getFrame(self) -> javax.swing.JFrame:
        ...

    def getMainWindow(self) -> java.awt.Window:
        ...

    def getNodeForWindow(self, win: java.awt.Window) -> WindowNode:
        ...

    def getStatusText(self) -> str:
        ...

    def removeDockingWindowListener(self, listener: DockingWindowListener):
        ...

    def removeStatusItem(self, c: javax.swing.JComponent):
        ...

    def setStatusText(self, text: typing.Union[java.lang.String, str]):
        ...

    @property
    def nodeForWindow(self) -> WindowNode:
        ...

    @property
    def mainWindow(self) -> java.awt.Window:
        ...

    @property
    def statusText(self) -> java.lang.String:
        ...

    @statusText.setter
    def statusText(self, value: java.lang.String):
        ...

    @property
    def frame(self) -> javax.swing.JFrame:
        ...


@typing.type_check_only
class SplitNode(Node):
    """
    Node for managing a JSplitPane view of two component trees.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DockingWindowsContextSensitiveHelpListener(java.lang.Object):
    """
    A listener class that allows the DockingWindowsManager to be updated as the user mouses 
    over components.
    """

    class_: typing.ClassVar[java.lang.Class]


class KbEnabledState(java.lang.Record):
    """
    A class to track an action's precedence and enablement
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, precedence: KeyBindingPrecedence, isValid: typing.Union[jpype.JBoolean, bool], isEnabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isEnabled(self) -> bool:
        ...

    def isValid(self) -> bool:
        ...

    def precedence(self) -> KeyBindingPrecedence:
        ...

    def toString(self) -> str:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...


class HiddenDockingFrame(DockingFrame):
    """
    Hack to fix:
     
    1. JFrames cannot be invisible
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...


class DropTargetHandler(java.lang.Object):
    """
    A basic interface for holding onto drop handlers
    """

    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...


class DockingContextListener(java.lang.Object):
    """
    A listener to be notified when the tool's context changes.   Normally context is used to 
    manage :obj:`DockingActionIf` enablement directly by the system.  This class allows 
    clients to listen to context change as well.
    """

    class_: typing.ClassVar[java.lang.Class]

    def contextChanged(self, context: ActionContext):
        """
        Called when the context changes
        
        :param ActionContext context: the context
        """


@typing.type_check_only
class ComponentNode(Node):
    """
    Node object for managing one or more components. If more that one managed component
    is active, then this node will create a tabbedPane object to contain the active components.
    """

    @typing.type_check_only
    class RenameMouseListener(java.awt.event.MouseAdapter):

        @typing.type_check_only
        class RenameActionListener(java.awt.event.ActionListener):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def iconChanged(self, placeholder: ComponentPlaceholder):
        ...

    def makeSelectedTab(self, placeholder: ComponentPlaceholder):
        """
        Makes the component the selected tab.
        
        :param ComponentPlaceholder placeholder: the component placeholder object of the component to be shown in the active tab.
        """


class ComponentProviderActivationListener(java.lang.Object):
    """
    An interface that enables callback when a :obj:`ComponentProvider` becomes activated or
    deactivated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def componentProviderActivated(self, componentProvider: ComponentProvider):
        """
        Called when the given component provider is activated.
        
        :param ComponentProvider componentProvider: The activated component provider.
        """

    def componentProviderDeactivated(self, componentProvider: ComponentProvider):
        """
        Called when the given component provider is deactivated.
        
        :param ComponentProvider componentProvider: The deactivated component provider.
        """


class MouseEntryTextField(docking.widgets.textfield.HintTextField):

    @typing.type_check_only
    class MyMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyKeyListener(java.awt.event.KeyListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], listener: java.util.function.Consumer[gui.event.MouseBinding]):
        ...

    def clearField(self):
        ...

    def getMouseBinding(self) -> gui.event.MouseBinding:
        ...

    def setDisabledHint(self, disabledHint: typing.Union[java.lang.String, str]):
        """
        Sets the hint text that will be displayed when this field is disabled
        
        :param java.lang.String or str disabledHint: the hint text
        """

    def setMouseBinding(self, mb: gui.event.MouseBinding):
        ...

    @property
    def mouseBinding(self) -> gui.event.MouseBinding:
        ...

    @mouseBinding.setter
    def mouseBinding(self, value: gui.event.MouseBinding):
        ...


class DockingWindowManagerTestUtils(java.lang.Object):
    """
    This class mainly serves as a conduit through which testing code can access some of the 
    non-public internals of :obj:`DockingWindowManager`, without opening up its interface to the
    public **and** without using reflective magic.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getActiveProviders(dwm: DockingWindowManager) -> java.util.Set[ComponentProvider]:
        ...

    @staticmethod
    def getDockableComponent(dwm: DockingWindowManager, provider: ComponentProvider) -> DockableComponent:
        ...

    @staticmethod
    def moveProvider(dwm: DockingWindowManager, movee: ComponentProvider, relativeTo: ComponentProvider, position: WindowPosition):
        ...

    @staticmethod
    def moveProviderToWindow(dwm: DockingWindowManager, provider: ComponentProvider) -> java.awt.Window:
        """
        Moves the given provider to its own window, at its current location.
        
        :param ComponentProvider provider: the provider to move
        :return: the provider's window
        :rtype: java.awt.Window
        """


class PopupActionManager(java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, windowManager: DockingWindowManager, menuGroupMap: docking.menu.MenuGroupMap):
        ...

    def addAction(self, action: docking.action.DockingActionIf):
        ...

    def dispose(self):
        ...

    def removeAction(self, action: docking.action.DockingActionIf):
        ...


class DockingDialog(javax.swing.JDialog, help.HelpDescriptor):

    @typing.type_check_only
    class BoundsInfo(java.lang.Object):
        """
        A simple container object to store multiple values in a map
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def containsProvider(self, dcp: DialogComponentProvider) -> bool:
        """
        Returns true if the given provider is the provider owned by this dialog.
        
        :param DialogComponentProvider dcp: the provider to check
        :return: true if the given provider is the provider owned by this dialog
        :rtype: bool
        """

    @staticmethod
    def createDialog(parent: java.awt.Window, comp: DialogComponentProvider, centeredOnComponent: java.awt.Component) -> DockingDialog:
        ...

    def getDialogComponent(self) -> DialogComponentProvider:
        ...

    def getOwningWindowManager(self) -> DockingWindowManager:
        ...

    def setCenteredOnComponent(self, c: java.awt.Component):
        """
        Centers the dialog on the given component.
        
        :param java.awt.Component c: the component to center over.
        """

    @property
    def owningWindowManager(self) -> DockingWindowManager:
        ...

    @property
    def dialogComponent(self) -> DialogComponentProvider:
        ...


class DockableComponent(javax.swing.JPanel, java.awt.event.ContainerListener):
    """
    Wrapper class for user components. Adds the title, local toolbar and provides the drag target
    functionality.
    """

    @typing.type_check_only
    class DockableComponentDropTarget(java.awt.dnd.DropTarget):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    DROP_CODE: typing.ClassVar[DropCode]
    TARGET_INFO: typing.ClassVar[ComponentPlaceholder]
    DRAGGED_OVER_INFO: typing.ClassVar[ComponentPlaceholder]
    SOURCE_INFO: typing.ClassVar[ComponentPlaceholder]
    DROP_CODE_SET: typing.ClassVar[jpype.JBoolean]

    def getComponentProvider(self) -> ComponentProvider:
        """
        Returns the component provider attached to this dockable component; null if this object
        has been disposed
        
        :return: the provider
        :rtype: ComponentProvider
        """

    def getComponentWindowingPlaceholder(self) -> ComponentPlaceholder:
        """
        Returns the placeholder object associated with this DockableComponent
        
        :return: the placeholder object associated with this DockableComponent
        :rtype: ComponentPlaceholder
        """

    def getDockingWindowManager(self) -> DockingWindowManager:
        """
        Returns the docking window manager that owns this component
        
        :return: the manager
        :rtype: DockingWindowManager
        """

    def getHeader(self) -> DockableHeader:
        ...

    def installDragDropTarget(self, component: java.awt.Component):
        ...

    @property
    def dockingWindowManager(self) -> DockingWindowManager:
        ...

    @property
    def componentWindowingPlaceholder(self) -> ComponentPlaceholder:
        ...

    @property
    def header(self) -> DockableHeader:
        ...

    @property
    def componentProvider(self) -> ComponentProvider:
        ...


class DockingUtils(java.lang.Object):
    """
    
    ***********************************
    Notes about how to use HTML safely:
    ***********************************
    
    Java's built-in HTML rendering in UI components is very useful, but can also introduce security
    issues when a hostile actor is providing the text strings that are being rendered.
     
    
    Before using a native Java UI component, search for a corresponding 'G'hidra component, and
    if possible choose the non-HTML version of that component (if available).
     
    
    For instance, instead of using :obj:`JLabel`, use either :obj:`GLabel` or :obj:`GHtmlLabel`
    (and their variants).
     
    
    (native JLabel, JCheckbox, etc, usage is actually disallowed in the Ghidra project)
     
    
    When using a UI component that is HTML enabled, care must be used when constructing the text
    that is being rendered.
     
    
    During string-building or concatenation, appending a non-literal string value (ie.
    ``"Hello " + getFoo();`` ), the non-literal string value should be escaped using
    :meth:`HTMLUtilities.escapeHTML(String) <HTMLUtilities.escapeHTML>` (ie. ``"Hello " + HTMLUtilities.escapeHTML(getFoo());``.
     
    
    Of course, there are exceptions to every rule, and if the string value can be definitely be
    traced to its source and there are no user-supplied origins, the HTML escaping can be skipped.
     
    
    Note: just using a UI component that is HTML enabled does not mean that it will treat its
    text as HTML text.  If you need to HTML escape any values that are being fed to the component, you
    need to force the HTML mode 'on' by pre-pending a "<HTML>" at the beginning of the string.
    If you fail to do this, the escaped substrings will look wrong because any '<' and '>' chars
    (and others) in the substring will be mangled when rendered in plain-text mode.
     
    
    When working with plain text, try to avoid allowing a user supplied string being the first
    value of text that could be fed to a UI component.  This will prevent the possibly hostile
    string from having a leading HTML start tag.
    (ie. when displaying an error to the user about a bad file, don't put the filename
    value at the start of the string, but instead put a quote or some other delimiter to prevent
    html mode).
     
     
    =================================
    Recommended Ghidra UI Components:
    =================================
    
     
     
    +--------------------------------+---------------------------+
    |        Native Component        |   Recommended Component   |
    +================================+===========================+
    |:obj:`JLabel`                   |:obj:`GLabel`              |
    |                                |:obj:`GDLabel`             |
    |                                |:obj:`GHtmlLabel`          |
    |                                |:obj:`GDHtmlLabel`         |
    |                                |:obj:`GIconLabel`          |
    +--------------------------------+---------------------------+
    |:obj:`JCheckBox`                |:obj:`GCheckBox`           |
    |                                |:obj:`GHtmlCheckBox`       |
    +--------------------------------+---------------------------+
    |:obj:`JComboBox`                |:obj:`GComboBox`           |
    |                                |:obj:`GhidraComboBox`      |
    +--------------------------------+---------------------------+
    |:obj:`JList`                    |:obj:`GList`               |
    +--------------------------------+---------------------------+
    |:obj:`ListCellRenderer`         |:obj:`GListCellRenderer`   |
    |:obj:`DefaultListCellRenderer`  |                           |
    +--------------------------------+---------------------------+
    |:obj:`TableCellRenderer`        |:obj:`GTableCellRenderer`  |
    +--------------------------------+---------------------------+
    |:obj:`TreeCellRenderer`         |:obj:`GTreeRenderer`       |
    |:obj:`DefaultTreeCellRenderer`  |``DnDTreeCellRenderer``    |
    +--------------------------------+---------------------------+
    |:obj:`JRadioButton`             |:obj:`GRadioButton`        |
    +--------------------------------+---------------------------+
    |:obj:`JButton`                  |???tbd???                  |
    +--------------------------------+---------------------------+
    """

    class ComponentCallback(java.lang.Object, typing.Generic[T]):
        """
        A callback to operate on a component
        
        
        .. seealso::
        
            | :obj:`DockingUtils.forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)`
        """

        class_: typing.ClassVar[java.lang.Class]

        def call(self, component: T) -> DockingUtils.TreeTraversalResult:
            ...


    class TreeTraversalOrder(java.lang.Enum[DockingUtils.TreeTraversalOrder]):
        """
        Specifies the order of component traversal
        
        
        .. seealso::
        
            | :obj:`DockingUtils.forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)`
        """

        class_: typing.ClassVar[java.lang.Class]
        CHILDREN_FIRST: typing.Final[DockingUtils.TreeTraversalOrder]
        PARENT_FIRST: typing.Final[DockingUtils.TreeTraversalOrder]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DockingUtils.TreeTraversalOrder:
            ...

        @staticmethod
        def values() -> jpype.JArray[DockingUtils.TreeTraversalOrder]:
            ...


    class TreeTraversalResult(java.lang.Enum[DockingUtils.TreeTraversalResult]):
        """
        Controls traversal and communicates cause for termination
        
        
        .. seealso::
        
            | :obj:`DockingUtils.forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)`
        """

        class_: typing.ClassVar[java.lang.Class]
        CONTINUE: typing.Final[DockingUtils.TreeTraversalResult]
        FINISH: typing.Final[DockingUtils.TreeTraversalResult]
        TERMINATE: typing.Final[DockingUtils.TreeTraversalResult]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DockingUtils.TreeTraversalResult:
            ...

        @staticmethod
        def values() -> jpype.JArray[DockingUtils.TreeTraversalResult]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    CONTROL_KEY_MODIFIER_MASK: typing.Final[jpype.JInt]
    """
    System dependent mask for the Ctrl key
    """

    CONTROL_KEY_MODIFIER_MASK_DEPRECATED: typing.Final[jpype.JInt]
    """
    A version the control key modifiers that is based upon the pre-Java 9 :obj:`InputEvent`
    usage.  This mask is here for those clients that cannot be upgraded, such as those with
    dependencies on 3rd-party libraries that still use the old mask style.
    
    
    .. deprecated::
    
    use instead :obj:`.CONTROL_KEY_MODIFIER_MASK`
    """

    CONTROL_KEY_NAME: typing.Final[java.lang.String]

    def __init__(self):
        ...

    @staticmethod
    def createToolbarSeparator() -> javax.swing.JSeparator:
        ...

    @staticmethod
    @typing.overload
    def forAllDescendants(start: java.awt.Container, type: java.lang.Class[T], order: DockingUtils.TreeTraversalOrder, cb: DockingUtils.ComponentCallback[T]) -> DockingUtils.TreeTraversalResult:
        """
        Perform some operation on a component and all of its descendants, recursively
        
        This traverses the swing/awt component tree starting at the given container and descends
        recursively through all containers. Any time a component of type (or subclass of type) is
        found, the given callback is executed on it. If order is
        :obj:`TreeTraversalOrder.CHILDREN_FIRST`, then the traversal will execute the callback on
        the children of a container before executing the callback on the container itself; if
        :obj:`TreeTraversalOrder.PARENT_FIRST`, then the traversal will execute the callback on the
        container before descending.
        
        The callback must return one of three result values. In normal circumstances, it should
        return :obj:`TreeTraversalResult.CONTINUE`, allowing traversal to continue to the next
        element. If the callback wishes to terminate traversal "successfully," e.g., because it
        needed to locate the first element satisfying some predicate, then it should return
        :obj:`TreeTraversalResult.FINISH`. If an error occurs during traversal, then it should
        either return :obj:`TreeTraversalResult.TERMINATE` or throw an appropriate exception to
        terminate traversal "unsuccessfully."
        
        This method will also return a value of :obj:`TreeTraversalResult` indicating how traversal
        terminated. If :obj:`TreeTraversalResult.CONTINUE`, then every element in the subtree was
        visited, and traversal was successful. If :obj:`TreeTraversalResult.FINISH`, then some
        elements may have been omitted, but traversal was still successful. If
        :obj:`TreeTraversalResult.TERMINATE`, then some elements may have been omitted, and
        traversal was not successful.
        
        :param java.awt.Container start: the "root" container of the subtree on which to operate
        :param java.lang.Class[T] type: the type of components on which to operate
        :param DockingUtils.TreeTraversalOrder order: whether to operation on children or parents first
        :param DockingUtils.ComponentCallback[T] cb: the callback to perform the actual operation
        :return: a result indicating whether or not traversal completed successfully
        :rtype: DockingUtils.TreeTraversalResult
        """

    @staticmethod
    @typing.overload
    def forAllDescendants(start: java.awt.Container, cb: DockingUtils.ComponentCallback[java.awt.Component]) -> DockingUtils.TreeTraversalResult:
        """
        Perform some operation on a component and all of its descendants, recursively.
        
        This applies the operation to all components in the tree, children first.
        
        :param java.awt.Container start: the "root" container of the subtree on which to operate
        :param DockingUtils.ComponentCallback[java.awt.Component] cb: the callback to perform the actual operation
        :return: a result indicating whether or not traversal completed successfully
        :rtype: DockingUtils.TreeTraversalResult
        
        .. seealso::
        
            | :obj:`DockingUtils.forAllDescendants(Container, Class, TreeTraversalOrder, ComponentCallback)`
        """

    @staticmethod
    def hideTipWindow():
        """
        Hides any open tooltip window
        """

    @staticmethod
    def installUndoRedo(textComponent: javax.swing.text.JTextComponent) -> UndoRedoKeeper:
        """
        Installs key binding support for undo/redo operations on the given text component.
        
         
        Note: the edits are tracked by adding a listener to the document of the given text
        component.  If that document is changed,  then undo/redo will stop working.
        
        :param javax.swing.text.JTextComponent textComponent: the text component
        :return: the object that allows the client to track the undo/redo state
        :rtype: UndoRedoKeeper
        """

    @staticmethod
    @typing.overload
    def isControlModifier(mouseEvent: java.awt.event.MouseEvent) -> bool:
        """
        Checks if the mouseEvent has the "control" key down.  On windows, this is actually
        the ``control`` key.  On Mac, it is the ``command`` key.
        
        :param java.awt.event.MouseEvent mouseEvent: the event to check
        :return: true if the control key is pressed
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isControlModifier(keyEvent: java.awt.event.KeyEvent) -> bool:
        """
        Checks if the mouseEvent has the "control" key down.  On windows, this is actually
        the ``control`` key.  On Mac, it is the ``command`` key.
        
        :param java.awt.event.KeyEvent keyEvent: the event to check
        :return: true if the control key is pressed
        :rtype: bool
        """

    @staticmethod
    def isTipWindowEnabled() -> bool:
        """
        Returns true if application-wide Java tooltips are enabled.
        
        :return: true if application-wide Java tooltips are enabled.
        :rtype: bool
        """

    @staticmethod
    def scaleIconAsNeeded(icon: javax.swing.Icon) -> javax.swing.Icon:
        ...

    @staticmethod
    def setTipWindowEnabled(enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the application-wide Java tooltip enablement.
        
        :param jpype.JBoolean or bool enabled: true if enabled; false prevents all Java tooltips
        """

    @staticmethod
    def setTransparent(c: javax.swing.JComponent):
        """
        Sets the given component to transparent, which allows the parent component's background
        to be painted.
         
        
        Notes
        Historically, to make a component transparent you would call
        :meth:`JComponent.setOpaque(boolean) <JComponent.setOpaque>` with a ``false`` value.  However, it turns out
        that the definition and the implementation of this method are at odds.  ``setOpaque(false)``
        is meant to signal that some part of the component is transparent, so the parent component
        needs to be painted.  Most LaFs implemented this by not painting the background of the
        component, but used the parent's color instead.  The Nimbus LaF actually honors the
        contract of ``setOpaque()``, which has the effect of painting the components
        background by default.
         
        
        This method allows components to achieve transparency when they used to
        rely on ``setOpaque(false)``.
        
        :param javax.swing.JComponent c: the component to be made transparent
        """


class DockingActionProxy(docking.action.ToggleDockingActionIf, docking.action.MultiActionDockingActionIf, java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dockingAction: docking.action.DockingActionIf):
        ...

    def getAction(self) -> docking.action.DockingActionIf:
        ...

    def getProxyAction(self) -> docking.action.DockingActionIf:
        ...

    @property
    def proxyAction(self) -> docking.action.DockingActionIf:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...


class ErrorReporter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def report(self, parent: java.awt.Component, title: typing.Union[java.lang.String, str], details: typing.Union[java.lang.String, str]):
        ...


class DropTargetFactory(java.lang.Object):
    """
    A factory for installing drop handlers onto components.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createDropTargetHandler(self, component: java.awt.Component) -> DropTargetHandler:
        """
        Creates a drop handler for a given component.
         
        
        The drop handler is returned so that clients may dispose of the handler when they are 
        done using it.  This is recommended in order to cleanup resources.
        
        :param java.awt.Component component: The component onto which a drop handler should be installed.
        :return: The new drop handler.
        :rtype: DropTargetHandler
        """


class DockingActionInputBindingListener(java.lang.Object):
    """
    A simple listener interface to notify clients of changes to key strokes and mouse bindings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def keyStrokeChanged(self, ks: javax.swing.KeyStroke):
        """
        Called when the key stroke is changed.
        
        :param javax.swing.KeyStroke ks: the key stroke.
        """

    def mouseBindingChanged(self, mb: gui.event.MouseBinding):
        """
        Called when the mouse binding is changed.
        
        :param gui.event.MouseBinding mb: the mouse binding.
        """


class ShowAllComponentsAction(ShowComponentAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, winMgr: DockingWindowManager, infoList: java.util.List[ComponentPlaceholder], subMenuName: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class PlaceholderManager(java.lang.Object):
    """
    Managers :obj:`ComponentPlaceholder`s.  This includes creating them, saving placeholders
    for later reuse and disposal.
    """

    class_: typing.ClassVar[java.lang.Class]


class DialogActionContext(DefaultActionContext):
    """
    Action context for :obj:`DialogComponentProvider`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dialogProvider: DialogComponentProvider, sourceComponent: java.awt.Component):
        ...

    @typing.overload
    def __init__(self, contextObject: java.lang.Object, sourceComponent: java.awt.Component):
        ...

    def getDialogComponentProvider(self) -> DialogComponentProvider:
        ...

    def setDialogComponentProvider(self, dialogProvider: DialogComponentProvider):
        ...

    @property
    def dialogComponentProvider(self) -> DialogComponentProvider:
        ...

    @dialogComponentProvider.setter
    def dialogComponentProvider(self, value: DialogComponentProvider):
        ...


class HeaderCursor(java.lang.Object):
    """
    The cursor values used when drag-n-dropping dockable components
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ErrLogDialog(AbstractErrDialog):
    """
    A dialog that takes error text and displays it with an option details button.  If there is
    an :obj:`ErrorReporter`, then a button is provided to report the error.
    """

    @typing.type_check_only
    class ErrorDetailsSplitPane(javax.swing.JSplitPane):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ErrorDetailsTablePanel(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ErrorDetailsPanel(javax.swing.JPanel):
        """
        scrolled text panel used to display the error message details;
        each time an error message is "added", appends the contents to
        the internal StringBuffer.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ErrorEntry(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ErrEntryTableModel(docking.widgets.table.GDynamicColumnTableModel[ErrLogDialog.ErrorEntry, java.lang.Object]):

        @typing.type_check_only
        class IdColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ErrLogDialog.ErrorEntry, java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class MessageColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ErrLogDialog.ErrorEntry, java.lang.String]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class DetailsColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ErrLogDialog.ErrorEntry, java.lang.String]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class TimestampColumn(docking.widgets.table.AbstractDynamicTableColumnStub[ErrLogDialog.ErrorEntry, java.util.Date]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class MaxWidthHtmlLabel(docking.widgets.label.GHtmlLabel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createExceptionDialog(title: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str], t: java.lang.Throwable) -> ErrLogDialog:
        ...

    @staticmethod
    def getErrorReporter() -> ErrorReporter:
        ...

    @staticmethod
    def setErrorReporter(errorReporter: ErrorReporter):
        ...


class ComponentPlaceholder(java.lang.Object):
    """
    Class to hold information about a dockable component with respect to its position within the
    windowing system.  It also holds identification information about the provider so that its
    location can be reused when the provider is re-opened.
     
    
    The placeholder will be used to link previously saved position information.  The tool will
    initially construct plugins and their component providers with default position information.
    Then, any existing xml data will be restored, which may have provider position information.
    The restoring of the xml will create placeholders with this saved information.  Finally, the
    restored placeholders will be linked with existing component providers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> DockableComponent:
        """
        Returns a Dockable component that wraps the component for this placeholder
        
        :return: the component
        :rtype: DockableComponent
        """

    def getFullTitle(self) -> str:
        """
        Returns the full title for this component (title + subtitle)
        
        :return: the full title for this component (title + subtitle)
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the name of this component.
        
        :return: the name of this component.
        :rtype: str
        """

    def getProvider(self) -> ComponentProvider:
        """
        Returns the component provider for this placeholder.
        
        :return: the component provider for this placeholder.
        :rtype: ComponentProvider
        """

    def getSubTitle(self) -> str:
        """
        Returns the subtitle for the component
        
        :return: the subtitle for the component
        :rtype: str
        """

    def getTabText(self) -> str:
        """
        The text for display on the tab of a tabbed component.
        
        :return: The text for display on the tab of a tabbed component.
        :rtype: str
        """

    def getTitle(self) -> str:
        """
        Returns the title for this component
        
        :return: the title for this component
        :rtype: str
        """

    def isDisposed(self) -> bool:
        ...

    def update(self):
        ...

    @property
    def fullTitle(self) -> java.lang.String:
        ...

    @property
    def component(self) -> DockableComponent:
        ...

    @property
    def subTitle(self) -> java.lang.String:
        ...

    @property
    def provider(self) -> ComponentProvider:
        ...

    @property
    def tabText(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def title(self) -> java.lang.String:
        ...


class DefaultActionContext(ActionContext):
    """
    The default implementation of ActionContext
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor with no provider, context object, or source component
        """

    @typing.overload
    def __init__(self, provider: ComponentProvider):
        """
        Constructor with no source component and no context object
        
        :param ComponentProvider provider: the ComponentProvider that generated this context.
        """

    @typing.overload
    def __init__(self, provider: ComponentProvider, sourceComponent: java.awt.Component):
        """
        Constructor for ActionContext with context object and sourceComponent being the same
        
        :param ComponentProvider provider: the ComponentProvider that generated this context.
        :param java.awt.Component sourceComponent: an optional source object; this is intended to be the component that
                is the source of the context, usually the focused component
        """

    @typing.overload
    def __init__(self, provider: ComponentProvider, contextObject: java.lang.Object, sourceComponent: java.awt.Component):
        """
        Constructor
        
        :param ComponentProvider provider: the ComponentProvider that generated this context.
        :param java.lang.Object contextObject: an optional contextObject that the ComponentProvider can provide; this 
                can be anything that actions wish to later retrieve
        :param java.awt.Component sourceComponent: an optional source object; this is intended to be the component that
                is the source of the context, usually the focused component
        """


@typing.type_check_only
class PlaceholderSet(java.lang.Object):
    """
    A class that tracks:
     
    * placeholders that are being used for a given provider
    * placeholders that are no longer being used, which are available for reuse
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class Node(java.lang.Object):
    """
    Base class for the various node objects used to build the component hierarchy.
    """

    class_: typing.ClassVar[java.lang.Class]


class DockingFrame(javax.swing.JFrame):
    """
    Base frame used by the root window and detached windows
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def isTransient(self) -> bool:
        """
        REturns whether this frame is transient.  A transient frame is one that is show temporarily.
        
        :return: true if transient
        :rtype: bool
        """

    def setTransient(self):
        """
        Marks this frame as transient.  A transient frame is one that is show temporarily.
        """

    @property
    def transient(self) -> jpype.JBoolean:
        ...


class GenericHeader(javax.swing.JPanel):

    class TitleFlasher(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setColor(self, updatedColor: java.awt.Color):
            ...


    @typing.type_check_only
    class TitlePanel(javax.swing.JPanel):
        """
        Overridden pane to draw a title using a gradient colored background
        """

        @typing.type_check_only
        class PopupMouseListener(java.awt.event.MouseAdapter):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, nonFocusColor: java.awt.Color, focusColor: java.awt.Color):
        ...

    def actionAdded(self, action: docking.action.DockingActionIf):
        """
        updates the toolbar to include the new action.
        
        :param docking.action.DockingActionIf action: the action that was added.
        """

    def actionRemoved(self, action: docking.action.DockingActionIf):
        """
        updates the toolbar to remove the given action.
        
        :param docking.action.DockingActionIf action: the action that was removed.
        """

    def dispose(self):
        ...

    def getAction(self, name: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        ...

    def getToolBarWidth(self) -> int:
        ...

    def isSelected(self) -> bool:
        ...

    def setColor(self, color: java.awt.Color):
        ...

    def setComponent(self, component: java.awt.Component):
        ...

    def setIcon(self, icon: javax.swing.Icon):
        ...

    def setNoWrapToolbar(self, noWrap: typing.Union[jpype.JBoolean, bool]):
        """
        Signals whether or not to break the toolbar actions into multiple rows.  The default is
        to wrap as necessary.
        
        :param jpype.JBoolean or bool noWrap: true signals not to break the actions into multiple rows
        """

    def setSelected(self, hasFocus: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the focus state of the component so that a visual clue can be displayed.
        
        :param jpype.JBoolean or bool hasFocus: true if the this component has focus, false otherwise.
        """

    def setTitle(self, title: typing.Union[java.lang.String, str]):
        ...

    def update(self):
        ...

    @property
    def toolBarWidth(self) -> jpype.JInt:
        ...

    @property
    def action(self) -> docking.action.DockingActionIf:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...


@typing.type_check_only
class DockableToolBarManager(java.lang.Object):
    """
    Manages to toolbar for the dockable components.
    """

    @typing.type_check_only
    class ToolBarCloseAction(docking.action.DockingAction):
        """
        Action added to toolbar for "hiding" the component.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToolBarMenuAction(docking.action.DockingAction):
        """
        Actions added to toolbar for displaying the drop-down menu.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class KeyEntryPanel(javax.swing.JPanel):
    """
    A panel that holds a :obj:`KeyEntryTextField` and a button for clearing the current key binding.
     
    
    This class is a drop-in replacement for clients that are currently using 
    :obj:`KeyEntryTextField`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, columns: typing.Union[jpype.JInt, int], listener: KeyEntryListener):
        """
        Constructs this class with a text field based on the number of given columns.
        
        :param jpype.JInt or int columns: the number of columns for the text field
        :param KeyEntryListener listener: the listener to be called as the user enters key strokes
        """

    def clearField(self):
        """
        Clears the key stroke being used by this panel
        """

    def getKeyStroke(self) -> javax.swing.KeyStroke:
        """
        Gets the key stroke being used by this panel
        
        :return: the key stroke
        :rtype: javax.swing.KeyStroke
        """

    def getTextField(self) -> javax.swing.JTextField:
        """
        Returns the text field used by this class
        
        :return: the text field
        :rtype: javax.swing.JTextField
        """

    def setDisabledHint(self, disabledHint: typing.Union[java.lang.String, str]):
        """
        Sets the text field hint for this panel.
        
        :param java.lang.String or str disabledHint: the hint
        
        .. seealso::
        
            | :obj:`KeyEntryTextField.setDisabledHint(String)`
        """

    def setKeyStroke(self, ks: javax.swing.KeyStroke):
        """
        Sets the key stroke on this panel
        
        :param javax.swing.KeyStroke ks: the key stroke
        """

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...

    @keyStroke.setter
    def keyStroke(self, value: javax.swing.KeyStroke):
        ...

    @property
    def textField(self) -> javax.swing.JTextField:
        ...


class ActionBindingPanel(javax.swing.JPanel):
    """
    A panel that displays inputs for key strokes and mouse bindings.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listener: DockingActionInputBindingListener):
        ...

    def clearKeyStroke(self):
        ...

    def clearMouseBinding(self):
        ...

    def getKeyStroke(self) -> javax.swing.KeyStroke:
        ...

    def getMouseBinding(self) -> gui.event.MouseBinding:
        ...

    def isMouseBinding(self) -> bool:
        ...

    def setKeyBindingData(self, ks: javax.swing.KeyStroke, mb: gui.event.MouseBinding):
        ...

    @property
    def mouseBinding(self) -> gui.event.MouseBinding:
        ...

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...


class DefaultFocusOwnerProvider(FocusOwnerProvider):
    """
    Uses Java's default focus manager to provide the focus owner.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DisabledComponentLayerFactory(java.lang.Object):
    """
    A factory to create JLayer instances to provide the L&F and functionality of a 
    disabled panel -- the component assumes a disabled color, and selection via mouse and
    keyboard is prevented. As this is simply a layer in the UI stack, previous states of 
    components is maintained and unmodified.
    """

    @typing.type_check_only
    class DisabledComponentLayerUI(javax.swing.plaf.LayerUI[javax.swing.JComponent]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDisabledLayer(component: javax.swing.JComponent) -> javax.swing.JLayer[javax.swing.JComponent]:
        ...


class AbstractErrDialog(ReusableDialogComponentProvider):
    """
    A dialog that is meant to be extended for showing exceptions
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMessage(self) -> str:
        """
        Returns the string message of this error dialog
        
        :return: the message
        :rtype: str
        """

    @property
    def message(self) -> java.lang.String:
        ...


class DefaultHelpService(help.HelpService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["WindowPosition", "MySplitPane", "TaskScheduler", "ActionToGuiHelper", "ActionToGuiMapper", "ComponentTransferableData", "SystemExecutableAction", "DockingMouseBindingAction", "ComponentProvider", "DropCode", "DetachedWindowNode", "EmptyBorderToggleButton", "ShowWindowAction", "ErrLogExpandableDialog", "CloseIcon", "StatusBar", "MultiActionDialog", "ComponentTransferable", "DockingErrorDisplay", "ActionContext", "DockableHeader", "MenuBarMenuHandler", "DockingWindowListener", "ComponentLoadedListener", "PlaceholderInstaller", "SplitPanel", "DockingKeyBindingAction", "DialogComponentProviderPopupActionManager", "ReusableDialogComponentProvider", "UndoRedoKeeper", "KeyEntryListener", "TransferActionListener", "Tool", "WindowActionManager", "KeyBindingOverrideKeyEventDispatcher", "StatusBarSpacer", "KeyEntryTextField", "MouseBindingMouseEventDispatcher", "PopupMenuHandler", "DockingWindowManager", "DialogComponentProvider", "DockingActionPerformer", "PopupMenuContext", "WindowNode", "ShowComponentAction", "FocusOwnerProvider", "DockingCheckBoxMenuItem", "ExecutableAction", "DockingMenuItem", "KeyBindingPrecedence", "AbstractDockingTool", "GlobalMenuAndToolBarManager", "EditListener", "DropDownMenuIcon", "RootNode", "SplitNode", "DockingWindowsContextSensitiveHelpListener", "KbEnabledState", "HiddenDockingFrame", "DropTargetHandler", "DockingContextListener", "ComponentNode", "ComponentProviderActivationListener", "MouseEntryTextField", "DockingWindowManagerTestUtils", "PopupActionManager", "DockingDialog", "DockableComponent", "DockingUtils", "DockingActionProxy", "ErrorReporter", "DropTargetFactory", "DockingActionInputBindingListener", "ShowAllComponentsAction", "PlaceholderManager", "DialogActionContext", "HeaderCursor", "ErrLogDialog", "ComponentPlaceholder", "DefaultActionContext", "PlaceholderSet", "Node", "DockingFrame", "GenericHeader", "DockableToolBarManager", "KeyEntryPanel", "ActionBindingPanel", "DefaultFocusOwnerProvider", "DisabledComponentLayerFactory", "AbstractErrDialog", "DefaultHelpService"]
