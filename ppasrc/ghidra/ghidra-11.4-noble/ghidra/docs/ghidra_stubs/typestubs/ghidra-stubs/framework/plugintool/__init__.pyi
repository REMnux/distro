from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.framework
import docking.util.image
import ghidra.app.nav
import ghidra.framework
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool.dialog
import ghidra.framework.plugintool.util
import ghidra.util.classfinder
import ghidra.util.task
import java.awt # type: ignore
import java.beans # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import org.jdom # type: ignore
import utility.application
import utility.function


T = typing.TypeVar("T")


class NavigatableComponentProviderAdapter(ComponentProviderAdapter, ghidra.app.nav.Navigatable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], contextType: java.lang.Class[typing.Any]):
        ...

    def dispose(self):
        ...

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        ...


class StandAlonePluginTool(PluginTool):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, app: GenericStandAloneApplication, name: typing.Union[java.lang.String, str], hasStatus: typing.Union[jpype.JBoolean, bool]):
        ...

    def addManagePluginsAction(self):
        ...


class SettableApplicationInformationDisplayFactory(docking.framework.ApplicationInformationDisplayFactory):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setHomeCallback(self, callback: java.lang.Runnable):
        ...

    def setHomeIcon(self, icon: javax.swing.ImageIcon):
        ...

    def setSplashIcon128(self, splashIcon: javax.swing.ImageIcon):
        ...

    def setWindowsIcons(self, windowsIcons: java.util.List[java.awt.Image]):
        ...


class PluginTool(docking.AbstractDockingTool):
    """
    Base class that is a container to manage plugins and their actions, and to coordinate the
    firing of plugin events and tool events. A PluginTool may have visible components supplied by
    ComponentProviders . These components may be docked within the tool, or moved
    out into their own windows.
    
     
    Plugins normally add actions via :meth:`addAction(DockingActionIf) <.addAction>`.   There is also
    an alternate method for getting actions to appear in the popup context menu (see
    :meth:`addPopupActionProvider(PopupActionProvider) <.addPopupActionProvider>`).   The popup listener mechanism is generally not
    needed and should only be used in special circumstances (see :obj:`PopupActionProvider`).
    
     
    The PluginTool also manages tasks that run in the background, and options used by the plugins.
    """

    @typing.type_check_only
    class ToolOptionsListener(ghidra.framework.options.OptionsChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CheckedRunnable(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def run(self):
            ...


    @typing.type_check_only
    class TaskBusyListener(ghidra.util.task.TaskListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    TOOL_NAME_PROPERTY: typing.Final = "ToolName"
    """
    Name of the property for the tool name.
    """

    ICON_PROPERTY_NAME: typing.Final = "Icon"
    """
    Name of the property for the tool icon.
    """

    DESCRIPTION_PROPERTY_NAME: typing.Final = "Description"
    """
    Name of the property for the description of the tool.
    """

    PLUGIN_COUNT_PROPERTY_NAME: typing.Final = "PluginCount"
    """
    Name of the property for the number of plugins the tool has.
    """


    @typing.overload
    def __init__(self, project: ghidra.framework.model.Project, template: ghidra.framework.model.ToolTemplate):
        """
        Construct a new PluginTool.
        
        :param ghidra.framework.model.Project project: project that contains this tool
        :param ghidra.framework.model.ToolTemplate template: the template from which to load this tool
        """

    @typing.overload
    def __init__(self, project: ghidra.framework.model.Project, name: typing.Union[java.lang.String, str], isDockable: typing.Union[jpype.JBoolean, bool], hasStatus: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new PluginTool.
        
        :param ghidra.framework.model.Project project: project that contains the tool
        :param java.lang.String or str name: the name of the tool
        :param jpype.JBoolean or bool isDockable: true if the tool contains components that can be docked
        :param jpype.JBoolean or bool hasStatus: true if the tool should display a status component
        :param jpype.JBoolean or bool isModal: true if the tool is modal, meaning that while this tool is visible,
                no other tool or dialog in Ghidra can have focus
        """

    @typing.overload
    def __init__(self, project: ghidra.framework.model.Project, projectManager: ghidra.framework.model.ProjectManager, toolServices: ghidra.framework.model.ToolServices, name: typing.Union[java.lang.String, str], isDockable: typing.Union[jpype.JBoolean, bool], hasStatus: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool]):
        ...

    def accept(self, url: java.net.URL) -> bool:
        """
        Request tool to accept specified URL.  Acceptance of URL depends greatly on the plugins
        configured into tool.  If no plugin accepts URL it will be rejected and false returned.
        If a plugin can accept the specified URL it will attempt to process and return true if
        successful.  The user may be prompted if connecting to the URL requires user authentication.
        
        :param java.net.URL url: read-only resource URL
        :return: true if URL accepted and processed else false
        :rtype: bool
        """

    def acceptDomainFiles(self, data: jpype.JArray[ghidra.framework.model.DomainFile]) -> bool:
        ...

    def addEventListener(self, eventClass: java.lang.Class[PluginEvent], listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    def addListenerForAllPluginEvents(self, listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    @typing.overload
    def addPlugin(self, className: typing.Union[java.lang.String, str]):
        """
        Add a plugin to the tool.
        
        :param java.lang.String or str className: name of the plugin class, e.g., "MyPlugin.class.getName()"
        :raises PluginException: if the plugin could not be constructed, or
        there was problem executing its init() method, or if a plugin of this
        class already exists in the tool
        """

    @typing.overload
    def addPlugin(self, p: Plugin):
        ...

    @typing.overload
    @deprecated("use addPlugins(Collection)")
    def addPlugins(self, classNames: jpype.JArray[java.lang.String]):
        """
        Add plugins to the tool.
        
        :param jpype.JArray[java.lang.String] classNames: array of plugin class names
        :raises PluginException: if a plugin could not be constructed, or
        there was problem executing its init() method, or if a plugin of this
        class already exists in the tool
        
        .. deprecated::
        
        use :meth:`addPlugins(Collection) <.addPlugins>`
        """

    @typing.overload
    def addPlugins(self, classNames: collections.abc.Sequence):
        """
        Add plugins to the tool.
        
        :param collections.abc.Sequence classNames: collection of plugin class names
        :raises PluginException: if a plugin could not be constructed, or
        there was problem executing its init() method, or if a plugin of this
        class already exists in the tool
        """

    def addPropertyChangeListener(self, l: java.beans.PropertyChangeListener):
        ...

    def addStatusComponent(self, c: javax.swing.JComponent, addBorder: typing.Union[jpype.JBoolean, bool], rightSide: typing.Union[jpype.JBoolean, bool]):
        """
        Add a status component to the tool.
        
        :param javax.swing.JComponent c: component to add
        :param jpype.JBoolean or bool addBorder: true if a border should be added to the component
        :param jpype.JBoolean or bool rightSide: true if the component should be placed in the right side of the tool
        """

    def addToolListener(self, listener: ghidra.framework.model.ToolListener):
        ...

    def beep(self):
        """
        A convenience method to make an attention-grabbing noise to the user
        """

    def canCloseDomainFile(self, domainFile: ghidra.framework.model.DomainFile) -> bool:
        ...

    def canCloseDomainObject(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        """
        Can the domain object be closed?
         
        Note: This forces plugins to terminate any tasks they have running for the
        indicated domain object and apply any unsaved data to the domain object. If they can't do
        this or the user cancels then this returns false.
        
        :param ghidra.framework.model.DomainObject domainObject: the domain object to check
        :return: false any of the plugins reports that the domain object
        should not be closed
        :rtype: bool
        """

    def cancelCurrentTask(self):
        """
        Cancel the current task in the tool.
        """

    def clearLastEvents(self):
        """
        Clear the list of events that were last generated.
        """

    def close(self):
        """
        Closes this tool, possibly with input from the user. The following conditions are checked
        and can prompt the user for more info and allow them to cancel the close.
         
        1. Running tasks. Closing with running tasks could lead to data loss.
        2. Plugins get asked if they can be closed. They may prompt the user to resolve
        some plugin specific state.
        3. The user is prompted to save any data changes.
        4. Tools are saved, possibly asking the user to resolve any conflicts caused by
        changing multiple instances of the same tool in different ways.
        5. If all the above conditions passed, the tool is closed and disposed.
        """

    @typing.overload
    def execute(self, commandName: typing.Union[java.lang.String, str], domainObject: T, f: java.util.function.Function[T, java.lang.Boolean]) -> bool:
        """
        Execute the given command in the foreground.  Required domain object transaction will be
        started with delayed end to ensure that any follow-on analysis starts prior to transaction 
        end.
        
        :param T: :obj:`DomainObject` implementation interface:param java.lang.String or str commandName: command name to be associated with transaction
        :param T domainObject: domain object to be modified
        :param java.util.function.Function[T, java.lang.Boolean] f: command function callback which should return true on success or false on failure.
        :return: result from command function callback
        :rtype: bool
        """

    @typing.overload
    def execute(self, commandName: typing.Union[java.lang.String, str], domainObject: T, r: java.lang.Runnable):
        """
        Execute the given command in the foreground.  Required domain object transaction will be
        started with delayed end to ensure that any follow-on analysis starts prior to transaction 
        end.
        
        :param T: :obj:`DomainObject` implementation interface:param java.lang.String or str commandName: command name to be associated with transaction
        :param T domainObject: domain object to be modified
        :param java.lang.Runnable r: command function runnable
        """

    @typing.overload
    def execute(self, command: ghidra.framework.cmd.Command[T], obj: T) -> bool:
        """
        Call the applyTo() method on the given command to make some change to
        the domain object; the command is done in the AWT thread, therefore,
        the command that is to be executed should be a relatively quick operation
        so that the event queue does not appear to "hang." For lengthy
        operations, the command should be done in a background task.
        
        :param ghidra.framework.cmd.Command[T] command: command to apply
        :param T obj: domain object that the command will be applied to
        :return: status of the command's applyTo() method
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.executeBackgroundCommand(BackgroundCommand, DomainObject)`
        """

    @typing.overload
    def execute(self, task: ghidra.util.task.Task, delay: typing.Union[jpype.JInt, int]):
        """
        Launch the task in a new thread
        
        :param ghidra.util.task.Task task: task to run in a new thread
        :param jpype.JInt or int delay: number of milliseconds to delay the display of task monitor dialog
        """

    @typing.overload
    def execute(self, task: ghidra.util.task.Task):
        """
        Launch the task in a new thread
        
        :param ghidra.util.task.Task task: task to run in a new thread
        """

    def executeBackgroundCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand[T], obj: T):
        """
        Start a new thread that will call the given command's applyTo()
        method to make some change in the domain object. This method should
        be called for an operation that could potentially take a long time to
        complete.
        
        :param ghidra.framework.cmd.BackgroundCommand[T] cmd: command that will be executed in another thread (not the
        AWT Thread)
        :param T obj: domain object that the command will be applied to
        """

    def firePluginEvent(self, event: PluginEvent):
        ...

    def getActiveWindow(self) -> java.awt.Window:
        ...

    def getConsumedToolEventNames(self) -> jpype.JArray[java.lang.String]:
        ...

    def getDomainFiles(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        ...

    def getIconURL(self) -> docking.util.image.ToolIconURL:
        ...

    def getInstanceName(self) -> str:
        ...

    def getLocation(self) -> java.awt.Point:
        """
        Return the location of this tool's frame on the screen.
        
        :return: location of this tool's frame
        :rtype: java.awt.Point
        """

    def getManagePluginsDialog(self) -> ghidra.framework.plugintool.dialog.ManagePluginsDialog:
        """
        Returns the manage plugins dialog that is currently
        being used.
        
        :return: the current manage plugins dialog
        :rtype: ghidra.framework.plugintool.dialog.ManagePluginsDialog
        """

    def getManagedPlugins(self) -> java.util.List[Plugin]:
        """
        Return a list of plugins in the tool
        
        :return: list of plugins in the tool
        :rtype: java.util.List[Plugin]
        """

    def getOptions(self) -> jpype.JArray[ghidra.framework.options.ToolOptions]:
        """
        Get all options.
        
        :return: zero-length array if no options exist.
        :rtype: jpype.JArray[ghidra.framework.options.ToolOptions]
        """

    def getPluginsConfiguration(self) -> PluginsConfiguration:
        ...

    def getProject(self) -> ghidra.framework.model.Project:
        """
        Get the project associated with this tool.  Null will be returned if there is no
        project open or if this tool does not use projects.
        
        :return: null if there is no open project
        :rtype: ghidra.framework.model.Project
        """

    def getProjectManager(self) -> ghidra.framework.model.ProjectManager:
        """
        Returns the project manager associated with this tool.
        
         
        Null will be returned if this tool does not use projects.
        
        :return: the project manager associated with this tool
        :rtype: ghidra.framework.model.ProjectManager
        """

    def getServices(self, c: java.lang.Class[T]) -> jpype.JArray[T]:
        """
        Get the objects that implement the given service.
        
        :param java.lang.Class[T] c: service class
        :return: array of Objects that implement the service, c.
        :rtype: jpype.JArray[T]
        """

    def getSize(self) -> java.awt.Dimension:
        """
        Return the dimension of this tool's frame.
        
        :return: dimension of this tool's frame
        :rtype: java.awt.Dimension
        """

    def getSupportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...

    def getToolEventNames(self) -> jpype.JArray[java.lang.String]:
        ...

    def getToolName(self) -> str:
        ...

    def getToolServices(self) -> ghidra.framework.model.ToolServices:
        """
        Returns an object that provides fundamental services that plugins can use
        
        :return: the services instance
        :rtype: ghidra.framework.model.ToolServices
        """

    def getToolTemplate(self, includeConfigState: typing.Union[jpype.JBoolean, bool]) -> ghidra.framework.model.ToolTemplate:
        ...

    def getTransientState(self) -> ghidra.framework.plugintool.util.TransientToolState:
        ...

    def getUndoRedoToolState(self, domainObject: ghidra.framework.model.DomainObject) -> ghidra.framework.plugintool.util.UndoRedoToolState:
        ...

    def hasOptions(self, category: typing.Union[java.lang.String, str]) -> bool:
        """
        Return true if there is an options category with the given name
        
        :param java.lang.String or str category: name of the options set
        :return: true if there is an options category with the given name
        :rtype: bool
        """

    def hasToolListeners(self) -> bool:
        """
        Returns true if there is at least one tool listening to this tool's plugin events
        
        :return: true if there is at least one tool listening to this tool's plugin events
        :rtype: bool
        """

    def hasUnsavedData(self) -> bool:
        ...

    def isConfigurable(self) -> bool:
        ...

    def isExecutingCommand(self) -> bool:
        """
        Return whether there is a command being executed
        
        :return: true if there is a command being executed
        :rtype: bool
        """

    def isRestoringDataState(self) -> bool:
        ...

    def isService(self, serviceInterface: java.lang.Class[typing.Any]) -> bool:
        """
        Returns true if the specified ``serviceInterface``
        is a valid service that exists in this tool.
        
        :param java.lang.Class[typing.Any] serviceInterface: the service interface
        :return: true if the specified ``serviceInterface``
        :rtype: bool
        """

    def isWindowsOnTop(self) -> bool:
        """
        Return the value of the Tool option (GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP)
        for whether docked windows will always be shown on top of their parent windows.
        
        :return: value of the Tool option, GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP
        :rtype: bool
        """

    def prepareToSave(self, dobj: ghidra.framework.model.DomainObject):
        """
        Called when the domain object is about to be saved; this allows any plugin that has
        a cache to flush out to the domain object.
        
        :param ghidra.framework.model.DomainObject dobj: domain object that is about to be saved
        """

    def processToolEvent(self, toolEvent: PluginEvent):
        ...

    def putInstanceName(self, newInstanceName: typing.Union[java.lang.String, str]):
        ...

    def registerDefaultContextProvider(self, type: java.lang.Class[docking.ActionContext], provider: docking.action.ActionContextProvider):
        """
        Registers an action context provider as the default provider for a specific action
        context type. Note that this registers a default provider for exactly
        that type and not a subclass of that type. If the provider want to support a hierarchy of
        types, then it must register separately for each type. See :obj:`ActionContext` for details
        on how the action context system works.
        
        :param java.lang.Class[docking.ActionContext] type: the ActionContext class to register a default provider for
        :param docking.action.ActionContextProvider provider: the ActionContextProvider that provides default tool context for actions
        that consume the given ActionContext type
        """

    def registerOptionsNameChange(self, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str]):
        """
        Updates saved options from an old name to a new name.  NOTE: this must be called before
        any calls to register or get options.
        
        :param java.lang.String or str oldName: the old name of the options.
        :param java.lang.String or str newName: the new name of the options.
        """

    def removeEventListener(self, eventClass: java.lang.Class[PluginEvent], listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    def removeListenerForAllPluginEvents(self, listener: ghidra.framework.plugintool.util.PluginEventListener):
        ...

    @typing.overload
    @deprecated("use removePlugins(List)")
    def removePlugins(self, plugins: jpype.JArray[Plugin]):
        """
        Remove the array of plugins from the tool.
        
        :param jpype.JArray[Plugin] plugins: array of plugins to remove
        
        .. deprecated::
        
        use :meth:`removePlugins(List) <.removePlugins>`
        """

    @typing.overload
    def removePlugins(self, plugins: java.util.List[Plugin]):
        """
        Remove the array of plugins from the tool.
        
        :param java.util.List[Plugin] plugins: array of plugins to remove
        """

    @deprecated("use the DockingWindowManager")
    def removePreferenceState(self, name: typing.Union[java.lang.String, str]):
        """
        This method will be deleted.  Preference state should be managed with the 
        :obj:`DockingWindowManager`.
        
        :param java.lang.String or str name: the name
        
        .. deprecated::
        
        use the :obj:`DockingWindowManager`
        """

    def removePropertyChangeListener(self, l: java.beans.PropertyChangeListener):
        ...

    def removeStatusComponent(self, c: javax.swing.JComponent):
        """
        Remove the status component.
        
        :param javax.swing.JComponent c: status component to remove
        """

    def removeToolListener(self, listener: ghidra.framework.model.ToolListener):
        ...

    def restoreDataStateFromXml(self, root: org.jdom.Element):
        ...

    def restoreWindowingDataFromXml(self, element: org.jdom.Element):
        ...

    def saveDataStateToXml(self, savingProject: typing.Union[jpype.JBoolean, bool]) -> org.jdom.Element:
        ...

    def saveToXml(self, includeConfigState: typing.Union[jpype.JBoolean, bool]) -> org.jdom.Element:
        ...

    def saveTool(self):
        """
        Save this tool's configuration.
        """

    def saveToolAs(self) -> bool:
        """
        Triggers a 'Save As' dialog that allows the user to save off the tool under a different
        name.  This returns true if the user performed a save.
        
        :return: true if a save happened
        :rtype: bool
        """

    def saveToolToToolTemplate(self) -> ghidra.framework.model.ToolTemplate:
        ...

    def saveWindowingDataToXml(self) -> org.jdom.Element:
        ...

    def scheduleFollowOnCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand[T], obj: T):
        """
        Add the given background command to a queue that is processed after the
        main background command completes.
        
        :param ghidra.framework.cmd.BackgroundCommand[T] cmd: background command to submit
        :param T obj: the domain object to be modified by the command.
        """

    def setDefaultComponent(self, provider: docking.ComponentProvider):
        """
        Sets the provider that should get the default focus when no component has focus.
        
        :param docking.ComponentProvider provider: the provider that should get the default focus when no component has focus.
        """

    def setIconURL(self, newIconURL: docking.util.image.ToolIconURL):
        ...

    def setLocation(self, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        Set the location of this tool's frame on the screen.
        
        :param jpype.JInt or int x: screen x coordinate
        :param jpype.JInt or int y: screen y coordinate
        """

    def setSize(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Sets the size of the tool's main window
        
        :param jpype.JInt or int width: width in pixels
        :param jpype.JInt or int height: height in pixels
        """

    def setSubTitle(self, subTitle: typing.Union[java.lang.String, str]):
        """
        Sets the subtitle on the tool; the subtitle is extra text in the title.
        
        :param java.lang.String or str subTitle: the subtitle to display on the tool
        """

    def setToolName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setUnconfigurable(self):
        ...

    def setWindowsOnTop(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Set the Tool option (GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP)
        for whether a docked window will always be shown on top of its parent window.
        
        :param jpype.JBoolean or bool b: true means that the docked window will always appear on top of its
        parent window; false means to allow the docked window to be "hidden" under its
        parent dialog
        """

    def shouldSave(self) -> bool:
        """
        Returns true if this tool needs saving
        
        :return: true if this tool needs saving
        :rtype: bool
        """

    def showComponentHeader(self, provider: docking.ComponentProvider, b: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether a component's header should be shown; the header is the component that
        is dragged in order to move the component within the tool, or out of the tool
        into a separate window
        
        :param docking.ComponentProvider provider: provider of the visible component in the tool
        :param jpype.JBoolean or bool b: true means to show the header
        """

    def showConfig(self, addSaveActions: typing.Union[jpype.JBoolean, bool], isNewTool: typing.Union[jpype.JBoolean, bool]):
        """
        Displays the manage plugins dialog.
        
        :param jpype.JBoolean or bool addSaveActions: if true show save actions
        :param jpype.JBoolean or bool isNewTool: true if creating a new tool
        """

    @typing.overload
    def showDialog(self, dialogComponent: docking.DialogComponentProvider, centeredOnProvider: docking.ComponentProvider):
        """
        Shows the dialog using the window containing the given componentProvider as its parent window.
        Remembers the last location and size of this dialog for the next time it is shown.
        
        :param docking.DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        :param docking.ComponentProvider centeredOnProvider: the component provider that is used to find a parent window for this dialog.
        The dialog is centered on this component provider's component.
        """

    @typing.overload
    def showDialog(self, dialogComponent: docking.DialogComponentProvider, centeredOnComponent: java.awt.Component):
        """
        Shows the dialog using the tool's parent frame, but centers the dialog on the given
        component
        
        :param docking.DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        :param java.awt.Component centeredOnComponent: the component on which to center the dialog.
        """

    @deprecated("dialogs are now always shown over the active window when possible")
    def showDialogOnActiveWindow(self, dialogComponent: docking.DialogComponentProvider):
        """
        Shows the dialog using the tool's currently active window as a parent.  Also,
        remembers any size and location adjustments made by the user for the next
        time the dialog is shown.
        
        :param docking.DialogComponentProvider dialogComponent: the DialogComponentProvider object to be shown in a dialog.
        
        .. deprecated::
        
        dialogs are now always shown over the active window when possible
        """

    def showExtensions(self):
        """
        Displays the extensions installation dialog.
        """

    def threadIsBackgroundTaskThread(self) -> bool:
        """
        
        
        :return: true if the current thread group or its ancestors is
        a member of this tools background task thread group, else false
        :rtype: bool
        """

    def unregisterDefaultContextProvider(self, type: java.lang.Class[docking.ActionContext], provider: docking.action.ActionContextProvider):
        """
        Removes the default provider for the given ActionContext type.
        
        :param java.lang.Class[docking.ActionContext] type: the subclass of ActionContext to remove a provider for
        :param docking.action.ActionContextProvider provider: the ActionContextProvider to remove for the given ActionContext type
        """

    @property
    def projectManager(self) -> ghidra.framework.model.ProjectManager:
        ...

    @property
    def domainFiles(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        ...

    @property
    def restoringDataState(self) -> jpype.JBoolean:
        ...

    @property
    def instanceName(self) -> java.lang.String:
        ...

    @property
    def toolTemplate(self) -> ghidra.framework.model.ToolTemplate:
        ...

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...

    @property
    def toolEventNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def options(self) -> jpype.JArray[ghidra.framework.options.ToolOptions]:
        ...

    @property
    def executingCommand(self) -> jpype.JBoolean:
        ...

    @property
    def iconURL(self) -> docking.util.image.ToolIconURL:
        ...

    @iconURL.setter
    def iconURL(self, value: docking.util.image.ToolIconURL):
        ...

    @property
    def transientState(self) -> ghidra.framework.plugintool.util.TransientToolState:
        ...

    @property
    def undoRedoToolState(self) -> ghidra.framework.plugintool.util.UndoRedoToolState:
        ...

    @property
    def toolName(self) -> java.lang.String:
        ...

    @toolName.setter
    def toolName(self, value: java.lang.String):
        ...

    @property
    def services(self) -> jpype.JArray[T]:
        ...

    @property
    def windowsOnTop(self) -> jpype.JBoolean:
        ...

    @windowsOnTop.setter
    def windowsOnTop(self, value: jpype.JBoolean):
        ...

    @property
    def managedPlugins(self) -> java.util.List[Plugin]:
        ...

    @property
    def managePluginsDialog(self) -> ghidra.framework.plugintool.dialog.ManagePluginsDialog:
        ...

    @property
    def consumedToolEventNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def size(self) -> java.awt.Dimension:
        ...

    @property
    def pluginsConfiguration(self) -> PluginsConfiguration:
        ...

    @property
    def service(self) -> jpype.JBoolean:
        ...

    @property
    def toolServices(self) -> ghidra.framework.model.ToolServices:
        ...

    @property
    def supportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...

    @property
    def location(self) -> java.awt.Point:
        ...

    @property
    def activeWindow(self) -> java.awt.Window:
        ...

    @property
    def configurable(self) -> jpype.JBoolean:
        ...


class StandAloneApplication(GenericStandAloneApplication):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, propertiesFilename: typing.Union[java.lang.String, str]):
        """
        Creates a new application using the given properties filename. The
        filename is expected reside in the current working directory.
         
        
        **The given properties file is expected to have the
        :obj:`ApplicationProperties.APPLICATION_NAME_PROPERTY` and
        :obj:`ApplicationProperties.APPLICATION_VERSION_PROPERTY` properties
        set.**
        
        :param java.lang.String or str propertiesFilename: the name of the properties file.
        :raises IOException: error causing application initialization failure
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str]):
        """
        Creates a new application using the specified application name
        and version.
        
        :param java.lang.String or str name: application name
        :param java.lang.String or str version: application version
        :raises IOException: error causing application initialization failure
        """

    @typing.overload
    def __init__(self, applicationLayout: utility.application.ApplicationLayout):
        """
        Creates a new application using the given application layout
        and associated application properties.
        
        :param utility.application.ApplicationLayout applicationLayout: application layout
        """

    @staticmethod
    def readApplicationProperties(propertiesFilename: typing.Union[java.lang.String, str]) -> ghidra.framework.ApplicationProperties:
        """
        Read :obj:`ApplicationProperties` from the specified file path relative
        to the current working directory.
         
        
        **The given properties file is expected to have the
        :obj:`ApplicationProperties.APPLICATION_NAME_PROPERTY` and
        :obj:`ApplicationProperties.APPLICATION_VERSION_PROPERTY` properties
        set.**
        
        :param java.lang.String or str propertiesFilename: the name of the properties file.
        :return: application properties
        :rtype: ghidra.framework.ApplicationProperties
        :raises IOException: if file read error occurs
        """

    def setHomeCallback(self, callback: java.lang.Runnable):
        ...

    def setHomeIcon(self, icon: javax.swing.ImageIcon):
        ...

    def setWindowsIcons(self, windowsIcons: java.util.List[java.awt.Image]):
        ...

    def showSpashScreen(self, splashIcon: javax.swing.ImageIcon):
        ...

    def start(self):
        ...


class GenericStandAloneApplication(java.lang.Object):
    """
    A simplified interface for stand alone applications.
    """

    class_: typing.ClassVar[java.lang.Class]

    def exit(self):
        ...

    def getToolServices(self) -> ghidra.framework.model.ToolServices:
        ...

    @property
    def toolServices(self) -> ghidra.framework.model.ToolServices:
        ...


class PluginEvent(java.lang.Object):
    """
    Event generated by a plugin.
     
    
    A PluginEvent should be annotate with a :obj:`ToolEventName` if it may be
    passed between multiple tools via a :obj:`ToolConnection`.
    """

    class_: typing.ClassVar[java.lang.Class]
    EXTERNAL_SOURCE_NAME: typing.Final = "External Tool"
    """
    Name of event source when plugin event is passed to
    another tool as cross-tool event.
    """


    def getEventName(self) -> str:
        """
        Get the plugin event name.
        """

    def getSourceName(self) -> str:
        """
        Returns the name of the plugin immediately responsible for firing this
        event.
        """

    def getToolEventName(self) -> str:
        """
        Get the optional cross-tool event name which has been established via
        a :obj:`ToolEventName` annotation which makes it available for
        passing as an external tool via a :obj:`ToolConnection`.
        This name may differ from the :meth:`getEventName() <.getEventName>`.s
        
        :return: tool event name or null if not permitted as a cross-tool event
        :rtype: str
        """

    def getTriggerEvent(self) -> PluginEvent:
        ...

    def isToolEvent(self) -> bool:
        """
        Determine if this event has been annotated with a :obj:`ToolEventName` which
        makes it available for passing to another tool via a :obj:`ToolConnection`.
        
        :return: true if event can be utilized as a cross-tool event
        :rtype: bool
        """

    @staticmethod
    def lookupToolEventName(pluginEventClass: java.lang.Class[typing.Any]) -> str:
        """
        Returns the tool event name corresponding to the given pluginEventClass.
        If no corresponding tool event exists, null will be returned.
        """

    def setSourceName(self, s: typing.Union[java.lang.String, str]):
        ...

    def setTriggerEvent(self, triggerEvent: PluginEvent):
        ...

    @property
    def toolEventName(self) -> java.lang.String:
        ...

    @property
    def toolEvent(self) -> jpype.JBoolean:
        ...

    @property
    def eventName(self) -> java.lang.String:
        ...

    @property
    def triggerEvent(self) -> PluginEvent:
        ...

    @triggerEvent.setter
    def triggerEvent(self, value: PluginEvent):
        ...

    @property
    def sourceName(self) -> java.lang.String:
        ...

    @sourceName.setter
    def sourceName(self, value: java.lang.String):
        ...


class PluginConfigurationModel(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: PluginTool):
        ...

    @typing.overload
    def __init__(self, pluginInstaller: PluginInstaller, pluginPackagingProvider: PluginPackagingProvider):
        ...

    def addPlugin(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription):
        ...

    def addSupportedPlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage):
        ...

    def getAllPluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    def getDependencies(self, pd: ghidra.framework.plugintool.util.PluginDescription) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Return the descriptions of the plugins that are dependent on some service that the plugin
        corresponding to the given PluginDescription provides.
        
        :param ghidra.framework.plugintool.util.PluginDescription pd: PluginDescription of the plugin
        :return: the descriptions
        :rtype: java.util.List[ghidra.framework.plugintool.util.PluginDescription]
        """

    def getPackageState(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> ghidra.framework.plugintool.util.PluginPackageState:
        ...

    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    def getPluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        ...

    def hasDependencies(self, pluginDependency: ghidra.framework.plugintool.util.PluginDescription) -> bool:
        """
        Return whether the plugin corresponding to the given PluginDescription
        has other plugins depending on a service it provides.
        
        :param ghidra.framework.plugintool.util.PluginDescription pluginDependency: PluginDescription of the plugin
        :return: true if the plugin corresponding to the given PluginDescription
        has at least one plugin depending on a service it provides
        :rtype: bool
        """

    def hasOnlyUnstablePlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> bool:
        ...

    def isLoaded(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription) -> bool:
        ...

    def removeAllPlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage):
        ...

    def removePlugin(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription):
        ...

    def setChangeCallback(self, listener: utility.function.Callback):
        ...

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def allPluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        ...

    @property
    def packageState(self) -> ghidra.framework.plugintool.util.PluginPackageState:
        ...

    @property
    def dependencies(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...


class ComponentProviderAdapter(docking.ComponentProvider):
    """
    Extends the :obj:`ComponentProvider` to fit into the Plugin architecture by taking in a 
    :obj:`PluginTool` which extends :obj:`Tool`.  Most implementers will want to extend
    this class instead of the ComponentProvider class because they will want to access the extra
    methods provided by PluginTool over DockingTool without having to cast the dockingTool variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Creates a new component provider with a default location of
        :obj:`WindowPosition.WINDOW <docking.WindowPosition.WINDOW>`.
        
        :param PluginTool tool: the plugin tool.
        :param java.lang.String or str name: The providers name.  This is used to group similar providers into a tab within
                the same window.
        :param java.lang.String or str owner: The owner of this provider, usually a plugin name.
        """

    @typing.overload
    def __init__(self, tool: PluginTool, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], contextType: java.lang.Class[typing.Any]):
        """
        Creates a new component provider with a default location of
        :obj:`WindowPosition.WINDOW <docking.WindowPosition.WINDOW>`.
        
        :param PluginTool tool: the plugin tool.
        :param java.lang.String or str name: The providers name.  This is used to group similar providers into a tab within
                the same window.
        :param java.lang.String or str owner: The owner of this provider, usually a plugin name
        :param java.lang.Class[typing.Any] contextType: the type of context supported by this provider; may be null
        """


class PluginsConfiguration(java.lang.Object):
    """
    This class maintains a collection of all plugin classes that are acceptable for a given tool
    type.  Simple applications with only one plugin type can use the
    :obj:`DefaultPluginsConfiguration`.  More complex tools can support a subset of the available
    plugins. Those tools should create custom subclasses for each tool type, that filter out plugins
    that are not appropriate for that tool type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getManagedPluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    def getPluginClassNames(self, element: org.jdom.Element) -> java.util.Set[java.lang.String]:
        ...

    def getPluginDescription(self, className: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.util.PluginDescription:
        ...

    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    def getPluginNamesByCurrentPackage(self, classNames: java.util.List[java.lang.String]) -> java.util.Set[java.lang.String]:
        """
        Used to convert an old style tool XML file by mapping the given class names to plugin
        packages and then adding **all** plugins in that package.  This has the effect of pulling
        in more plugin classes than were originally specified in the tool xml.
        
        :param java.util.List[java.lang.String] classNames: the list of classNames from the old XML file
        :return: the adjusted set of plugin class names
        :rtype: java.util.Set[java.lang.String]
        """

    def getPluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        ...

    def getUnstablePluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    def savePluginsToXml(self, root: org.jdom.Element, plugins: java.util.List[Plugin]):
        ...

    @property
    def pluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        ...

    @property
    def pluginClassNames(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def unstablePluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription:
        ...

    @property
    def managedPluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginNamesByCurrentPackage(self) -> java.util.Set[java.lang.String]:
        ...


class ModalPluginTool(PluginTool):
    """
    PluginTool that is used by the Merge process to resolve conflicts
    when a file is being checked into a server repository. This tool
    is modal while it is visible.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createTool(name: typing.Union[java.lang.String, str]) -> ModalPluginTool:
        ...


class DefaultPluginInstaller(PluginInstaller):
    """
    The default plugin installer that uses a tool to install plugins
    """

    class_: typing.ClassVar[java.lang.Class]


class PluginToolMacAboutHandler(java.lang.Object):
    """
    A plugin-level about handler that serves as the callback from the Dock's 'About' popup action.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def install(winMgr: docking.DockingWindowManager):
        """
        Applies an about handler which will show our custom about dialog.
        
        :param docking.DockingWindowManager winMgr: The docking window manager to use to install the about dialog.
        """


class ProjectPluginEvent(PluginEvent):
    """
    Plugin event for notifying when a project is opened or closed. Note this is only applicable for
    FrontEndTool plugins.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceName: typing.Union[java.lang.String, str], project: ghidra.framework.model.Project):
        """
        Constructor
        
        :param java.lang.String or str sourceName: the name of source of the event
        :param ghidra.framework.model.Project project: if non-null, the project that was opened; otherwise the current was closed.
        """

    def getProject(self) -> ghidra.framework.model.Project:
        """
        Returns the project that was opened or null if the project was closed.
        
        :return: the project that was opened or null if the project was closed.
        :rtype: ghidra.framework.model.Project
        """

    @property
    def project(self) -> ghidra.framework.model.Project:
        ...


class PluginPackagingProvider(java.lang.Object):
    """
    Provides :obj:`PluginPackage`s and plugin descriptions and to clients
    """

    class_: typing.ClassVar[java.lang.Class]
    EXPERIMENTAL_ICON: typing.Final[javax.swing.Icon]
    UNSTABLE_PACKAGE: typing.Final[ghidra.framework.plugintool.util.PluginPackage]

    def getPluginDescription(self, pluginClassName: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.util.PluginDescription:
        """
        Returns the plugin description for the given plugin class name
        
        :param java.lang.String or str pluginClassName: the plugin class name
        :return: the description
        :rtype: ghidra.framework.plugintool.util.PluginDescription
        """

    @typing.overload
    def getPluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Returns all loaded plugin descriptions
        
        :return: the descriptions
        :rtype: java.util.List[ghidra.framework.plugintool.util.PluginDescription]
        """

    @typing.overload
    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Get all plugin descriptions for the given plugin package
        
        :param ghidra.framework.plugintool.util.PluginPackage pluginPackage: the package
        :return: the descriptions
        :rtype: java.util.List[ghidra.framework.plugintool.util.PluginDescription]
        """

    def getPluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        """
        Returns all known plugin packages
        
        :return: the plugin packages
        :rtype: java.util.List[ghidra.framework.plugintool.util.PluginPackage]
        """

    def getUnstablePluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Returns all :obj:`PluginStatus.UNSTABLE` plugin package descriptions
        
        :return: the descriptions
        :rtype: java.util.List[ghidra.framework.plugintool.util.PluginDescription]
        """

    def getUnstablePluginPackage(self) -> ghidra.framework.plugintool.util.PluginPackage:
        """
        Returns the plugin package used to house all unstable plugin packages
        
        :return: the package
        :rtype: ghidra.framework.plugintool.util.PluginPackage
        """

    @property
    def pluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginPackages(self) -> java.util.List[ghidra.framework.plugintool.util.PluginPackage]:
        ...

    @property
    def unstablePluginDescriptions(self) -> java.util.List[ghidra.framework.plugintool.util.PluginDescription]:
        ...

    @property
    def pluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription:
        ...

    @property
    def unstablePluginPackage(self) -> ghidra.framework.plugintool.util.PluginPackage:
        ...


class PluginToolAccessUtils(java.lang.Object):
    """
    Utility class to provide access to non-public methods on PluginTool. There are a number of
    methods that internal classes need access to but we don't want on the public interface of
    PluginTool.This is a stopgap approach until we clean up the package structure for tool related
    classes and interfaces. This class should only be used by internal tool manager classes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def canClose(tool: PluginTool) -> bool:
        """
        Returns true if the tool can be closed. Note this does not handle any data saving. It only
        checks that there are no tasks running and the plugins can be closed.
        
        :param PluginTool tool: the tool to close
        :return: true if the tool can be closed
        :rtype: bool
        """

    @staticmethod
    def dispose(tool: PluginTool):
        """
        Disposes the tool.
        
        :param PluginTool tool: the tool to dispose
        """


class DeafultPluginPackagingProvider(PluginPackagingProvider):
    """
    The default plugin package provider that uses the :obj:`PluginsConfiguration` to supply packages
    """

    class_: typing.ClassVar[java.lang.Class]


class BusyToolException(java.lang.Exception):
    """
    Exception thrown if an operation cannot be done because the tool has background tasks
    running.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Construct a new exception.
        
        :param java.lang.String or str message: reason for the exception
        """


class PluginToolMacQuitHandler(java.lang.Object):
    """
    A plugin-level quit handler that serves as the callback from the Dock's 'Quit' popup action.
     
    
    This will also respond to the Command-Q callback.
     
    
    Note: there is a big assumption for this class that the 'front end tool', whatever that may 
    be for your application, will be installed before all other tools.  Thus, when quit is called
    on your application, it will go through the main tool of your app, that knows about sub-tools
    and such.  Moreover, you would not want this handler installed on a subordinate tool; otherwise, 
    the quit handler would try to close the wrong tool when the handler is activated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def install(tool: PluginTool):
        """
        Applies a quit handler which will close the given tool.
        
        :param PluginTool tool: The tool to close, which should result in the desired quit behavior.
        """


class ToolServicesAdapter(ghidra.framework.model.ToolServices):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Plugin(ghidra.util.classfinder.ExtensionPoint, ghidra.framework.plugintool.util.PluginEventListener, ghidra.framework.plugintool.util.ServiceListener):
    """
    Plugins are a basic building block in Ghidra, used to bundle features or capabilities
    into a unit that can be enabled or disabled by the user in their Tool.
     
    
    Plugins expose their features or capabilities to users via menu items and buttons that
    the user can click on, and via "service" APIs that other Plugins can programmatically subscribe
    to, and via :obj:`PluginEvent`s that are broadcast.
     
     
    ********************
    Well formed Plugins:
    ********************
    
     
    * Derive from Plugin (directly or indirectly).
    * Class name ends with "Plugin" and does not match any other Plugin, regardless of its 
    location in the package tree.
    * Have a :obj:`@PluginInfo() <PluginInfo>` annotation.
    * Have a constructor with exactly 1 parameter: PluginTool.
    *     
        * public MyPlugin(PluginTool tool) { ... }
    
    * Usually overrides protected void init().
    
     
    ************
    Class naming
    ************
    
    All Plugin Classes **MUST END IN** "Plugin".  If not, the ClassSearcher will not find them.
     
    
    Some special Plugins marked with the :obj:`ProgramaticUseOnly` interface are manually
    created and do not follow this naming requirement.
    
     
    *****************
    Plugin Life cycle
    *****************
    
     
    1. Your Plugin's constructor is called
    2.     
        1. Plugin base class constructor is called.
        2.     
            1. Services listed in the @PluginInfo annotation are automatically added to dependency 
            list
        
        3. Your Plugin publishes any services listed in PluginInfo using
        :meth:`registerServiceProvided() <Plugin.registerServiceProvided>`.
        (required)
        4. Create Actions (optional)
        5. Register :obj:`Options <ghidra.framework.options.Options>` with the
        :meth:`PluginTool.getOptions(String) <PluginTool.getOptions>`. (optional)
    
    3. Other Plugins are constructed, dependencies evaluated, etc.
        If your dependencies are not available (i.e., not installed, threw an exception during their
    initialization, etc), your Plugin's:meth:`dispose() <.dispose>` will be called and then your Plugin
    instance will be discarded.
    4. Your Plugin's :meth:`init() <.init>` method is called (when its dependencies are met).
    5.     
        1. Call :meth:`PluginTool.getService(Class) <PluginTool.getService>` to get service
        implementations. (the service class being requested should already be
        listed in the @PluginInfo)
        2. Create Actions (optional)
        3. Other initialization stuff.
    
    6. Your Plugin's :meth:`readConfigState(SaveState) <.readConfigState>` is called.
    7. ...user uses Ghidra...
    8.     
        * Your Plugin's :meth:`processEvent(PluginEvent) <.processEvent>` is called for events.
        * Your Plugin's Action's methods (i.e.,
        :meth:`actionPerformed <DockingAction.actionPerformed>`) are
        called.
        * Your Plugin's published service methods are called by other Plugins.
        * Your Plugin's listener methods are called.
    
    9. Plugin is unloaded due to shutdown of the Tool or being disabled by user
    10.     
        1. Your Plugin's :meth:`writeConfigState(SaveState) <.writeConfigState>` is called - override this
        method to write configuration info into the Tool definition.
        2. Your Plugin's :meth:`dispose() <.dispose>` is called - override this method to free
        any resources and perform any needed cleanup.
        3. Your Plugin's services and events are de-registered automatically.
    
    
    
     
    *************************
    Plugin Service dependency
    *************************
    
    All Plugins must be tagged with a :obj:`@PluginInfo(...) <PluginInfo>` annotation.
     
    
    The annotation gives you the ability to declare a dependency on another Plugin
    via the :meth:`servicesRequired <PluginInfo.servicesRequired>`
     
    
    Ghidra will ensure that your Plugin will not be :meth:`initialized <.init>` until all
    of its required services are loaded successfully and are available for use when your Plugin
    calls the :meth:`PluginTool.getService(Class) <PluginTool.getService>` method.
     
    
    Conversely, any services your Plugin advertises in @PluginInfo must be published via calls to
    :meth:`registerServiceProvided() <.registerServiceProvided>` in your Plugin's
    constructor.
     
    
    **Cyclic dependencies** are not allowed and will cause the Plugin management code to fail to
    load your Plugin. (i.e., PluginA requires a service that PluginB provides, which requires a
    service that PluginA provides)
    
     
    *****************************
    Plugin Service implementation
    *****************************
    
    A Plugin may provide a service to other Plugins by advertising in its :obj:`PluginInfo`
    annotation that it :meth:`provides <PluginInfo.servicesProvided>` an interface class.
     
    
    Your Plugin can either directly implement the interface in your Plugin class:
     
    
      ``public class MyPlugin extends Plugin **implements MyService** {....}``
     
    
    or it may delegate the handling of the service interface to another object during its
    constructor:
     
    
      ``public MyPlugin(PluginTool tool) {``
    
        ``...``
    
        ``MyService serviceObj = new MyService() { ... };``
    
        ``**registerServiceProvided(MyService.class, serviceObj);**``
    
      ``}``
    
     
    
    When your Plugin directly implements the advertised service interface, you should **not**
    call :meth:`registerServiceProvided <.registerServiceProvided>` for that service
    interface.
     
    
    Service interface classes are just normal java interface declarations and have no
    preconditions or other requirements to be used as a Plugin's advertised service interface.
     
    
    Optionally, service interface classes can be marked with meta-data via a
    :obj:`@ServiceInfo <ServiceInfo>` annotation that can have a
    :meth:`defaultProvider <ServiceInfo.defaultProvider>` property which specifies a Plugin's
    class (or classname) that should be auto-loaded to provide an implementation of the service
    interface when that service is required by some other Plugin.  Without the defaultProvider
    information, dependent Plugins will fail to load unless the user manually loads a Plugin
    that provides the necessary interface service.
     
    
    Multiple Plugins can implement the same service interface.  Plugins that use that
    multi-implemented service will either receive a randomly picked instance if using
    :meth:`PluginTool.getService(Class) <PluginTool.getService>` or will receive all implementations if using
    :meth:`PluginTool.getServices(Class) <PluginTool.getServices>`.
    
     
    *************
    Plugin Events
    *************
    
     
    * Every type of plugin event should be represented by some class extending
    :obj:`PluginEvent`.
    * One PluginEvent subclass may be used for more than one event type as long as there's some
    natural grouping.
    
    
     
    *******************
    Component Providers
    *******************
    
     
    * A plugin may supply a :obj:`ComponentProvider` that provides a visual component when
    the plugin is added to the tool.
    
    
     
    ****************************************************
    Important interfaces Plugins often need to implement
    ****************************************************
    
     
    * :obj:`OptionsChangeListener` - to receive notification when a configuration option
    is changed by the user.
    * :obj:`ApplicationLevelPlugin` - marks this Plugin as being suitable for inclusion in the
    application-level tool.
    * :obj:`ApplicationLevelOnlyPlugin` - marks this Plugin as application-level only, not
    usable in an application's sub-tools.
    * :obj:`ProgramaticUseOnly` - marks this Plugin as special and not for user configuration.
    """

    class_: typing.ClassVar[java.lang.Class]

    def accept(self, url: java.net.URL) -> bool:
        """
        Request plugin to process URL if supported.  Actual processing may be delayed and 
        interaction with user may occur (e.g., authentication, approval, etc.).
        
        :param java.net.URL url: data URL
        :return: boolean true if this plugin can process URL.
        :rtype: bool
        """

    def acceptData(self, data: jpype.JArray[ghidra.framework.model.DomainFile]) -> bool:
        """
        Method called if the plugin supports this domain file.
        
        :param jpype.JArray[ghidra.framework.model.DomainFile] data: array of :obj:`DomainFile`s
        :return: boolean true if can accept
        :rtype: bool
        """

    def dataStateRestoreCompleted(self):
        """
        Notification that all plugins have had their data states restored.
        """

    def dependsUpon(self, plugin: Plugin) -> bool:
        """
        Check if this plugin depends on the given plugin
        
        :param Plugin plugin: the plugin
        :return: true if this plugin depends on the given plugin
        :rtype: bool
        """

    def firePluginEvent(self, event: PluginEvent):
        """
        Fire the given plugin event; the tool notifies all other plugins
        who are interested in receiving the given event type.
        
        :param PluginEvent event: event to fire
        """

    def getData(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        """
        Get the domain files that this plugin has open.
        
        :return: array of :obj:`DomainFile`s that are open by this Plugin.
        :rtype: jpype.JArray[ghidra.framework.model.DomainFile]
        """

    def getMissingRequiredServices(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    def getName(self) -> str:
        """
        Returns this plugin's name.
        
        :return: String name, derived from simple class name.
        :rtype: str
        """

    def getPluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription:
        """
        Returns the static :obj:`PluginDescription` object that was derived from the
        :obj:`@PluginInfo <PluginInfo>` annotation at the top of your Plugin.
        
        :return: the static/shared :obj:`PluginDescription` instance that describes this Plugin.
        :rtype: ghidra.framework.plugintool.util.PluginDescription
        """

    def getSupportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        """
        Return classes of data types that this plugin can support.
        
        :return: classes of data types that this plugin can support
        :rtype: jpype.JArray[java.lang.Class[typing.Any]]
        """

    def getTool(self) -> PluginTool:
        """
        Get the :obj:`PluginTool` that hosts/contains this plugin.
        
        :return: PluginTool
        :rtype: PluginTool
        """

    def getTransientState(self) -> java.lang.Object:
        """
        Returns an object containing the plugins state.  Plugins should override this method if
        they have state that they want to maintain between domain object state transitions (i.e. when the
        user tabs to a different domain object and back) Whatever object is returned will be fed back to
        the plugin after the tool state is switch back to the domain object that was active when the this
        method was called.
        
        :return: Object to be return in the restoreTransientState() method.
        :rtype: java.lang.Object
        """

    def getUndoRedoState(self, domainObject: ghidra.framework.model.DomainObject) -> java.lang.Object:
        """
        Returns an object containing the plugin's state as needed to restore itself after an undo
        or redo operation.  Plugins should override this method if they have special undo/redo handling.
        
        :param ghidra.framework.model.DomainObject domainObject: the object that is about to or has had undoable changes made to it.
        :return: the state object
        :rtype: java.lang.Object
        """

    def hasMissingRequiredService(self) -> bool:
        """
        Checks if this plugin is missing a required service.
        
        :return: boolean true if a required service isn't available via the PluginTool.
        :rtype: bool
        """

    def isDisposed(self) -> bool:
        ...

    def processEvent(self, event: PluginEvent):
        """
        Method called to process a plugin event.  Plugins should override this method
        if the plugin processes PluginEvents;
        
        :param PluginEvent event: plugin to process
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Tells the Plugin to read its data-independent (preferences)
        properties from the input stream.
        
        :param ghidra.framework.options.SaveState saveState: object that holds primitives for state information
        """

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Tells the Plugin to read its data-dependent state from the
        given SaveState object.
        
        :param ghidra.framework.options.SaveState saveState: object that holds primitives for state information
        """

    def restoreTransientState(self, state: java.lang.Object):
        """
        Provides the transient state object that was returned in the corresponding getTransientState()
        call.  Plugins should override this method if they have state that needs to be saved as domain objects
        get switched between active and inactive.
        
        :param java.lang.Object state: the state object that was generated by this plugin's getTransientState() method.
        """

    def restoreUndoRedoState(self, domainObject: ghidra.framework.model.DomainObject, state: java.lang.Object):
        """
        Updates the plugin's state based on the data stored in the state object.  The state object
        is the object that was returned by this plugin in the :meth:`getUndoRedoState(DomainObject) <.getUndoRedoState>`
        
        :param ghidra.framework.model.DomainObject domainObject: the domain object that has had an undo or redo operation applied to it.
        :param java.lang.Object state: the state that was recorded before the undo or redo operation.
        """

    def serviceAdded(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Notifies this plugin that a service has been added to
        the plugin tool.
        Plugins should override this method if they update their state
        when a particular service is added.
        
        :param java.lang.Class[typing.Any] interfaceClass: The **interface** of the added service
        :param java.lang.Object service: service that is being added
        """

    def serviceRemoved(self, interfaceClass: java.lang.Class[typing.Any], service: java.lang.Object):
        """
        Notifies this plugin that service has been removed from the
        plugin tool.
        Plugins should override this method if they update their state
        when a particular service is removed.
        
        :param java.lang.Class[typing.Any] interfaceClass: The **interface** of the added service
        :param java.lang.Object service: that is being removed.
        """

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Tells a Plugin to write any data-independent (preferences)
        properties to the output stream.
        
        :param ghidra.framework.options.SaveState saveState: object that holds primitives for state information
        """

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        """
        Tells the Plugin to write any data-dependent state to the
        output stream.
        
        :param ghidra.framework.options.SaveState saveState: object that holds primitives for state information
        """

    @property
    def data(self) -> jpype.JArray[ghidra.framework.model.DomainFile]:
        ...

    @property
    def missingRequiredServices(self) -> java.util.List[java.lang.Class[typing.Any]]:
        ...

    @property
    def undoRedoState(self) -> java.lang.Object:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def supportedDataTypes(self) -> jpype.JArray[java.lang.Class[typing.Any]]:
        ...

    @property
    def pluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription:
        ...

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def transientState(self) -> java.lang.Object:
        ...

    @property
    def tool(self) -> PluginTool:
        ...


class ServiceInterfaceImplementationPair(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    interfaceClass: java.lang.Class[typing.Any]
    provider: java.lang.Object

    def __init__(self, interfaceClass: java.lang.Class[typing.Any], provider: java.lang.Object):
        ...


class PluginInstaller(java.lang.Object):
    """
    An interface that facilitates the adding and removing of plugins
    """

    class_: typing.ClassVar[java.lang.Class]

    def addPlugins(self, pluginClassNames: java.util.List[java.lang.String]):
        """
        Adds the given plugins to the system
        
        :param java.util.List[java.lang.String] pluginClassNames: the plugin class names to add
        :raises PluginException: if there is an issue loading any of the plugins
        """

    def getManagedPlugins(self) -> java.util.List[Plugin]:
        """
        Returns all currently installed plugins
        
        :return: the plugins
        :rtype: java.util.List[Plugin]
        """

    def removePlugins(self, plugins: java.util.List[Plugin]):
        """
        Removes the given plugins from the system
        
        :param java.util.List[Plugin] plugins: the plugins
        """

    @property
    def managedPlugins(self) -> java.util.List[Plugin]:
        ...


@typing.type_check_only
class PluginManager(java.lang.Object):

    @typing.type_check_only
    class PluginDependency(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def dependant(self) -> java.lang.Class[typing.Any]:
            ...

        def dependency(self) -> java.lang.Class[typing.Any]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getTransientState(self) -> ghidra.framework.plugintool.util.TransientToolState:
        ...

    def getUndoRedoToolState(self, domainObject: ghidra.framework.model.DomainObject) -> ghidra.framework.plugintool.util.UndoRedoToolState:
        ...

    @property
    def transientState(self) -> ghidra.framework.plugintool.util.TransientToolState:
        ...

    @property
    def undoRedoToolState(self) -> ghidra.framework.plugintool.util.UndoRedoToolState:
        ...


class ServiceProviderStub(ServiceProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ServiceProviderDecorator(ServiceProvider):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createEmptyDecorator() -> ServiceProviderDecorator:
        ...

    @staticmethod
    def decorate(delegate: ServiceProvider) -> ServiceProviderDecorator:
        ...

    def overrideService(self, serviceClass: java.lang.Class[T], service: java.lang.Object):
        """
        Adds a service that will override any service contained in the delegate 
        :obj:`ServiceProvider`. 
         
         
        Note: this will not notify any clients that services have been changed.  This means 
        that you should call this method before passing this service provider on to your clients.
        
        :param java.lang.Class[T] serviceClass: the service class
        :param java.lang.Object service: the service implementation
        """


class ServiceProvider(java.lang.Object):
    """
    Interface for providing Services
    """

    class_: typing.ClassVar[java.lang.Class]

    def addServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener):
        """
        Adds a listener that will be called as services are added and removed from this 
        ServiceProvider.
        
        :param ghidra.framework.plugintool.util.ServiceListener listener: The listener to add.
        """

    def getService(self, serviceClass: java.lang.Class[T]) -> T:
        """
        Returns the Service object that implements the given service interface.
        
        :param java.lang.Class[T] serviceClass: the interface class.
        """

    def removeServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener):
        """
        Removes the given listener from this ServiceProvider.  This method does nothing if the
        given listener is not contained by this ServiceProvider.
        
        :param ghidra.framework.plugintool.util.ServiceListener listener:
        """

    @property
    def service(self) -> T:
        ...



__all__ = ["NavigatableComponentProviderAdapter", "StandAlonePluginTool", "SettableApplicationInformationDisplayFactory", "PluginTool", "StandAloneApplication", "GenericStandAloneApplication", "PluginEvent", "PluginConfigurationModel", "ComponentProviderAdapter", "PluginsConfiguration", "ModalPluginTool", "DefaultPluginInstaller", "PluginToolMacAboutHandler", "ProjectPluginEvent", "PluginPackagingProvider", "PluginToolAccessUtils", "DeafultPluginPackagingProvider", "BusyToolException", "PluginToolMacQuitHandler", "ToolServicesAdapter", "Plugin", "ServiceInterfaceImplementationPair", "PluginInstaller", "PluginManager", "ServiceProviderStub", "ServiceProviderDecorator", "ServiceProvider"]
