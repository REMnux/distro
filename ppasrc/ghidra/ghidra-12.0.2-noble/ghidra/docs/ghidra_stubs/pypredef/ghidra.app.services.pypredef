from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import generic.jar
import ghidra.app.context
import ghidra.app.nav
import ghidra.app.plugin.core.analysis
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.plugin.core.eclipse
import ghidra.app.plugin.core.graph
import ghidra.app.plugin.core.marker
import ghidra.app.plugin.core.navigation.locationreferences
import ghidra.app.plugin.core.programtree
import ghidra.app.plugin.core.strings
import ghidra.app.plugin.core.terminal
import ghidra.app.plugin.core.terminal.vt
import ghidra.app.util
import ghidra.app.util.importer
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.debug.api.action
import ghidra.debug.api.breakpoint
import ghidra.debug.api.control
import ghidra.debug.api.emulation
import ghidra.debug.api.listing
import ghidra.debug.api.modules
import ghidra.debug.api.platform
import ghidra.debug.api.progress
import ghidra.debug.api.target
import ghidra.debug.api.tracemgr
import ghidra.debug.api.tracermi
import ghidra.debug.api.watch
import ghidra.features.base.codecompare.model
import ghidra.features.base.codecompare.panel
import ghidra.features.base.memsearch.gui
import ghidra.formats.gfilesystem
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.pcode.emu
import ghidra.program.model.address
import ghidra.program.model.block
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.service.graph
import ghidra.trace.model
import ghidra.trace.model.breakpoint
import ghidra.trace.model.guest
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.program
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.awt # type: ignore
import java.awt.datatransfer # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.nio # type: ignore
import java.nio.charset # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore
import utility.function


T = typing.TypeVar("T")


class GoToService(java.lang.Object):
    """
    The GoToService provides a general service for plugins to generate GoTo events. The provider of
    this service will take care of interfacing with any history service that may be available.
     
    
    This class will execute all ``goTo`` calls on the Java Swing thread. This will happen in a
    blocking manner if the client calls from any other thread. This has the potential to lead to
    deadlocks if the client is using custom synchronization. Care must be taken to not be holding any
    lock that will cause the Swing thread to block when using this class from any other thread. To
    work around this issue, clients can always call this service from within a
    :meth:`Swing.runLater(Runnable) <Swing.runLater>` call, which will prevent any deadlock issues.
    """

    class_: typing.ClassVar[java.lang.Class]
    VALID_GOTO_CHARS: typing.Final[jpype.JArray[jpype.JChar]]
    """
    Characters that are allowed in words that the GoToService can use. These typically represent
    library name delimiters.
    """


    def getDefaultNavigatable(self) -> ghidra.app.nav.Navigatable:
        """
        Returns the default navigatable that is the destination for GoTo events.
         
        
        This navigatable will not be null.
        
        :return: the navigatable
        :rtype: ghidra.app.nav.Navigatable
        """

    def getOverrideService(self) -> GoToOverrideService:
        ...

    @typing.overload
    def goTo(self, loc: ghidra.program.util.ProgramLocation) -> bool:
        """
        Generates a GoTo event and handles any history state that needs to be saved.
         
        
        This method will attempt to find the program that contains the given ProgramLocation.
        
        :param ghidra.program.util.ProgramLocation loc: location to go to
        :return: true if the go to was successful
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goTo(ProgramLocation, Program)`
        """

    @typing.overload
    def goTo(self, loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program) -> bool:
        """
        Generates a GoTo event and handles any history state that needs to be saved.
         
        
        This overloaded version of :meth:`goTo(Address) <.goTo>` uses the given program as the program
        within which to perform the GoTo. If the given program does not contain the given address,
        then the GoTo will not be performed and false will be returned. Passing ``null`` as
        the ``program`` parameter will cause this method to attempt to find a program that
        contains the given ProgramLocation.
        
        :param ghidra.program.util.ProgramLocation loc: location to go to
        :param ghidra.program.model.listing.Program program: the program within which to perform the GoTo
        :return: true if the go to was successful
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goTo(ProgramLocation)`
        """

    @typing.overload
    def goTo(self, navigatable: ghidra.app.nav.Navigatable, loc: ghidra.program.util.ProgramLocation, program: ghidra.program.model.listing.Program) -> bool:
        """
        Generates a GoTo event to the given location in the given program.
        
        :param ghidra.app.nav.Navigatable navigatable: the destination navigatable
        :param ghidra.program.util.ProgramLocation loc: the location
        :param ghidra.program.model.listing.Program program: program
        :return: true if the go to was successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, navigatable: ghidra.app.nav.Navigatable, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, refAddress: ghidra.program.model.address.Address) -> bool:
        """
        Generates a GoTo event to the given address.
         
        
        The refAddress is used to determine if there is a specific symbol reference from that
        reference.
        
        :param ghidra.app.nav.Navigatable navigatable: the destination navigatable
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address address: the destination address
        :param ghidra.program.model.address.Address refAddress: the from reference address
        :return: true if the go to was successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, fromAddress: ghidra.program.model.address.Address, address: ghidra.program.model.address.Address) -> bool:
        """
        Generates a GoTo event to the given address.
         
        
        The fromAddress is used to determine if there is a specific symbol reference from the current
        address.
        
        :param ghidra.program.model.address.Address fromAddress: the current address
        :param ghidra.program.model.address.Address address: the address to goto
        :return: true if the go to was successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, navigatable: ghidra.app.nav.Navigatable, goToAddress: ghidra.program.model.address.Address) -> bool:
        """
        Generates a GoTo event to the given address for the specific navigatable.
        
        :param ghidra.app.nav.Navigatable navigatable: the destination navigatable
        :param ghidra.program.model.address.Address goToAddress: the address to goto
        :return: true if the go to was successful
        :rtype: bool
        """

    @typing.overload
    def goTo(self, goToAddress: ghidra.program.model.address.Address) -> bool:
        """
        Generates a GoTo event to the gotoAddress.
        
        :param ghidra.program.model.address.Address goToAddress: the address to goto
        :return: true if the go to was successful
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goTo(Address, Program)`
        """

    @typing.overload
    def goTo(self, goToAddress: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> bool:
        """
        Generates a GoTo event to the gotoAddress.
         
        
        This overloaded version of :meth:`goTo(Address) <.goTo>` uses the given program as the program
        within which to perform the GoTo. If the given program does not contain the given address,
        then the GoTo will not be performed and false will be returned. Passing ``null`` as
        the ``program`` parameter will cause this method to attempt to find a program that
        contains the given ProgramLocation.
        
        :param ghidra.program.model.address.Address goToAddress: the address to goto
        :param ghidra.program.model.listing.Program program: the program within which to perform the GoTo
        :return: true if the go to was successful
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.goTo(Address)`
        """

    @typing.overload
    def goToExternalLocation(self, externalLoc: ghidra.program.model.symbol.ExternalLocation, checkNavigationOption: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Navigate to either the external program location or address linkage location.
         
        
        Specific behavior may vary based upon implementation.
        
        :param ghidra.program.model.symbol.ExternalLocation externalLoc: external location
        :param jpype.JBoolean or bool checkNavigationOption: if true the service navigation option will be used to determine
                    if navigation to the external program will be attempted, or if navigation to the
                    external linkage location within the current program will be attempted. If false,
                    the implementations default behavior will be performed.
        :return: true if either navigation to the external program or to a linkage location was
                completed successfully.
        :rtype: bool
        """

    @typing.overload
    def goToExternalLocation(self, navigatable: ghidra.app.nav.Navigatable, externalLoc: ghidra.program.model.symbol.ExternalLocation, checkNavigationOption: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Navigate to either the external program location or address linkage location.
         
        
        Specific behavior may vary based upon implementation.
        
        :param ghidra.app.nav.Navigatable navigatable: Navigatable
        :param ghidra.program.model.symbol.ExternalLocation externalLoc: external location
        :param jpype.JBoolean or bool checkNavigationOption: if true the service navigation option will be used to determine
                    if navigation to the external program will be attempted, or if navigation to the
                    external linkage location within the current program will be attempted. If false,
                    the implementations default behavior will be performed.
        :return: true if either navigation to the external program or to a linkage location was
                completed successfully.
        :rtype: bool
        """

    @typing.overload
    def goToQuery(self, fromAddr: ghidra.program.model.address.Address, queryData: QueryData, listener: GoToServiceListener, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Generates a GoTo event for the given query.
         
        
        If the query results in more than one location, a list of locations will be displayed. If the
        query results in only one location, then a goto event will be fired(except for a wildcard
        query in which case a list will still be displayed.
         
        
        The listener will be notified after query and will indicate the query status.
        
        :param ghidra.program.model.address.Address fromAddr: The address used to determine the scope of the query
        :param QueryData queryData: the query input data
        :param GoToServiceListener listener: the listener that will be notified when the query completes
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the queryInput is found or appears to be a wildcard search
        :rtype: bool
        """

    @typing.overload
    def goToQuery(self, navigatable: ghidra.app.nav.Navigatable, fromAddr: ghidra.program.model.address.Address, queryData: QueryData, listener: GoToServiceListener, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Generates a GoTo event for the given query.
         
        
        If the query results in more than one location, a list of locations will be displayed. If the
        query results in only one location, then a goto event will be fired(except for a wildcard
        query in which case a list will still be displayed.
         
        
        The listener will be notified after query and will indicate the query status.
        
        :param ghidra.app.nav.Navigatable navigatable: the destination for the go to event
        :param ghidra.program.model.address.Address fromAddr: The address used to determine the scope of the query
        :param QueryData queryData: the query input data
        :param GoToServiceListener listener: the listener that will be notified when the query completes
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: true if the queryInput is found or appears to be a wildcard search
        :rtype: bool
        """

    def setOverrideService(self, override: GoToOverrideService):
        ...

    @property
    def overrideService(self) -> GoToOverrideService:
        ...

    @overrideService.setter
    def overrideService(self, value: GoToOverrideService):
        ...

    @property
    def defaultNavigatable(self) -> ghidra.app.nav.Navigatable:
        ...


class ClipboardContentProviderService(java.lang.Object):
    """
    Determines what types of transfer data can be placed on the clipboard, as well as if 
    cut, copy, and paste operations are supported
    """

    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a change listener that will be notified when the state of the service provider changes
        such that the ability to perform some actions has changed.  For example, the given
        listener will be called when a copy action can be performed when it was previously not
        possible.
        
        :param javax.swing.event.ChangeListener listener: The listener to add.
        """

    def canCopy(self) -> bool:
        """
        Returns true if the given service provider can currently perform a copy operation.
        
        :return: true if the given service provider can currently perform a copy operation.
        :rtype: bool
        """

    def canCopySpecial(self) -> bool:
        """
        Returns true if the given service provider can currently perform a 'copy special' 
        operation.
        
        :return: true if copy special is enabled
        :rtype: bool
        """

    def canPaste(self, availableFlavors: jpype.JArray[java.awt.datatransfer.DataFlavor]) -> bool:
        """
        Returns true if the service can perform a paste operation using the given transferable.
        
        :param jpype.JArray[java.awt.datatransfer.DataFlavor] availableFlavors: data flavors available for the current clipboard transferable
        :return: true if the service can perform a paste operation using the given transferable.
        :rtype: bool
        """

    def copy(self, monitor: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable:
        """
        Triggers the default copy operation
        
        :param ghidra.util.task.TaskMonitor monitor: monitor that shows progress of the copy to clipboard, and
        may be canceled
        :return: the created transferable; null if the copy was unsuccessful
        :rtype: java.awt.datatransfer.Transferable
        """

    def copySpecial(self, copyType: ghidra.app.util.ClipboardType, monitor: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable:
        """
        Triggers a special copy with the specified copy type.
        
        :param ghidra.app.util.ClipboardType copyType: contains the data flavor of the clipboard contents
        :param ghidra.util.task.TaskMonitor monitor: monitor that shows progress of the copy to clipboard, and
        may be canceled
        :return: the created transferable; null if the copy was unsuccessful
        :rtype: java.awt.datatransfer.Transferable
        """

    def customizeClipboardAction(self, action: docking.action.DockingAction):
        """
        Customize the given action.
         
         
        
        This method is called at the end of the action's constructor, which takes placed
        *before* the action is added to the provider. By default, this method does nothing.
        Likely, you will need to know which action you are customizing. Inspect the action name.
        
        :param docking.action.DockingAction action: the action
        
        .. seealso::
        
            | :obj:`.getClipboardActionOwner()`
        """

    def enableCopy(self) -> bool:
        """
        Returns true if copy should be enabled; false if it should be disabled.  This method can
        be used in conjunction with :meth:`copy(TaskMonitor) <.copy>` in order to add menu items to
        popup menus but to have them enabled when appropriate.
        
        :return: true if copy should be enabled
        :rtype: bool
        """

    def enableCopySpecial(self) -> bool:
        """
        Returns true if copySpecial actions should be enabled;
        
        :return: true if copySpecial actions should be enabled;
        :rtype: bool
        """

    def enablePaste(self) -> bool:
        """
        Returns true if paste should be enabled; false if it should be disabled.  This method can
        be used in conjunction with :meth:`paste(Transferable) <.paste>` in order to add menu items to
        popup menus but to have them enabled when appropriate.
        
        :return: true if paste should be enabled
        :rtype: bool
        """

    def getClipboardActionOwner(self) -> str:
        """
        Provide an alternative action owner.
         
         
        
        This may be necessary if the key bindings or other user-customizable attributes need to be
        separated from the standard clipboard actions. By default, the clipboard service will create
        actions with a shared owner so that one keybinding, e.g., Ctrl-C, is shared across all Copy
        actions.
        
        :return: the alternative owner, or null for the standard owner
        :rtype: str
        
        .. seealso::
        
            | :obj:`.customizeClipboardAction(DockingAction)`
        """

    def getComponentProvider(self) -> docking.ComponentProvider:
        """
        Returns the component provider associated with this service
        
        :return: the provider
        :rtype: docking.ComponentProvider
        """

    def getCurrentCopyTypes(self) -> java.util.List[ghidra.app.util.ClipboardType]:
        """
        Gets the currently active ClipboardTypes for copying with the current context
        
        :return: the types
        :rtype: java.util.List[ghidra.app.util.ClipboardType]
        """

    def isValidContext(self, context: docking.ActionContext) -> bool:
        """
        Return whether the given context is valid for actions on popup menus.
        
        :param docking.ActionContext context: the context of where the popup menu will be positioned.
        :return: true if valid
        :rtype: bool
        """

    def lostOwnership(self, transferable: java.awt.datatransfer.Transferable):
        """
        Notification that the clipboard owner has lost its ownership.
        
        :param java.awt.datatransfer.Transferable transferable: the contents which the owner had placed on the clipboard
        """

    def paste(self, pasteData: java.awt.datatransfer.Transferable) -> bool:
        """
        Triggers the default paste operation for the given transferable
        
        :param java.awt.datatransfer.Transferable pasteData: the paste transferable
        :return: true of the paste was successful
        :rtype: bool
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the given change listener.
        
        :param javax.swing.event.ChangeListener listener: The listener to remove.
        
        .. seealso::
        
            | :obj:`.addChangeListener(ChangeListener)`
        """

    @property
    def clipboardActionOwner(self) -> java.lang.String:
        ...

    @property
    def currentCopyTypes(self) -> java.util.List[ghidra.app.util.ClipboardType]:
        ...

    @property
    def componentProvider(self) -> docking.ComponentProvider:
        ...

    @property
    def validContext(self) -> jpype.JBoolean:
        ...


class StringTranslationService(java.lang.Object):
    """
    Interface for providing string translating services.
     
    
    Implementations of this interface are usually done via a Plugin
    and then registered via :obj:`Plugin`'s registerServiceProvided().
     
    
    Consumers of this service should expect multiple instance types to be returned from
    :meth:`PluginTool.getServices(Class) <PluginTool.getServices>`, and should add a service listener via
    :meth:`PluginTool.addServiceListener(ghidra.framework.plugintool.util.ServiceListener) <PluginTool.addServiceListener>`
    if service instances are retained to be notified when service instances are changed.
    """

    class TranslateOptions(java.lang.Record):
        """
        Options that are given by the callers of 
        :meth:`StringTranslationService.translate(Program, List, TranslateOptions) <StringTranslationService.translate>`.
        """

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.ClassVar[StringTranslationService.TranslateOptions]

        def __init__(self, autoTranslate: typing.Union[jpype.JBoolean, bool]):
            ...

        def autoTranslate(self) -> bool:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createStringTranslationServiceHelpLocation(pluginClass: java.lang.Class[ghidra.framework.plugintool.Plugin], sts: StringTranslationService) -> ghidra.util.HelpLocation:
        """
        Helper that creates a :obj:`HelpLocation` based on the plugin and sts.
        
        :param java.lang.Class[ghidra.framework.plugintool.Plugin] pluginClass: Plugin that provides the string translation service
        :param StringTranslationService sts: :obj:`StringTranslationService`
        :return: HelpLocation with topic equal to the plugin name and anchor something like
        "MyTranslationServiceName_String_Translation_Service".
        :rtype: ghidra.util.HelpLocation
        """

    @staticmethod
    def getCurrentStringTranslationServices(tool: ghidra.framework.plugintool.PluginTool) -> java.util.List[StringTranslationService]:
        """
        Returns a sorted list of the currently enabled StringTranslationService service providers.
        
        :param ghidra.framework.plugintool.PluginTool tool: :obj:`PluginTool`
        :return: sorted list of currently enabled StringTranslationServices
        :rtype: java.util.List[StringTranslationService]
        """

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the :obj:`HelpLocation` instance that describes where to direct the user
        for help when they hit f1.
        
        :return: :obj:`HelpLocation` instance or null.
        :rtype: ghidra.util.HelpLocation
        """

    def getTranslationServiceName(self) -> str:
        """
        Returns the name of this translation service.  Used when building menus to allow
        the user to pick a translation service.
        
        :return: string name.
        :rtype: str
        """

    def translate(self, program: ghidra.program.model.listing.Program, stringLocations: java.util.List[ghidra.program.util.ProgramLocation], options: StringTranslationService.TranslateOptions):
        """
        Requests this translation service to translate the specified string data instances.
         
        
        The implementation generally should not block when performing this action.
        
        :param ghidra.program.model.listing.Program program: the program containing the data instances.
        :param java.util.List[ghidra.program.util.ProgramLocation] stringLocations: :obj:`List` of string locations.
        :param StringTranslationService.TranslateOptions options: :obj:`TranslateOptions`
        """

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def translationServiceName(self) -> java.lang.String:
        ...


class MarkerService(java.lang.Object):
    """
    
    
    Service to manage navigation markers displayed around a scrollable window like the Listing. The
    navigation bar displays the general location of markers for the entire view. The marker bar
    displays a marker at each marked address visible within the view.
     
    
     
    
    The interface defines priorities for display of markers in Marker Margin and colored bars in
    Navigation Margin. The higher the priority, the more likely the marker/bar will be displayed on
    the top. Areas will always be lower than marker priorities.
     
    
    Recommended Usage
    
    The service used to work independently of :obj:`Program`s. In order to work effectively this
    service has been changed to associate created markers with individual programs. Thus, it is up to
    the clients of this class perform lifecycle management of markers created by this service. For
    example, a client that creates a marker from
    :meth:`createAreaMarker(String, String, Program, int, boolean, boolean, boolean, Color) <.createAreaMarker>` should
    call :meth:`removeMarker(MarkerSet, Program) <.removeMarker>` when the markers are no longer used, such as when
    a program has become deactivated. In this example usage markers are added and removed as the user
    tabs through open programs.
    """

    class_: typing.ClassVar[java.lang.Class]
    SELECTION_PRIORITY: typing.Final = 100
    """
    Display priority for marking the selection.
    """

    HIGHLIGHT_PRIORITY: typing.Final = 50
    """
    Display priority for marking the highlight.
    """

    CHANGE_PRIORITY: typing.Final = -50
    """
    Display priority for marking a change set.
    """

    GROUP_PRIORITY: typing.Final = -25
    """
    Display priority for marking a change set for members in a group.
    """

    CURSOR_PRIORITY: typing.Final = 200
    """
    Display priority for marking the cursor location.
    """

    FUNCTION_COMPARE_CURSOR_PRIORITY: typing.Final = 49
    """
    Display priority for marking the cursor location.
    """

    SEARCH_PRIORITY: typing.Final = 75
    """
    Display priority for marking locations of search hits.
    """

    BREAKPOINT_PRIORITY: typing.Final = 50
    """
    Display priority for marking locations of breakpoints.
    """

    BOOKMARK_PRIORITY: typing.Final = 0
    """
    Display priority for bookmark locations.
    """

    PROPERTY_PRIORITY: typing.Final = 75
    """
    Display priority for marking locations where a property exists.
    """

    DIFF_PRIORITY: typing.Final = 80
    """
    Display priority for marking locations where a program diff difference exists.
    """

    REFERENCE_PRIORITY: typing.Final = -10
    """
    Display priority for marking references.
    """

    HIGHLIGHT_GROUP: typing.Final = "HIGHLIGHT_GROUP"
    """
    A group name for highlights. This is intended to be used with
    :meth:`setMarkerForGroup(String, MarkerSet, Program) <.setMarkerForGroup>` and
    :meth:`removeMarkerForGroup(String, MarkerSet, Program) <.removeMarkerForGroup>`
    """


    def addChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Adds a change listener to be notified when markers are added/removed or the addresses in any
        current markerSets are changed
        
        :param javax.swing.event.ChangeListener listener: the listener
        """

    @typing.overload
    def createAreaMarker(self, name: typing.Union[java.lang.String, str], markerDescription: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int], showMarkers: typing.Union[jpype.JBoolean, bool], showNavigation: typing.Union[jpype.JBoolean, bool], colorBackground: typing.Union[jpype.JBoolean, bool], color: java.awt.Color) -> MarkerSet:
        """
        Create a Marker display which shows area type markers.
        
        :param java.lang.String or str name: name of the navigation markers
        :param java.lang.String or str markerDescription: description of the navigation markers
        :param ghidra.program.model.listing.Program program: The program with which the created markers will be associated.
        :param jpype.JInt or int priority: to sort out what displays on top, higher is more likely to be on top
        :param jpype.JBoolean or bool showMarkers: true indicates to show area markers (on the left side of the browser.)
        :param jpype.JBoolean or bool showNavigation: true indicates to show area navigation markers (on the right side of
                    the browser.)
        :param jpype.JBoolean or bool colorBackground: if true, then the browser's background color will reflect the marker.
        :param java.awt.Color color: the color of marked areas.
        :return: set of navigation markers
        :rtype: MarkerSet
        """

    @typing.overload
    def createAreaMarker(self, name: typing.Union[java.lang.String, str], markerDescription: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int], showMarkers: typing.Union[jpype.JBoolean, bool], showNavigation: typing.Union[jpype.JBoolean, bool], colorBackground: typing.Union[jpype.JBoolean, bool], color: java.awt.Color, isPreferred: typing.Union[jpype.JBoolean, bool]) -> MarkerSet:
        """
        Create a Marker display which shows area type markers.
        
        :param java.lang.String or str name: name of the navigation markers
        :param java.lang.String or str markerDescription: description of the navigation markers
        :param ghidra.program.model.listing.Program program: The program with which the created markers will be associated.
        :param jpype.JInt or int priority: to sort out what displays on top, higher is more likely to be on top
        :param jpype.JBoolean or bool showMarkers: true indicates to show area markers (on the left side of the browser.)
        :param jpype.JBoolean or bool showNavigation: true indicates to show area navigation markers (on the right side of
                    the browser.)
        :param jpype.JBoolean or bool colorBackground: if true, then the browser's background color will reflect the marker.
        :param java.awt.Color color: the color of marked areas.
        :param jpype.JBoolean or bool isPreferred: true indicates higher priority than all non-preferred MarkerSets
        :return: set of navigation markers
        :rtype: MarkerSet
        """

    def createMarginProvider(self) -> ghidra.app.plugin.core.marker.MarkerMarginProvider:
        """
        Create a new marker margin provider. The newly created provider is not added to the UI;
        clients must install the newly created provider themselves. Note that you must keep a strong
        reference to the provider, or it may not receive updates from the service.
        
        :return: the new provider
        :rtype: ghidra.app.plugin.core.marker.MarkerMarginProvider
        """

    def createOverviewProvider(self) -> ghidra.app.plugin.core.marker.MarkerOverviewProvider:
        """
        Create a new marker overview provider. The newly created provider is not added to the UI;
        clients must install the newly created provider themselves. Note that you must keep a strong
        reference to the provider, or it may not receive updates from the service.
        
        :return: the new provider
        :rtype: ghidra.app.plugin.core.marker.MarkerOverviewProvider
        """

    @typing.overload
    def createPointMarker(self, name: typing.Union[java.lang.String, str], markerDescription: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int], showMarkers: typing.Union[jpype.JBoolean, bool], showNavigation: typing.Union[jpype.JBoolean, bool], colorBackground: typing.Union[jpype.JBoolean, bool], color: java.awt.Color, icon: javax.swing.Icon) -> MarkerSet:
        """
        Create a Marker display which shows point type markers.
        
        :param java.lang.String or str name: name of the navigation markers
        :param java.lang.String or str markerDescription: description of the navigation markers
        :param ghidra.program.model.listing.Program program: The program with which the created markers will be associated.
        :param jpype.JInt or int priority: to sort out what displays on top, higher is more likely to be on top
        :param jpype.JBoolean or bool showMarkers: true indicates to show area markers (on the left side of the browser.)
        :param jpype.JBoolean or bool showNavigation: true indicates to show area navigation markers (on the right side of
                    the browser.)
        :param jpype.JBoolean or bool colorBackground: if true, then the browser's background color will reflect the marker.
        :param java.awt.Color color: the color of marked areas in navigation bar
        :param javax.swing.Icon icon: icon to display in marker bar
        :return: set of navigation markers
        :rtype: MarkerSet
        """

    @typing.overload
    def createPointMarker(self, name: typing.Union[java.lang.String, str], markerDescription: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, priority: typing.Union[jpype.JInt, int], showMarkers: typing.Union[jpype.JBoolean, bool], showNavigation: typing.Union[jpype.JBoolean, bool], colorBackground: typing.Union[jpype.JBoolean, bool], color: java.awt.Color, icon: javax.swing.Icon, isPreferred: typing.Union[jpype.JBoolean, bool]) -> MarkerSet:
        """
        Create a Marker display which shows point type markers.
        
        :param java.lang.String or str name: name of the navigation markers
        :param java.lang.String or str markerDescription: description of the navigation markers
        :param ghidra.program.model.listing.Program program: The program with which the created markers will be associated.
        :param jpype.JInt or int priority: to sort out what displays on top, higher is more likely to be on top
        :param jpype.JBoolean or bool showMarkers: true indicates to show area markers (on the left side of the browser.)
        :param jpype.JBoolean or bool showNavigation: true indicates to show area navigation markers (on the right side of
                    the browser.)
        :param jpype.JBoolean or bool colorBackground: if true, then the browser's background color will reflect the marker.
        :param java.awt.Color color: the color of marked areas in navigation bar
        :param javax.swing.Icon icon: icon to display in marker bar
        :param jpype.JBoolean or bool isPreferred: is prioritized over non-preferred MarkersSets
        :return: set of navigation markers
        :rtype: MarkerSet
        """

    def getBackgroundColor(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> java.awt.Color:
        """
        Returns the background color associated with the given program and address. Each markerSet
        that supports background coloring is blended to determine a background color for the given
        address.
        
        :param ghidra.program.model.listing.Program program: the program to check for a background color.
        :param ghidra.program.model.address.Address address: the address to check for a background color.
        :return: the background color to use for that address or null if no markers contain that
                address.
        :rtype: java.awt.Color
        """

    def getMarkerSet(self, name: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> MarkerSet:
        """
        Return the marker set with the given name;
        
        :param java.lang.String or str name: The name of the marker set for which to search
        :param ghidra.program.model.listing.Program program: The program with which the created markers will be associated.
        :return: the markerset with the given name;
        :rtype: MarkerSet
        """

    def isActiveMarkerForGroup(self, groupName: typing.Union[java.lang.String, str], markerSet: MarkerSet, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the given marker set is the current marker set for the given group.
        
        :param java.lang.String or str groupName: The group name to check
        :param MarkerSet markerSet: The marker set to check
        :param ghidra.program.model.listing.Program program: The program with which the markers are associated.
        :return: true if the given marker set is the current marker set for the given group
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setMarkerForGroup(String, MarkerSet, Program)`
        
            | :obj:`.removeMarkerForGroup(String, MarkerSet, Program)`
        """

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener):
        """
        Removes the given change listener from the list of listeners to be notified of changes
        
        :param javax.swing.event.ChangeListener listener: the listener
        """

    def removeMarker(self, markerSet: MarkerSet, program: ghidra.program.model.listing.Program):
        """
        Remove the marker set
        
        :param MarkerSet markerSet: marker set to be removed from navigation bars.
        :param ghidra.program.model.listing.Program program: The program with which the markers are associated.
        """

    def removeMarkerForGroup(self, groupName: typing.Union[java.lang.String, str], markerSet: MarkerSet, program: ghidra.program.model.listing.Program):
        """
        Removes a marker set for a given group name. If the given marker set is not the marker set
        associated with the given group name, then no action will be taken.
        
        :param java.lang.String or str groupName: The name associated the marker set with.
        :param MarkerSet markerSet: The marker set to add to this service
        :param ghidra.program.model.listing.Program program: The program with which the markers are associated
        
        .. seealso::
        
            | :obj:`.setMarkerForGroup(String, MarkerSet, Program)`
        
            | :obj:`.isActiveMarkerForGroup(String, MarkerSet, Program)`
        """

    def setMarkerClickedListener(self, listener: ghidra.app.util.viewer.listingpanel.MarkerClickedListener):
        """
        Sets the listener to be notified when the user double-clicks in the Marker Margin area. Note
        that only one listener is allowed to be set at a time. If an attempt to set a second listener
        occurs, then an IllegalStateException is thrown.
        
        :param ghidra.app.util.viewer.listingpanel.MarkerClickedListener listener: the listener to be notified or null to remove the current listener
        :raises IllegalStateException: if a listener is already set.
        """

    def setMarkerForGroup(self, groupName: typing.Union[java.lang.String, str], markerSet: MarkerSet, program: ghidra.program.model.listing.Program):
        """
        Sets a marker set for a given group name. Any previous marker set associated with the given
        group name will be removed from this marker service. This method is used to ensure that only
        one marker set is used at any time for a give group.
        
        :param java.lang.String or str groupName: The name to associate the marker set with.
        :param MarkerSet markerSet: The marker set to add to this service
        :param ghidra.program.model.listing.Program program: The program with which the markers are associated.
        
        .. seealso::
        
            | :obj:`.removeMarkerForGroup(String, MarkerSet, Program)`
        """


class StringValidatorService(java.lang.Object):
    """
    A service that judges the validity of a string
    """

    class DummyStringValidator(StringValidatorService):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    DUMMY: typing.Final[StringValidatorService]

    @staticmethod
    def getCurrentStringValidatorServices(tool: ghidra.framework.plugintool.PluginTool) -> java.util.List[StringValidatorService]:
        """
        Returns a list of string validator services
        
        :param ghidra.framework.plugintool.PluginTool tool: :obj:`PluginTool`
        :return: list of services
        :rtype: java.util.List[StringValidatorService]
        """

    def getStringValidityScore(self, query: StringValidatorQuery) -> StringValidityScore:
        """
        Judges a string (specified in the query instance).
        
        :param StringValidatorQuery query: :obj:`StringValidatorQuery`
        :return: :obj:`StringValidityScore`
        :rtype: StringValidityScore
        """

    def getValidatorServiceName(self) -> str:
        """
        Returns the name of the service
        
        :return: 
        :rtype: str
        """

    @property
    def validatorServiceName(self) -> java.lang.String:
        ...

    @property
    def stringValidityScore(self) -> StringValidityScore:
        ...


class DataTypeManagerService(DataTypeQueryService, DataTypeArchiveService):
    """
    Service to provide list of cycle groups and data types identified as
    "favorites." Favorites will show up on the popup menu for creating
    data and defining function return types and parameters.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener):
        """
        Adds a listener to be notified when changes occur to any open datatype manager.
        
        :param ghidra.program.model.data.DataTypeManagerChangeListener listener: the listener to be added.
        """

    @typing.overload
    def edit(self, dt: ghidra.program.model.data.DataType):
        """
        Pop up an editor window for the given data type.
        
        :param ghidra.program.model.data.DataType dt: the data type; built in types cannot be edited
        :raises IllegalArgumentException: if the given has not been resolved by a DataTypeManager;
                in other words, if :meth:`DataType.getDataTypeManager() <DataType.getDataTypeManager>` returns null
        """

    @typing.overload
    def edit(self, composite: ghidra.program.model.data.Composite, fieldName: typing.Union[java.lang.String, str]):
        """
        Pop up an editor window for the given structure or union
        
        :param ghidra.program.model.data.Composite composite: the structure or union
        :param java.lang.String or str fieldName: the optional field name to select in the editor window
        :raises IllegalArgumentException: if the given has not been resolved by a DataTypeManager;
                in other words, if :meth:`DataType.getDataTypeManager() <DataType.getDataTypeManager>` returns null
        """

    def getCategoryPath(self, selectedPath: javax.swing.tree.TreePath) -> ghidra.program.model.data.CategoryPath:
        """
        Shows the user a dialog that allows them to choose a category path from a tree of all 
        available categories.
        
        :param javax.swing.tree.TreePath selectedPath: An optional tree path to select in the tree
        :return: A category path chosen by the user
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getDataType(self, selectedPath: javax.swing.tree.TreePath) -> ghidra.program.model.data.DataType:
        """
        Shows the user a dialog that allows them to choose a data type from a tree of all available
        data types.
        
        :param javax.swing.tree.TreePath selectedPath: An optional tree path to select in the tree
        :return: A data type chosen by the user
        :rtype: ghidra.program.model.data.DataType
        """

    def getEditorHelpLocation(self, dataType: ghidra.program.model.data.DataType) -> ghidra.util.HelpLocation:
        """
        Gets the location of the help for editing the specified data type.
        
        :param ghidra.program.model.data.DataType dataType: the data type to be edited.
        :return: the help location for editing the data type.
        :rtype: ghidra.util.HelpLocation
        """

    def getFavorites(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Get the data types marked as favorites that will show up on
        a popup menu.
        
        :return: list of favorite datatypes
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def getPossibleEquateNames(self, value: typing.Union[jpype.JLong, int]) -> java.util.Set[java.lang.String]:
        """
        Examines all enum dataTypes for items that match the given value. Returns a list of Strings
        that might make sense for the given value.
        
        :param jpype.JLong or int value: the value to search for.
        :return: the list of enum item names that match the given value
        :rtype: java.util.Set[java.lang.String]
        """

    def getRecentlyUsed(self) -> ghidra.program.model.data.DataType:
        """
        Get the data type that was most recently used to apply data to a
        Program.
        
        :return: data type that was most recently used
        :rtype: ghidra.program.model.data.DataType
        """

    def getSelectedDatatypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Returns the list of data types that are currently selected in the data types tree
        
        :return: the list of data types that are currently selected in the data types tree
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def isEditable(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the indicated data type can be edited 
        (i.e. it has an editor that this service knows how to invoke).
        
        :param ghidra.program.model.data.DataType dt: data type to be edited
        :return: true if this service can invoke an editor for changing the data type.
        :rtype: bool
        """

    def removeDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener):
        """
        Removes the given listener from receiving dataTypeManger change notifications.
        
        :param ghidra.program.model.data.DataTypeManagerChangeListener listener: the listener to be removed.
        """

    def setCategorySelected(self, category: ghidra.program.model.data.Category):
        """
        Selects the given data type category in the tree of data types.  This method will cause the
        data type tree to come to the front, scroll to the category and then to select the tree
        node that represents the category.  If the category is null, the selection is cleared.
        
        :param ghidra.program.model.data.Category category: the category to select; may be null
        """

    def setDataTypeSelected(self, dataType: ghidra.program.model.data.DataType):
        """
        Selects the given data type in the display of data types.  A null ``dataType``
        value will clear the current selection.
        
        :param ghidra.program.model.data.DataType dataType: The data type to select.
        """

    def setRecentlyUsed(self, dt: ghidra.program.model.data.DataType):
        """
        Set the given data type as the most recently used to apply a
        data type to a Program.
        
        :param ghidra.program.model.data.DataType dt: data type that was most recently used
        """

    @property
    def favorites(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...

    @property
    def editorHelpLocation(self) -> ghidra.util.HelpLocation:
        ...

    @property
    def selectedDatatypes(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...

    @property
    def editable(self) -> jpype.JBoolean:
        ...

    @property
    def categoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def recentlyUsed(self) -> ghidra.program.model.data.DataType:
        ...

    @recentlyUsed.setter
    def recentlyUsed(self, value: ghidra.program.model.data.DataType):
        ...

    @property
    def possibleEquateNames(self) -> java.util.Set[java.lang.String]:
        ...


class DataTypeReference(java.lang.Object):
    """
    A container class to hold information about a location that references a :obj:`DataType`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str], function: ghidra.program.model.listing.Function, address: ghidra.program.model.address.Address, context: ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getContext(self) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def context(self) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext:
        ...


class AnalysisPriority(java.lang.Object):
    """
    Class to specify priority within the Automated Analysis pipeline.
    """

    class_: typing.ClassVar[java.lang.Class]
    FORMAT_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines a full format analysis as the first priority for automatic analysis.
    These are the first analyzers that will run after import.
    Possibly there is a need to move blocks around, or create headers.
    Analyzers that will look binary as a full file format analysis
    should run with this priority.
     
    NOTE: there may be analyzers that run before this that need to fix issues like Non-Returning
    functions.  Be very careful running an analyzer with a higher priority.
    """

    BLOCK_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines block analysis as the second priority for automatic analysis.
    Initial markup of raw bytes should occur at or after this priority (images, etc).
    The initial disassembly of EntryPoints will occur at this priority.
    """

    DISASSEMBLY: typing.Final[AnalysisPriority]
    """
    Defines disassembly as the third priority for automatic analysis.
    Disassembly of code found through good solid flow will occur at this priority.
    More heuristic code recovery will occur later.
    """

    CODE_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines code analysis as the fourth priority for automatic analysis.
    If your analyzer is looking at RAW CODE, you should general go at or after this
    priority.  Usually this is used in conjunction with analyzers that process new
    instructions ``AnalyzerType.INSTRUCTIONS``.  It is also useful for
    those analyzers that depend on code, but want to analyze flow, such as non-returning
    functions, that should happen before functions are widely laid down.  If
    bad flow is not fixed at an early priority, switch statement recovery, function
    boundaries, etc... may need to be redone and bad stuff cleaned up.
    """

    FUNCTION_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines function analysis as the fifth priority for automatic analysis.
    After this priority, basic functions and their instructions should be recovered.
    More functions could be recovered in further analysis, but if your analysis
    depends on basic function creation, you should go after this priority.
    """

    REFERENCE_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines reference analysis as the sixth priority for automatic analysis.
    After this priority, basic reference recovery should have taken place.
    More references could be recovered later.
    """

    DATA_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines data analysis as the seventh priority for automatic analysis.
    After this priority, data creation (strings, pointers) should have settled down.
    More data can be recovered with further analysis.
    """

    FUNCTION_ID_ANALYSIS: typing.Final[AnalysisPriority]
    """
    Defines Function identification analysis as the eighth priority for automatic analysis.
    After this priority, full function (name/class) evaluation should have taken place.
    """

    DATA_TYPE_PROPOGATION: typing.Final[AnalysisPriority]
    """
    Defines data type propagation as the ninth priority for automatic analysis.
    Data type propagation analysis should happen as late as possible so that all basic code
    recovery, reference analysis, etc... has taken place.
    """

    LOW_PRIORITY: typing.Final[AnalysisPriority]
    HIGHEST_PRIORITY: typing.Final[AnalysisPriority]

    @typing.overload
    def __init__(self, priority: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], priority: typing.Union[jpype.JInt, int]):
        """
        Construct a new priority object.
        
        :param java.lang.String or str name: the name
        :param jpype.JInt or int priority: priority to use
        """

    def after(self) -> AnalysisPriority:
        """
        Get a priority that is a little lower than this one.
        
        :return: a lower priority
        :rtype: AnalysisPriority
        """

    def before(self) -> AnalysisPriority:
        """
        Get a priority that is a little higher than this one.
        
        :return: a higher priority
        :rtype: AnalysisPriority
        """

    @staticmethod
    def getInitial(name: typing.Union[java.lang.String, str]) -> AnalysisPriority:
        """
        Return first gross priority.
        
        :param java.lang.String or str name: the name
        :return: first gross priority
        :rtype: AnalysisPriority
        """

    def getNext(self, nextName: typing.Union[java.lang.String, str]) -> AnalysisPriority:
        """
        Get the next gross priority.
        
        :param java.lang.String or str nextName: the next name
        :return: return next gross priority
        :rtype: AnalysisPriority
        """

    def priority(self) -> int:
        """
        Return the priority specified for this analysis priority.
        
        :return: the priority specified for this analysis priority.
        :rtype: int
        """

    @property
    def next(self) -> AnalysisPriority:
        ...


class FieldMouseHandlerService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addFieldMouseHandler(self, handler: ghidra.app.util.viewer.field.FieldMouseHandler):
        ...


class MarkerDescriptor(java.lang.Object):
    """
    Allows clients to specify how :obj:`MarkerLocation`s are navigated, as well as how they 
    should be painted
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getIcon(self, loc: ghidra.program.util.MarkerLocation) -> javax.swing.ImageIcon:
        """
        Called to get the icon that corresponds to the given location
        
        :param ghidra.program.util.MarkerLocation loc: the marker location
        :return: the icon; may be null
        :rtype: javax.swing.ImageIcon
        """

    def getProgramLocation(self, loc: ghidra.program.util.MarkerLocation) -> ghidra.program.util.ProgramLocation:
        """
        Called when the navigation bar to the right of the window is clicked to allow the 
        creator of a Marker an opportunity to provide a more specific ProgramLocation for
        navigation. If null is specified, the client will navigate to the corresponding address.
        
        :param ghidra.program.util.MarkerLocation loc: the marker location
        :return: the desired location; may be null
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getTooltip(self, loc: ghidra.program.util.MarkerLocation) -> str:
        """
        Called to get a tool tip for a marker under the cursor in the marker panel
        
        :param ghidra.program.util.MarkerLocation loc: the marker location
        :return: the tooltip; may be null
        :rtype: str
        """

    @property
    def tooltip(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class DataService(java.lang.Object):
    """
    Service for creating data
    """

    class_: typing.ClassVar[java.lang.Class]

    def createData(self, dt: ghidra.program.model.data.DataType, context: ghidra.app.context.ListingActionContext, stackPointers: typing.Union[jpype.JBoolean, bool], enableConflictHandling: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Apply the given data type at a location.
        
        :param ghidra.program.model.data.DataType dt: data type to create at the location
        :param ghidra.app.context.ListingActionContext context: the context containing program, location, and selection information
        :param jpype.JBoolean or bool stackPointers: if true, and supported, and the existing context-specified data is a 
        pointer, the specified datatype should be stacked onto the existing pointer if permitted.
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        :param jpype.JBoolean or bool enableConflictHandling: if true, the service may prompt the user to resolve data 
                conflicts
        :return: true if the data could be created at the current location
        :rtype: bool
        """

    def isCreateDataAllowed(self, context: ghidra.app.context.ListingActionContext) -> bool:
        """
        Determine if create data is permitted on the specified location. If the
        location is contained within the current program selection, the entire
        selection is examined.
        
        :param ghidra.app.context.ListingActionContext context: the context containing program, location, and selection information
        :return: true if create data is allowed, else false.
        :rtype: bool
        """

    @property
    def createDataAllowed(self) -> jpype.JBoolean:
        ...


class MarkerSet(java.lang.Comparable[MarkerSet]):
    """
    Defines methods for working with a set of addresses that correspond to markers.
    
    
    .. seealso::
    
        | :obj:`MarkerService`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, addr: ghidra.program.model.address.Address):
        """
        Add a marker at the address
        
        :param ghidra.program.model.address.Address addr: the address
        """

    @typing.overload
    def add(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Add the range given the start and end of the range
        
        :param ghidra.program.model.address.Address start: the start address
        :param ghidra.program.model.address.Address end: the end address
        """

    @typing.overload
    def add(self, range: ghidra.program.model.address.AddressRange):
        """
        Add a marker across the address range
        
        :param ghidra.program.model.address.AddressRange range: the addresses
        """

    @typing.overload
    def add(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Add a marker at each address in the given address set
        
        :param ghidra.program.model.address.AddressSetView addrSet: the addresses
        """

    @typing.overload
    def clear(self, addr: ghidra.program.model.address.Address):
        """
        Clear any marker at the address
        
        :param ghidra.program.model.address.Address addr: the address
        """

    @typing.overload
    def clear(self, range: ghidra.program.model.address.AddressRange):
        """
        Clear any marker across the address range
        
        :param ghidra.program.model.address.AddressRange range: the addresses
        """

    @typing.overload
    def clear(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Remove the given range from the marker set
        
        :param ghidra.program.model.address.Address start: the start of the range to remove
        :param ghidra.program.model.address.Address end: the end of the range to remove
        """

    @typing.overload
    def clear(self, addrSet: ghidra.program.model.address.AddressSetView):
        """
        Clear any marker at each address in the address set
        
        :param ghidra.program.model.address.AddressSetView addrSet: the addresses
        """

    def clearAll(self):
        """
        Clear all defined markers
        """

    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if this marker set contains the specified address
        
        :param ghidra.program.model.address.Address addr: address
        :return: true if marker set contains addr
        :rtype: bool
        """

    def displayInMarkerBar(self) -> bool:
        """
        True if this marker manager displays in the left hand marker bar
        
        :return: true if this marker manager displays in the left hand marker bar
        :rtype: bool
        """

    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Return the address set for this marker set
        
        :return: the addresses
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getMarkerColor(self) -> java.awt.Color:
        """
        Get the color for the marker
        
        :return: the color
        :rtype: java.awt.Color
        """

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the maximum Address in this MarkerSet;
        
        :return: the maximum Address in this MarkerSet;
        :rtype: ghidra.program.model.address.Address
        """

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the minimum Address in this MarkerSet;
        
        :return: the minimum Address in this MarkerSet;
        :rtype: ghidra.program.model.address.Address
        """

    def getName(self) -> str:
        """
        Return the name of this MarkerSet
        
        :return: the name
        :rtype: str
        """

    def getPriority(self) -> int:
        """
        Get display priority
        
        :return: the priority
        :rtype: int
        """

    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if any address in this MarkerSet is contained in the range defined by
        start and end.
        
        :param ghidra.program.model.address.Address start: the start address of the range to check for intersection.
        :param ghidra.program.model.address.Address end: the end address of the range to check for intersection.
        :return: true if the set of addresses contained in this MarkerSet intersects the given range.
        :rtype: bool
        """

    def isActive(self) -> bool:
        """
        Returns true if this MarkerSet is active.  Being "active" means that it is displayed
        in the listing
        
        :return: true if active
        :rtype: bool
        """

    def isColoringBackground(self) -> bool:
        """
        Returns true if this MarkerSet is coloring the background in the listing for locations
        contained in this MarkerSet
        
        :return: true if coloring background
        :rtype: bool
        """

    def isDisplayedInNavigationBar(self) -> bool:
        """
        True if this marker manager displays in the right hand navigation bar
        
        :return: true if this marker manager displays in the right hand navigation bar
        :rtype: bool
        """

    def isPreferred(self) -> bool:
        """
        Gets whether this marker is in the preferred group when determining display priority.
        Typically point markers are in the preferred group and area markers are not.
        
        :return: true if preferred
        :rtype: bool
        """

    def setActive(self, state: typing.Union[jpype.JBoolean, bool]):
        """
        Return true if this marker set is active
        
        :param jpype.JBoolean or bool state: the state
        """

    def setAddressSet(self, set: ghidra.program.model.address.AddressSetView):
        """
        Clears the current set off addresses in this markerSet and adds in the addresses
        from the given AddressSet
        
        :param ghidra.program.model.address.AddressSetView set: the set of addresses to use in this marker set
        """

    def setAddressSetCollection(self, set: ghidra.program.model.address.AddressSetCollection):
        """
        Sets the AddressSetCollection to be used for this marker set.
          
         
        **Warning!** 
        Using this method will cause this MarkerSet to directly use the given AddressSetCollection.
        If the given AddressSetCollection is not an instance of ModifiableAddressSetCollection,
        then the markerSet methods that add and remove addresses will thrown an
        IllegalArgumentException.
        
        :param ghidra.program.model.address.AddressSetCollection set: the addressSetCollection to use as this markerSet's addressSetCollection.
        """

    def setColoringBackground(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not the MarkerSet is coloring the background of areas in the listing
        contained in this MarkerSet.
        
        :param jpype.JBoolean or bool b: true to color the background.
        """

    def setMarkerColor(self, color: java.awt.Color):
        """
        Set the color for the marker
        
        :param java.awt.Color color: marker color
        """

    def setMarkerDescriptor(self, markerDescriptor: MarkerDescriptor):
        """
        Set the marker manager listener to use for user interaction
        with markers owned by this manager.
        
        :param MarkerDescriptor markerDescriptor: the descriptor
        """

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def markerColor(self) -> java.awt.Color:
        ...

    @markerColor.setter
    def markerColor(self, value: java.awt.Color):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def active(self) -> jpype.JBoolean:
        ...

    @active.setter
    def active(self, value: jpype.JBoolean):
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...

    @property
    def preferred(self) -> jpype.JBoolean:
        ...

    @property
    def displayedInNavigationBar(self) -> jpype.JBoolean:
        ...

    @property
    def coloringBackground(self) -> jpype.JBoolean:
        ...

    @coloringBackground.setter
    def coloringBackground(self, value: jpype.JBoolean):
        ...


class ConsoleService(java.lang.Object):
    """
    Generic console interface allowing any plugin to print
    messages to console window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addErrorMessage(self, originator: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Appends an error message to the console text area.
        The message should be rendered is such a way as to denote
        that it is an error. For example, display in "red".
        
        :param java.lang.String or str originator: a descriptive name of the message creator
        :param java.lang.String or str message: the message to appear in the console
        """

    def addException(self, originator: typing.Union[java.lang.String, str], exc: java.lang.Exception):
        """
        Appends an exception to the console text area.
        
        :param java.lang.String or str originator: a descriptive name of the message creator
        :param java.lang.Exception exc: the exception
        """

    def addMessage(self, originator: typing.Union[java.lang.String, str], message: typing.Union[java.lang.String, str]):
        """
        Appends message to the console text area.
         
        For example:
            "originator> message"
        
        :param java.lang.String or str originator: a descriptive name of the message creator
        :param java.lang.String or str message: the message to appear in the console
        """

    def clearMessages(self):
        """
        Clears all messages from the console.
        """

    def getStdErr(self) -> java.io.PrintWriter:
        """
        Returns a print writer object to use as standard error.
        
        :return: a print writer object to use as standard error
        :rtype: java.io.PrintWriter
        """

    def getStdOut(self) -> java.io.PrintWriter:
        """
        Returns a print writer object to use as standard output.
        
        :return: a print writer object to use as standard output
        :rtype: java.io.PrintWriter
        """

    def getText(self, offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> str:
        """
        Fetches the text contained within the given portion 
        of the console.
         
        Please note:
        Support for this method is optional
        based on the underlying console
        implementation. If this method cannot be supported,
        please throw :obj:`UnsupportedOperationException`.
        
        :param jpype.JInt or int offset: the offset into the console representing the desired start of the text >= 0
        :param jpype.JInt or int length: the length of the desired string >= 0
        :return: the text, in a String of length >= 0
        :rtype: str
        """

    def getTextLength(self) -> int:
        """
        Returns number of characters of currently 
        in the console.
        If the console is cleared, this number is reset.
         
        Please note:
        Support for this method is optional
        based on the underlying console
        implementation. If this method cannot be supported,
        please throw :obj:`UnsupportedOperationException`.
        
        :return: number of characters >= 0
        :rtype: int
        """

    def print(self, msg: typing.Union[java.lang.String, str]):
        """
        Prints the message into the console.
        
        :param java.lang.String or str msg: the messages to print into the console
        """

    def printError(self, errmsg: typing.Union[java.lang.String, str]):
        """
        Prints the error message into the console.
        It will be displayed in red.
        
        :param java.lang.String or str errmsg: the error message to print into the console
        """

    def println(self, msg: typing.Union[java.lang.String, str]):
        """
        Prints the messages into the console followed by a line feed.
        
        :param java.lang.String or str msg: the message to print into the console
        """

    def printlnError(self, errmsg: typing.Union[java.lang.String, str]):
        """
        Prints the error message into the console followed by a line feed.
        It will be displayed in red.
        
        :param java.lang.String or str errmsg: the error message to print into the console
        """

    @property
    def stdOut(self) -> java.io.PrintWriter:
        ...

    @property
    def textLength(self) -> jpype.JInt:
        ...

    @property
    def stdErr(self) -> java.io.PrintWriter:
        ...


class VSCodeIntegrationService(java.lang.Object):
    """
    Service that provides Visual Studio Code-related functionality
    """

    class_: typing.ClassVar[java.lang.Class]

    def addToVSCodeWorkspace(self, workspaceFile: jpype.protocol.SupportsPath, projectDir: jpype.protocol.SupportsPath):
        """
        Adds the given project directory to the given Visual Studio Code workspace file
        A new workspace will be created if it doesn't already exist
        
        :param jpype.protocol.SupportsPath workspaceFile: The location of the workspace file
        :param jpype.protocol.SupportsPath projectDir: An existing project directory to add to the workspace
        :raises IOException: if the directory failed to be created
        """

    def createVSCodeModuleProject(self, projectDir: jpype.protocol.SupportsPath):
        """
        Creates a new Visual Studio Code module project at the given directory
        
        :param jpype.protocol.SupportsPath projectDir: The new directory to create
        :raises IOException: if the directory failed to be created
        """

    def getVSCodeExecutableFile(self) -> java.io.File:
        """
        :return: the Visual Studio Code executable file
        :rtype: java.io.File
        
        
        :raises FileNotFoundException: if the executable file does not exist
        """

    def getVSCodeIntegrationOptions(self) -> ghidra.framework.options.ToolOptions:
        """
        :return: the Visual Studio Code Integration options
        :rtype: ghidra.framework.options.ToolOptions
        """

    def handleVSCodeError(self, error: typing.Union[java.lang.String, str], askAboutOptions: typing.Union[jpype.JBoolean, bool], t: java.lang.Throwable):
        """
        Displays the given Visual Studio Code related error message in an error dialog
        
        :param java.lang.String or str error: The error message to display in a dialog
        :param jpype.JBoolean or bool askAboutOptions: True if we should ask the user if they want to be taken to the Visual
        Studio Code options; otherwise, false
        :param java.lang.Throwable t: An optional throwable to tie to the message
        """

    def launchVSCode(self, file: jpype.protocol.SupportsPath):
        """
        Launches Visual Studio Code
        
        :param jpype.protocol.SupportsPath file: The initial file to open in Visual Studio Code
        """

    @property
    def vSCodeIntegrationOptions(self) -> ghidra.framework.options.ToolOptions:
        ...

    @property
    def vSCodeExecutableFile(self) -> java.io.File:
        ...


class ButtonPressedListener(java.lang.Object):
    """
    Listener that is notified when a mouse button is pressed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def buttonPressed(self, location: ghidra.program.util.ProgramLocation, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation, field: ghidra.app.util.viewer.field.ListingField, event: java.awt.event.MouseEvent):
        """
        Notification that a mouse button was pressed.
        
        :param ghidra.program.util.ProgramLocation location: program location when the button was pressed
        :param docking.widgets.fieldpanel.support.FieldLocation fieldLocation: locations within the FieldPanel
        :param ghidra.app.util.viewer.field.ListingField field: field from the ListingPanel
        :param java.awt.event.MouseEvent event: mouse event for the button pressed
        """


class CodeFormatService(java.lang.Object):
    """
    Service provided by a plugin that gives access to a manager for the field formats used by a 
    listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFormatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    @property
    def formatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...


class ViewManagerService(ViewService):
    """
    Service to manage generic views; the view controls what shows up in the code
    browser.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCurrentViewProvider(self) -> ghidra.app.plugin.core.programtree.ViewProviderService:
        """
        Get the current view provider.
        """

    def setCurrentViewProvider(self, viewName: typing.Union[java.lang.String, str]):
        """
        Set the current view to the provider with the given name.
        
        :param java.lang.String or str viewName:
        """

    def viewNameChanged(self, vps: ghidra.app.plugin.core.programtree.ViewProviderService, oldName: typing.Union[java.lang.String, str]):
        """
        Notification that a view name has changed.
        
        :param ghidra.app.plugin.core.programtree.ViewProviderService vps: service whose name has changed
        :param java.lang.String or str oldName: old name of the service
        """

    @property
    def currentViewProvider(self) -> ghidra.app.plugin.core.programtree.ViewProviderService:
        ...


class GraphDisplayBroker(java.lang.Object):
    """
    Ghidra service interface for managing and directing graph output.  It purpose is to discover
    available graphing display providers and (if more than one) allow the user to select the
    currently active graph consumer.  Clients that generate graphs don't have to worry about how to
    display them or export graphs. They simply send their graphs to the broker and register for graph
    events if they want interactive support.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addGraphDisplayBrokerListener(self, listener: ghidra.app.plugin.core.graph.GraphDisplayBrokerListener):
        """
        Adds a listener for notification when the set of graph display providers change or the currently
        active graph display provider changes
        
        :param ghidra.app.plugin.core.graph.GraphDisplayBrokerListener listener: the listener to be notified
        """

    def getDefaultGraphDisplay(self, reuseGraph: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.service.graph.GraphDisplay:
        """
        A convenience method for getting a :obj:`GraphDisplay` from the currently active provider.
        This method is intended to be used to display a new graph.
        
        :param jpype.JBoolean or bool reuseGraph: if true, the provider will attempt to re-use a current graph display
        :param ghidra.util.task.TaskMonitor monitor: the :obj:`TaskMonitor` that can be used to cancel the operation
        :return: a :obj:`GraphDisplay` object to sends graphs to be displayed or exported.
        :rtype: ghidra.service.graph.GraphDisplay
        :raises GraphException: thrown if an error occurs trying to get a graph display
        """

    def getDefaultGraphDisplayProvider(self) -> ghidra.service.graph.GraphDisplayProvider:
        """
        Gets the currently active GraphDisplayProvider that will be used to display/export graphs
        
        :return: the currently active GraphDisplayProvider
        :rtype: ghidra.service.graph.GraphDisplayProvider
        """

    def getGraphDisplayProvider(self, name: typing.Union[java.lang.String, str]) -> ghidra.service.graph.GraphDisplayProvider:
        """
        Gets the :obj:`GraphDisplayProvider` with the given name
        
        :param java.lang.String or str name: the name of the GraphDisplayProvider to get
        :return: the GraphDisplayProvider with the given name or null if none with that name exists.
        :rtype: ghidra.service.graph.GraphDisplayProvider
        """

    @typing.overload
    def getGraphExporters(self) -> java.util.List[ghidra.service.graph.AttributedGraphExporter]:
        """
        Returns a list of all discovered :obj:`AttributedGraphExporter`.
        
        :return: a list of all discovered :obj:`AttributedGraphExporter`.
        :rtype: java.util.List[ghidra.service.graph.AttributedGraphExporter]
        """

    @typing.overload
    def getGraphExporters(self, name: typing.Union[java.lang.String, str]) -> ghidra.service.graph.AttributedGraphExporter:
        """
        Returns the :obj:`AttributedGraphExporter` with the given name or null in no exporter with
        that name is known
        
        :param java.lang.String or str name: the name of the exporter to retrieve
        :return: the :obj:`AttributedGraphExporter` with the given name or null if no exporter with
        that name is known
        :rtype: ghidra.service.graph.AttributedGraphExporter
        """

    def hasDefaultGraphDisplayProvider(self) -> bool:
        """
        Checks if there is at least one :obj:`GraphDisplayProvider` in the system.
        
        :return: true if there is at least one :obj:`GraphDisplayProvider`
        :rtype: bool
        """

    def removeGraphDisplayBrokerLisetener(self, listener: ghidra.app.plugin.core.graph.GraphDisplayBrokerListener):
        """
        Removes the given listener
        
        :param ghidra.app.plugin.core.graph.GraphDisplayBrokerListener listener: the listener to no longer be notified of changes
        """

    @property
    def graphDisplayProvider(self) -> ghidra.service.graph.GraphDisplayProvider:
        ...

    @property
    def graphExporters(self) -> java.util.List[ghidra.service.graph.AttributedGraphExporter]:
        ...

    @property
    def defaultGraphDisplayProvider(self) -> ghidra.service.graph.GraphDisplayProvider:
        ...


class BlockModelService(java.lang.Object):
    """
    Service for providing block models.
    """

    class_: typing.ClassVar[java.lang.Class]
    BASIC_MODEL: typing.Final = 1
    """
    Type for a simple block model.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.model.block.SimpleBlockModel`
    """

    SUBROUTINE_MODEL: typing.Final = 2
    """
    Type for a subroutine block model.
    """

    SIMPLE_BLOCK_MODEL_NAME: typing.Final = "Simple Block"
    """
    Name of the implementation for a Simple block model.
    """

    MULTI_ENTRY_SUBROUTINE_MODEL_NAME: typing.Final = "Multiple Entry"
    """
    Name of the implementation for a subroutine with multiple entry points.
    """

    ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME: typing.Final = "Isolated Entry"
    """
    Name of the implementation for a subroutine that has a unique entry
    point, which may share code with other subroutines.
    """

    OVERLAPPED_SUBROUTINE_MODEL_NAME: typing.Final = "Overlapped Code"
    """
    Name of the implementation for an overlapped subroutine model.
    """

    PARTITIONED_SUBROUTINE_MODEL_NAME: typing.Final = "Partitioned Code"
    """
    Name of the implementation for a subroutine that does not share code
    with other subroutines and may have one or more entry points.
    """

    DEFAULT_BLOCK_MODEL_NAME: typing.Final = "Simple Block"
    """
    Default basic block model (Simple Block Model)
    """

    DEFAULT_SUBROUTINE_MODEL_NAME: typing.Final = "Multiple Entry"
    """
    Default subroutine model (M-Model)
    """


    def addListener(self, listener: BlockModelServiceListener):
        """
        Add service listener.
        
        :param BlockModelServiceListener listener: listener to add
        """

    @typing.overload
    @deprecated("use getActiveBlockModel(Program) instead")
    def getActiveBlockModel(self) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Basic Block model for the current program.
        
        :return: new Basic Block model instance or null if program is not open.
        :rtype: ghidra.program.model.block.CodeBlockModel
        
        .. deprecated::
        
        use getActiveBlockModel(Program) instead
        """

    @typing.overload
    @deprecated("use getActiveBlockModel(Program, boolean) instead")
    def getActiveBlockModel(self, includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Basic Block model for the current program.
        
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new Basic Block model instance or null if program is not open.
        :rtype: ghidra.program.model.block.CodeBlockModel
        
        .. deprecated::
        
        use getActiveBlockModel(Program, boolean) instead
        """

    @typing.overload
    def getActiveBlockModel(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Basic Block model.
        
        :param ghidra.program.model.listing.Program program: program to associate with the block model
        :return: new Basic Block model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        """

    @typing.overload
    def getActiveBlockModel(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Basic Block model.
        
        :param ghidra.program.model.listing.Program program: program to associate with the block model
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new Basic Block model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        """

    def getActiveBlockModelName(self) -> str:
        """
        Get the name of the active Basic Block model.
        
        :return: active block model name
        :rtype: str
        """

    @typing.overload
    @deprecated("use getActiveSubroutineModel(Program) instead")
    def getActiveSubroutineModel(self) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Subroutine Block model for the current program.
        
        :return: new Subroutine Block model instance or null if program is not open
        :rtype: ghidra.program.model.block.CodeBlockModel
        
        .. deprecated::
        
        use getActiveSubroutineModel(Program) instead
        """

    @typing.overload
    @deprecated("use getActiveSubroutineModel(Program) instead")
    def getActiveSubroutineModel(self, includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Subroutine Block model for the current program.
        
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new Subroutine Block model instance or null if program is not open
        :rtype: ghidra.program.model.block.CodeBlockModel
        
        .. deprecated::
        
        use getActiveSubroutineModel(Program) instead
        """

    @typing.overload
    def getActiveSubroutineModel(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Subroutine Block model.
        
        :param ghidra.program.model.listing.Program program: program associated with the block model.
        :return: new Subroutine Block model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        """

    @typing.overload
    def getActiveSubroutineModel(self, program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the active Subroutine Block model.
        
        :param ghidra.program.model.listing.Program program: program associated with the block model.
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new Subroutine Block model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        """

    def getActiveSubroutineModelName(self) -> str:
        """
        Get the name of the active Subroutine model.
        
        :return: active subroutine model name
        :rtype: str
        """

    def getAvailableModelNames(self, modelType: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.String]:
        """
        Get list of registered block models of the specified type.
        A modelType of ANY_BLOCK will return all models registered.
        List ordering is based upon the registration order.
        It is important to recognize that the list of returned names
        could change as models are registered and unregistered.
        
        :param jpype.JInt or int modelType: type of model (ANY_MODEL, BASIC_MODEL or SUBROUTINE_MODEL)
        :return: array of model names
        :rtype: jpype.JArray[java.lang.String]
        """

    @typing.overload
    @deprecated("use getNewModelByName(String, Program) instead")
    def getNewModelByName(self, modelName: typing.Union[java.lang.String, str]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the specified block model.
        
        :param java.lang.String or str modelName: name of registered block model
        :return: new model instance or null if program is not open.
        :rtype: ghidra.program.model.block.CodeBlockModel
        :raises NotFoundException: if specified model is not registered
        
        .. deprecated::
        
        use getNewModelByName(String, Program) instead
        """

    @typing.overload
    @deprecated("use getNewModelByName(String, Program, boolean) instead")
    def getNewModelByName(self, modelName: typing.Union[java.lang.String, str], includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the specified block model.
        
        :param java.lang.String or str modelName: name of registered block model
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new model instance or null if program is not open.
        :rtype: ghidra.program.model.block.CodeBlockModel
        :raises NotFoundException: if specified model is not registered
        
        .. deprecated::
        
        use getNewModelByName(String, Program, boolean) instead
        """

    @typing.overload
    def getNewModelByName(self, modelName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the specified block model.
        
        :param java.lang.String or str modelName: name of registered block model
        :param ghidra.program.model.listing.Program program: program associated with the model
        :return: new model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        :raises NotFoundException: if specified model is not registered
        """

    @typing.overload
    def getNewModelByName(self, modelName: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, includeExternals: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.block.CodeBlockModel:
        """
        Get new instance of the specified block model.
        
        :param java.lang.String or str modelName: name of registered block model
        :param ghidra.program.model.listing.Program program: program associated with the model
        :param jpype.JBoolean or bool includeExternals: externals are included if true
        :return: new model instance or null if program is null
        :rtype: ghidra.program.model.block.CodeBlockModel
        :raises NotFoundException: if specified model is not registered
        """

    def registerModel(self, modelClass: java.lang.Class[ghidra.program.model.block.CodeBlockModel], modelName: typing.Union[java.lang.String, str]):
        """
        Register a new model.
        
        :param java.lang.Class[ghidra.program.model.block.CodeBlockModel] modelClass: code block model class.
        Subroutine models must implement the SubroutineBlockMode interface - all other models
        are assumed to be basic block models.
        :param java.lang.String or str modelName: name of model
        """

    def removeListener(self, listener: BlockModelServiceListener):
        """
        Remove service listener.
        
        :param BlockModelServiceListener listener: to remove
        """

    def unregisterModel(self, modelClass: java.lang.Class[ghidra.program.model.block.CodeBlockModel]):
        """
        Deregister a model.
        
        :param java.lang.Class[ghidra.program.model.block.CodeBlockModel] modelClass: code block model class.
        """

    @property
    def activeBlockModelName(self) -> java.lang.String:
        ...

    @property
    def activeSubroutineModelName(self) -> java.lang.String:
        ...

    @property
    def availableModelNames(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def activeBlockModel(self) -> ghidra.program.model.block.CodeBlockModel:
        ...

    @property
    def activeSubroutineModel(self) -> ghidra.program.model.block.CodeBlockModel:
        ...

    @property
    def newModelByName(self) -> ghidra.program.model.block.CodeBlockModel:
        ...


class Terminal(java.lang.AutoCloseable):
    """
    A handle to a terminal window in the UI.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addTerminalListener(self, listener: ghidra.app.plugin.core.terminal.TerminalListener):
        """
        Add a listener for terminal events
        
        :param ghidra.app.plugin.core.terminal.TerminalListener listener: the listener
        """

    def getColumns(self) -> int:
        """
        Get the maximum number of characters in each row
        
        :return: the column count
        :rtype: int
        """

    def getCursorColumn(self) -> int:
        """
        Get the cursor's current column
        
        :return: the column, 0 up, left to right
        :rtype: int
        """

    def getCursorRow(self) -> int:
        """
        Get the cursor's current line
         
         
        
        Lines are indexed 0 up where the top line of the display is 0. The cursor can never be in the
        scroll-back buffer.
        
        :return: the line, 0 up, top to bottom
        :rtype: int
        """

    def getDisplayText(self) -> str:
        """
        Get the text in the terminal, excluding the scroll-back buffer
        
        :return: the display text
        :rtype: str
        """

    def getFullText(self) -> str:
        """
        Get all the text in the terminal, including the scroll-back buffer
        
        :return: the full text
        :rtype: str
        """

    def getLineText(self, line: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the given line's text
         
         
        
        The line at the top of the display has index 0. Lines in the scroll-back buffer have negative
        indices.
        
        :param jpype.JInt or int line: the index, 0 up
        :return: the text in the line
        :rtype: str
        """

    def getRangeText(self, startCol: typing.Union[jpype.JInt, int], startLine: typing.Union[jpype.JInt, int], endCol: typing.Union[jpype.JInt, int], endLine: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the text in the given range
         
         
        
        The line at the top of the display has index 0. Lines in the scroll-back buffer have negative
        indices.
        
        :param jpype.JInt or int startCol: the first column to include in the starting line
        :param jpype.JInt or int startLine: the first line to include
        :param jpype.JInt or int endCol: the first column to *exclude* in the ending line
        :param jpype.JInt or int endLine: the last line to include
        :return: the text in the given range
        :rtype: str
        """

    def getRows(self) -> int:
        """
        Get the maximum number of rows in the display (not counting scroll-back)
        
        :return: the row count
        :rtype: int
        """

    def getScrollBackRows(self) -> int:
        """
        Get the number of lines in the scroll-back buffer
        
        :return: the size of the buffer in lines
        :rtype: int
        """

    def getSubTitle(self) -> str:
        """
        Get the pane's current sub title
        
        :return: the sub title
        :rtype: str
        """

    @typing.overload
    def injectDisplayOutput(self, bb: java.nio.ByteBuffer):
        """
        Process the given buffer as if it were output by the terminal's application.
         
         
        
        **Warning:** While implementations may synchronize to ensure the additional buffer is not
        processed at the same time as actual application input, there may not be any effort to ensure
        that the buffer is not injected in the middle of an escape sequence. Even if the injection is
        outside an escape sequence, this may still lead to unexpected behavior, since the injected
        output may be affected by or otherwise interfere with the application's control of the
        terminal's state. Generally, this should only be used for testing, or other cases when the
        caller knows it has exclusive control of the terminal.
        
        :param java.nio.ByteBuffer bb: the buffer of bytes to inject
        """

    @typing.overload
    def injectDisplayOutput(self, arr: jpype.JArray[jpype.JByte]):
        """
        
        
        :param jpype.JArray[jpype.JByte] arr: the array of bytes to inject
        
        .. seealso::
        
            | :obj:`.injectDisplayOutput(ByteBuffer)`
        """

    def isTerminated(self) -> bool:
        """
        Check whether the terminal is terminated or active
        
        :return: true for terminated, false for active
        :rtype: bool
        """

    def removeTerminalListener(self, listener: ghidra.app.plugin.core.terminal.TerminalListener):
        """
        Remove a listener for terminal events
        
        :param ghidra.app.plugin.core.terminal.TerminalListener listener: the listener
        """

    def setDynamicSize(self):
        """
        Fit the terminal's dimensions to the containing window.
        """

    @typing.overload
    def setFixedSize(self, cols: typing.Union[jpype.JShort, int], rows: typing.Union[jpype.JShort, int]):
        """
        Set the terminal size to the given dimensions, and do *not* resize it to the window.
        
        :param jpype.JShort or int cols: the number of columns
        :param jpype.JShort or int rows: the number of rows
        """

    @typing.overload
    def setFixedSize(self, cols: typing.Union[jpype.JInt, int], rows: typing.Union[jpype.JInt, int]):
        """
        
        
        :param jpype.JInt or int cols: the number of columns
        :param jpype.JInt or int rows: the number of rows
        
        .. seealso::
        
            | :obj:`.setFixedSize(short, short)`
        """

    def setMaxScrollBackRows(self, rows: typing.Union[jpype.JInt, int]):
        """
        Set the maximum size of the scroll-back buffer in lines
         
         
        
        This only affects the primary buffer. The alternate buffer has no scroll-back.
        
        :param jpype.JInt or int rows: the number of scroll-back rows
        """

    def setSubTitle(self, title: typing.Union[java.lang.String, str]):
        """
        Set the pane's sub title
         
         
        
        The application may also set this sub title using an escape sequence.
        
        :param java.lang.String or str title: the new sub title
        """

    def setTerminateAction(self, action: java.lang.Runnable):
        """
        Allow the user to terminate the session forcefully
        
        :param java.lang.Runnable action: the action to terminate the session, or null to remove the action
        """

    def terminated(self, exitcode: typing.Union[jpype.JInt, int]):
        """
        Notify the terminal that its session has terminated
         
         
        
        The title and sub title are adjust and all listeners are removed. If/when the terminal is
        closed, it is permanently removed from the tool.
        
        :param jpype.JInt or int exitcode: the exit code of the session leader, or -1 if not applicable
        """

    def toFront(self):
        """
        Bring the terminal to the front of the UI
        """

    @property
    def displayText(self) -> java.lang.String:
        ...

    @property
    def cursorRow(self) -> jpype.JInt:
        ...

    @property
    def subTitle(self) -> java.lang.String:
        ...

    @subTitle.setter
    def subTitle(self, value: java.lang.String):
        ...

    @property
    def columns(self) -> jpype.JInt:
        ...

    @property
    def lineText(self) -> java.lang.String:
        ...

    @property
    def fullText(self) -> java.lang.String:
        ...

    @property
    def cursorColumn(self) -> jpype.JInt:
        ...

    @property
    def scrollBackRows(self) -> jpype.JInt:
        ...

    @property
    def rows(self) -> jpype.JInt:
        ...


class QueryData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, queryString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool], includeDynamicLables: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, queryString: typing.Union[java.lang.String, str], caseSensitive: typing.Union[jpype.JBoolean, bool]):
        ...

    def getQueryString(self) -> str:
        ...

    @staticmethod
    def hasWildCards(query: typing.Union[java.lang.String, str]) -> bool:
        ...

    def isCaseSensitive(self) -> bool:
        ...

    def isIncludeDynamicLables(self) -> bool:
        ...

    def isWildCard(self) -> bool:
        ...

    @property
    def includeDynamicLables(self) -> jpype.JBoolean:
        ...

    @property
    def caseSensitive(self) -> jpype.JBoolean:
        ...

    @property
    def wildCard(self) -> jpype.JBoolean:
        ...

    @property
    def queryString(self) -> java.lang.String:
        ...


class GoToOverrideService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getOverrideComponent(self) -> javax.swing.JComponent:
        ...

    @typing.overload
    def goTo(self, queryInput: typing.Union[java.lang.String, str]) -> ghidra.program.util.ProgramLocation:
        ...

    @typing.overload
    def goTo(self, gotoAddress: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def overrideComponent(self) -> javax.swing.JComponent:
        ...


class DataTypeReferenceFinder(ghidra.util.classfinder.ExtensionPoint):
    """
    An interface for extension points to implement.  Implementations know how to find data type
    references.
     
    
    Implementation class names must end with DataTypeReferenceFinder
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def findReferences(self, program: ghidra.program.model.listing.Program, dataType: ghidra.program.model.data.DataType, callback: java.util.function.Consumer[DataTypeReference], monitor: ghidra.util.task.TaskMonitor):
        """
        Finds references in the current program in a manner appropriate with the given
        implementation.
         
        
        Note that this operation is multi-threaded and that results will be delivered as they
        are found via the ``callback``.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.data.DataType dataType: the type for which to search
        :param java.util.function.Consumer[DataTypeReference] callback: the callback to be called when a reference is found
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows for progress and cancellation
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def findReferences(self, program: ghidra.program.model.listing.Program, dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str], callback: java.util.function.Consumer[DataTypeReference], monitor: ghidra.util.task.TaskMonitor):
        """
        Finds references in the current program to specific field of the given :obj:`Composite` type
        in a manner appropriate with the given implementation.
         
        
        Note that this operation is multi-threaded and that results will be delivered as they
        are found via the ``callback``.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param ghidra.program.model.data.DataType dataType: the type containing the field for which to search
        :param java.lang.String or str fieldName: the name of the composite's field for which to search; may be null
        :param java.util.function.Consumer[DataTypeReference] callback: the callback to be called when a reference is found
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows for progress and cancellation
        :raises CancelledException: if the operation was cancelled
        """

    @typing.overload
    def findReferences(self, program: ghidra.program.model.listing.Program, fieldMatcher: FieldMatcher, callback: java.util.function.Consumer[DataTypeReference], monitor: ghidra.util.task.TaskMonitor):
        """
        Finds references in the current program to specific field of the given :obj:`Composite` type
        in a manner appropriate with the given implementation.
         
        
        The supplied field matcher will be used to restrict matches to the given field.  The matcher
        may be 'empty', supplying only the data type for which to search.  In this case, all uses
        of the type will be matched, regardless of field.
         
        
        Note that this operation is multi-threaded and that results will be delivered as they
        are found via the ``callback``.
        
        :param ghidra.program.model.listing.Program program: the program to search
        :param FieldMatcher fieldMatcher: the field matcher to use for matching types
        :param java.util.function.Consumer[DataTypeReference] callback: the callback to be called when a reference is found
        :param ghidra.util.task.TaskMonitor monitor: the monitor that allows for progress and cancellation
        :raises CancelledException: if the operation was cancelled
        """


class NavigationHistoryService(java.lang.Object):
    """
    The NavigationHistoryService maintains a stack of locations that the user has visited via a
    navigation plugin. It provides methods querying and manipulating this list.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addNewLocation(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Adds the current location memento to the list of previous locations for the given
        navigatable. Clears the list of next locations.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        """

    @typing.overload
    def clear(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Removes all visited locations from the history list for the given navigatable
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable whose list to be cleared
        """

    @typing.overload
    def clear(self, program: ghidra.program.model.listing.Program):
        """
        Removes all entries for the given program from all history lists
        
        :param ghidra.program.model.listing.Program program: the program whose entries to be cleared
        """

    def getNextLocations(self, navigatable: ghidra.app.nav.Navigatable) -> java.util.List[ghidra.app.nav.LocationMemento]:
        """
        Returns the :obj:`LocationMemento` objects in the "next" list
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :return: the LocationMemento objects in the "next" list
        :rtype: java.util.List[ghidra.app.nav.LocationMemento]
        """

    def getPreviousLocations(self, navigatable: ghidra.app.nav.Navigatable) -> java.util.List[ghidra.app.nav.LocationMemento]:
        """
        Returns the :obj:`LocationMemento` objects in the "previous" list
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :return: the LocationMemento objects in the "previous" list
        :rtype: java.util.List[ghidra.app.nav.LocationMemento]
        """

    def hasNext(self, navigatable: ghidra.app.nav.Navigatable) -> bool:
        """
        Returns true if there is a valid "next" location in the history list.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :return: true if there is a "next" location
        :rtype: bool
        """

    def hasNextFunction(self, navigatable: ghidra.app.nav.Navigatable) -> bool:
        """
        Returns true if there is a valid "next" function location in the history list
        
        :param ghidra.app.nav.Navigatable navigatable: Navigatable object we are looking at
        :return: true if there is a valid "next" function location
        :rtype: bool
        """

    def hasPrevious(self, navigatable: ghidra.app.nav.Navigatable) -> bool:
        """
        Returns true if there is a valid "previous" location in the history list
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :return: true if there is a "previous" location
        :rtype: bool
        """

    def hasPreviousFunction(self, navigatable: ghidra.app.nav.Navigatable) -> bool:
        """
        Returns true if there is a valid "previous" function location in the history list
        
        :param ghidra.app.nav.Navigatable navigatable: Navigatable object we are looking at
        :return: true if there is a valid "previous" function location
        :rtype: bool
        """

    @typing.overload
    def next(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Positions the current location to the next location in the history list. If there is no
        "next" location, the history list remains unchanged.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        """

    @typing.overload
    def next(self, navigatable: ghidra.app.nav.Navigatable, location: ghidra.app.nav.LocationMemento):
        """
        Navigates to the given location in the "next" list. If the location is not in the list, then
        nothing will happen.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :param ghidra.app.nav.LocationMemento location: The location within the "next" list to which to go
        """

    def nextFunction(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Positions the "current" location to the next location which is in a different function from
        current one or previous non-code location. If we are not inside any function, performs like
        "next".
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        """

    @typing.overload
    def previous(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Positions the "current" location to the previous location in the history list. If there is no
        "previous" location, the history list remains unchanged.
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        """

    @typing.overload
    def previous(self, navigatable: ghidra.app.nav.Navigatable, location: ghidra.app.nav.LocationMemento):
        """
        Navigates to the given location in the "previous" list. If the location is not in the list,
        then nothing will happen
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        :param ghidra.app.nav.LocationMemento location: The location within the "previous" list to which to go.
        """

    def previousFunction(self, navigatable: ghidra.app.nav.Navigatable):
        """
        Positions the "previous" location to the next location which is in a different function from
        current one or previous non-code location. If we are not inside any function, performs like
        "next".
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable to be navigated
        """

    @property
    def previousLocations(self) -> java.util.List[ghidra.app.nav.LocationMemento]:
        ...

    @property
    def nextLocations(self) -> java.util.List[ghidra.app.nav.LocationMemento]:
        ...


class GoToServiceListener(java.lang.Object):
    """
    Listener that is notified when the GOTO completes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def gotoCompleted(self, queryString: typing.Union[java.lang.String, str], foundResults: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the GOTO completed.
        
        :param java.lang.String or str queryString: original query string
        :param jpype.JBoolean or bool foundResults: true if at least one hit was found for the query
        """

    def gotoFailed(self, exc: java.lang.Exception):
        """
        Notification that the GOTO failed with an exception.
        
        :param java.lang.Exception exc: the exception that occurred.
        """


class FileImporterService(java.lang.Object):
    """
    Service for importing files into Ghidra.
    """

    class_: typing.ClassVar[java.lang.Class]

    def importFile(self, folder: ghidra.framework.model.DomainFolder, file: jpype.protocol.SupportsPath):
        """
        Imports the given file into the specified Ghidra project folder.
        
        :param ghidra.framework.model.DomainFolder folder: the Ghidra project folder to store the imported file.
        If null, the active project's root folder will be assumed.
        :param jpype.protocol.SupportsPath file: the file to import.
        """

    def importFiles(self, folder: ghidra.framework.model.DomainFolder, files: java.util.List[java.io.File]):
        """
        Imports the given files into the specified Ghidra project folder.
        
        :param ghidra.framework.model.DomainFolder folder: the Ghidra project folder to store the imported files.
        If null, the active project's root folder will be assumed.
        :param java.util.List[java.io.File] files: the files to import.
        """


class BlockModelServiceListener(java.lang.Object):
    """
    Listener interface for BlockModelService.
    """

    class_: typing.ClassVar[java.lang.Class]

    def modelAdded(self, modeName: typing.Union[java.lang.String, str], modelType: typing.Union[jpype.JInt, int]):
        """
        Provides notification when a model is added.
        
        :param java.lang.String or str modeName: name of the block model that was added
        :param jpype.JInt or int modelType: type of block model that was added
        """

    def modelRemoved(self, modeName: typing.Union[java.lang.String, str], modelType: typing.Union[jpype.JInt, int]):
        """
        Provides notifiication when a model is removed.
        
        :param java.lang.String or str modeName: name of the block model that was removed
        :param jpype.JInt or int modelType: type of block model that was removed
        """


class CodeViewerService(java.lang.Object):
    """
    Service provided by a plugin that shows the listing from a Program, i.e., a
    Code Viewer. The service allows other plugins to add components and 
    actions local to the Code Viewer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addButtonPressedListener(self, listener: ButtonPressedListener):
        """
        Add a listener that is notified when a mouse button is pressed.
        
        :param ButtonPressedListener listener:
        """

    def addListingDisplayListener(self, listener: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
        """
        Adds a listener to be notified when the set of visible addresses change.
        
        :param ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener listener: the listener to be notified;
        """

    def addLocalAction(self, action: docking.action.DockingAction):
        """
        Add an action that is local to the Code Viewer.
        
        :param docking.action.DockingAction action: local action to add
        """

    def addMarginProvider(self, marginProvider: ghidra.app.util.viewer.listingpanel.MarginProvider):
        """
        Add a provider that shows markers in a program for the portion 
        that is visible.
        
        :param ghidra.app.util.viewer.listingpanel.MarginProvider marginProvider: provider to add
        """

    def addOverviewProvider(self, overviewProvider: ghidra.app.util.viewer.listingpanel.OverviewProvider):
        """
        Add a provider that shows an overview of the program.
        
        :param ghidra.app.util.viewer.listingpanel.OverviewProvider overviewProvider: provider to add
        """

    def addProgramDropProvider(self, provider: ghidra.app.util.ProgramDropProvider):
        """
        Add a provider that will be notified for drag and drop actions.
        
        :param ghidra.app.util.ProgramDropProvider provider: for drag and drop
        """

    def getAddressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        """
        Returns the current address-index-map
        """

    def getCurrentField(self) -> docking.widgets.fieldpanel.field.Field:
        """
        Returns the current field under the cursor.
        
        :return: the current field under the cursor.
        :rtype: docking.widgets.fieldpanel.field.Field
        """

    def getCurrentFieldTextSelection(self) -> str:
        """
        Returns a String representing the current character-based selection of the currently 
        selected field.  If there is no selection, or if there is a :obj:`ProgramSelection` 
        (which spans multiple fields), then this method will return null.   
         
        
        To know which field contains the selection,
        
        :return: the currently selected text **within a given field**
        :rtype: str
        """

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns the current cursor location.
        
        :return: the current cursor location.
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getCurrentSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Returns the current program selection (which crosses multiple fields).
        
        :return: the current program selection.
        :rtype: ghidra.program.util.ProgramSelection
        """

    def getFieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        """
        Return the fieldPanel.
        """

    def getFormatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    def getListingModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Gets the current ListingLayoutModel;
        
        :return: the current ListingLayoutModel;
        :rtype: ghidra.app.util.viewer.listingpanel.ListingModel
        """

    def getListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        """
        Get the main Listing panel for the code viewer service.
        
        :return: the listing panel.
        :rtype: ghidra.app.util.viewer.listingpanel.ListingPanel
        """

    def getNavigatable(self) -> ghidra.app.nav.Navigatable:
        """
        Gets the navigatable for the code viewer service.
        
        :return: the navigatable for the code viewer service.
        :rtype: ghidra.app.nav.Navigatable
        """

    def getView(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get Current view that the CodeViewer is showing.
        """

    def goTo(self, loc: ghidra.program.util.ProgramLocation, centerOnScreen: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Commands the code viewer to position the cursor at the given location.
        
        :param ghidra.program.util.ProgramLocation loc: the location at which to position the cursor.
        :param jpype.JBoolean or bool centerOnScreen: if true, the location will be placed in the center of the display
        window
        :return: true if the location exists.
        :rtype: bool
        """

    def removeButtonPressedListener(self, listener: ButtonPressedListener):
        """
        Remove the button pressed listener.
        
        :param ButtonPressedListener listener:
        """

    def removeHighlightProvider(self, provider: ghidra.app.util.ListingHighlightProvider, program: ghidra.program.model.listing.Program):
        """
        Remove the highlight provider.
        
        :param ghidra.app.util.ListingHighlightProvider provider: the provider to remove.
        :param ghidra.program.model.listing.Program program: the program associated with the given provider.
        """

    def removeListingDisplayListener(self, listener: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
        """
        Removes listener from being notified when the set of visible addresses change.
        
        :param ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener listener: the listener to be notified;
        """

    def removeListingPanel(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
        """
        Remove the given listing panel from the code viewer.
        """

    def removeLocalAction(self, action: docking.action.DockingAction):
        """
        Remove the local action from the Code Viewer.
        
        :param docking.action.DockingAction action: local action to remove
        """

    def removeMarginProvider(self, marginProvider: ghidra.app.util.viewer.listingpanel.MarginProvider):
        """
        Remove a provider that shows markers in a program for the portion 
        that is visible.
        
        :param ghidra.app.util.viewer.listingpanel.MarginProvider marginProvider: provider to remove
        """

    def removeOverviewProvider(self, overviewProvider: ghidra.app.util.viewer.listingpanel.OverviewProvider):
        """
        Remove a provider that shows an overview of the program.
        
        :param ghidra.app.util.viewer.listingpanel.OverviewProvider overviewProvider: provider to remove
        """

    def requestFocus(self):
        """
        Request that the main connected Listing view gets focus
        """

    def setCoordinatedListingPanelListener(self, listener: CoordinatedListingPanelListener):
        """
        Set the :obj:`CoordinatedListingPanelListener` for this listing.
        
        :param CoordinatedListingPanelListener listener: the listener to add.
        """

    def setHighlightProvider(self, provider: ghidra.app.util.ListingHighlightProvider, program: ghidra.program.model.listing.Program):
        """
        Set the highlight  provider. The existing provider is replaced
        with the given provider.
        
        :param ghidra.app.util.ListingHighlightProvider provider: The provider to set.
        :param ghidra.program.model.listing.Program program: The program with which to associate the given provider.
        """

    def setListingPanel(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
        """
        Set a listing panel on the code viewer.
        
        :param ghidra.app.util.viewer.listingpanel.ListingPanel listingPanel: the panel to add.
        """

    def setNorthComponent(self, comp: javax.swing.JComponent):
        """
        Place a component in the North area of the CodeViewer.
        
        :param javax.swing.JComponent comp: component to place in the North area of the CodeViewer
        """

    def updateDisplay(self):
        """
        tells the browser to rebuild the display.
        """

    @property
    def listingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel:
        ...

    @listingPanel.setter
    def listingPanel(self, value: ghidra.app.util.viewer.listingpanel.ListingPanel):
        ...

    @property
    def view(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def formatManager(self) -> ghidra.app.util.viewer.format.FormatManager:
        ...

    @property
    def currentFieldTextSelection(self) -> java.lang.String:
        ...

    @property
    def navigatable(self) -> ghidra.app.nav.Navigatable:
        ...

    @property
    def listingModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        ...

    @property
    def currentField(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def currentSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def addressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap:
        ...

    @property
    def fieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel:
        ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class Analyzer(ghidra.util.classfinder.ExtensionPoint):
    """
    Interface to perform automatic analysis.
     
    NOTE:  ALL ANALYZER CLASSES MUST END IN "Analyzer".  If not, the ClassSearcher will not find 
    them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Called when the requested information type has been added, for example, when a function is
        added.
        
        :param ghidra.program.model.listing.Program program: program to analyze
        :param ghidra.program.model.address.AddressSetView set: AddressSet of locations that have been added
        :param ghidra.util.task.TaskMonitor monitor: monitor that indicates progress and indicates whether the user canceled the
                analysis
        :param ghidra.app.util.importer.MessageLog log: a message log to record analysis information
        :return: true if the analysis succeeded
        :rtype: bool
        :raises CancelledException: if the analysis is cancelled
        """

    def analysisEnded(self, program: ghidra.program.model.listing.Program):
        """
        Called when an auto-analysis session ends. This notifies the analyzer so it can clean up any 
        resources that only needed to be maintained during a single auto-analysis session.
        
        :param ghidra.program.model.listing.Program program: the program that was just completed being analyzed
        """

    def canAnalyze(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Can this analyzer work on this program.
        
        :param ghidra.program.model.listing.Program program: program to be analyzed
        :return: true if this analyzer can analyze this program
        :rtype: bool
        """

    def getAnalysisType(self) -> AnalyzerType:
        """
        Get the type of analysis this analyzer performs
        
        :return: analyze type
        :rtype: AnalyzerType
        """

    def getDefaultEnablement(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if this analyzer should be enabled by default.  Generally useful analyzers 
        should return true. Specialized analyzers should return false;
        
        :param ghidra.program.model.listing.Program program: the program
        :return: true if enabled by default
        :rtype: bool
        """

    def getDescription(self) -> str:
        """
        Get a longer description of what this analyzer does.
        
        :return: analyzer description
        :rtype: str
        """

    def getName(self) -> str:
        """
        Get the name of this analyzer
        
        :return: analyzer name
        :rtype: str
        """

    def getOptionsUpdater(self) -> ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater:
        """
        Returns an optional options updater that allows clients to migrate old options to new 
        options.  This can be used to facilitate option name changes, as well as option value type
        changes.
        
        :return: the updater; null if no updater
        :rtype: ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater
        """

    def getPriority(self) -> AnalysisPriority:
        """
        Get the priority that this analyzer should run at.
        
        :return: analyzer priority
        :rtype: AnalysisPriority
        """

    def isPrototype(self) -> bool:
        """
        Returns true if this analyzer is a prototype.
        
        :return: true if this analyzer is a prototype
        :rtype: bool
        """

    def optionsChanged(self, options: ghidra.framework.options.Options, program: ghidra.program.model.listing.Program):
        """
        Analyzers should initialize their options from the values in the given Options, providing
        appropriate default values.
        
        :param ghidra.framework.options.Options options: the program options/property list that contains the options
        :param ghidra.program.model.listing.Program program: program to be analyzed
        """

    def registerOptions(self, options: ghidra.framework.options.Options, program: ghidra.program.model.listing.Program):
        """
        Analyzers should register their options with associated default value, help content and
        description
        
        :param ghidra.framework.options.Options options: the program options/property list that contains the options
        :param ghidra.program.model.listing.Program program: program to be analyzed
        """

    def removed(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        """
        Called when the requested information type has been removed, for example, when a function is
        removed.
        
        :param ghidra.program.model.listing.Program program: program to analyze
        :param ghidra.program.model.address.AddressSetView set: AddressSet of locations that have been added
        :param ghidra.util.task.TaskMonitor monitor: monitor that indicates progress and indicates whether the user canceled the
                analysis
        :param ghidra.app.util.importer.MessageLog log: a message log to record analysis information
        :return: true if the analysis succeeded
        :rtype: bool
        :raises CancelledException: if the analysis is cancelled
        """

    def supportsOneTimeAnalysis(self) -> bool:
        """
        Returns true if it makes sense for this analyzer to directly invoked on an address or
        addressSet.  The AutoAnalyzer plug-in will automatically create an action for each analyzer
        that returns true.
        
        :return: true if supports one-time analysis
        :rtype: bool
        """

    @property
    def optionsUpdater(self) -> ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater:
        ...

    @property
    def defaultEnablement(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def priority(self) -> AnalysisPriority:
        ...

    @property
    def prototype(self) -> jpype.JBoolean:
        ...

    @property
    def analysisType(self) -> AnalyzerType:
        ...


class FileSystemBrowserService(java.lang.Object):
    """
    A service to interact with file systems.
    """

    class_: typing.ClassVar[java.lang.Class]

    def openFileSystem(self, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Opens the given :obj:`FSRL` in a file system browser.
        
        :param ghidra.formats.gfilesystem.FSRL fsrl: The thing to open in a file system browser.
        """


class HoverService(java.lang.Object):
    """
    ``HoverService`` provides the ability to popup data Windows over a Field viewer
    in response to the mouse hovering over a single Field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def componentHidden(self):
        """
        Provides notification when this hover component is popped-down
        """

    def componentShown(self):
        """
        Provides notification when this hover component is popped-up
        """

    def getHoverComponent(self, program: ghidra.program.model.listing.Program, programLocation: ghidra.program.util.ProgramLocation, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field) -> javax.swing.JComponent:
        """
        Returns a component to be shown in a popup window that is relevant to the given parameters.
        Null is returned if there is no appropriate information to display.
        
        :param ghidra.program.model.listing.Program program: the program that is being hovered over.
        :param ghidra.program.util.ProgramLocation programLocation: the program location where the mouse is hovering.
        :param docking.widgets.fieldpanel.support.FieldLocation fieldLocation: the precise mouse location within the field viewer
        :param docking.widgets.fieldpanel.field.Field field: the field over which the mouse is hovering
        :return: The component to be shown for the given location information.
        :rtype: javax.swing.JComponent
        """

    def getPriority(self) -> int:
        """
        Returns the priority of this hover service.   A lower priority is more important.
        
        :return: the priority
        :rtype: int
        """

    def hoverModeSelected(self) -> bool:
        """
        Return whether hover mode is "on"
        
        :return: the priority
        :rtype: bool
        """

    def scroll(self, amount: typing.Union[jpype.JInt, int]):
        """
        If this service's window supports scrolling, scroll by the specified amount.
        
        :param jpype.JInt or int amount: the amount to scroll
        """

    @property
    def priority(self) -> jpype.JInt:
        ...


class CoordinatedListingPanelListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def activeProgramChanged(self, activeProgram: ghidra.program.model.listing.Program):
        ...

    def listingClosed(self) -> bool:
        """
        Notifies the listener that it's associated listing panel should get closed.
        
        :return: true if the listener actually closes a listing panel.
        :rtype: bool
        """


class ProgramLocationPair(java.lang.Object):
    """
    A simple object that contains a ProgramLocation and its associated Program
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class StringValidityScore(java.lang.Record):
    """
    Result of a :obj:`StringValidatorService`'s judgment about a string.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, originalString: typing.Union[java.lang.String, str], transformedString: typing.Union[java.lang.String, str], score: typing.Union[jpype.JDouble, float], threshold: typing.Union[jpype.JDouble, float]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def isScoreAboveThreshold(self) -> bool:
        ...

    @staticmethod
    def makeDummyFor(s: typing.Union[java.lang.String, str]) -> StringValidityScore:
        ...

    def originalString(self) -> str:
        ...

    def score(self) -> float:
        ...

    def threshold(self) -> float:
        ...

    def toString(self) -> str:
        ...

    def transformedString(self) -> str:
        ...

    @property
    def scoreAboveThreshold(self) -> jpype.JBoolean:
        ...


class FunctionComparisonService(java.lang.Object):
    """
    Service interface to create comparisons between functions which will be displayed
    side-by-side in a function comparison window. Each side in the 
    display will allow the user to select one or more functions 
     
     
    Concurrent usage: All work performed by this service will be done asynchronously on the
    Swing thread.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addToComparison(self, function: ghidra.program.model.listing.Function):
        """
        Adds the given function to each side the last created comparison window or creates
        a new comparison if none exists. The right panel will be changed to show the new function.
        Note that this method will not add to any provider created via the
        :meth:`createCustomComparison(FunctionComparisonModel, Callback) <.createCustomComparison>`. Those providers
        are private to the client that created them. They take in a model, so if the client wants
        to add to those providers, it must retain a handle to the model and add functions directly
        to the model.
        
        :param ghidra.program.model.listing.Function function: the function to be added to the last function comparison window
        """

    @typing.overload
    def addToComparison(self, functions: collections.abc.Sequence):
        """
        Adds the given functions to each side the last created comparison window or creates
        a new comparison if none exists. The right panel will be change to show a random function
        from the new functions. Note that this method will not add to any comparison windows created
        with a custom comparison model.
        
        :param collections.abc.Sequence functions: the functions to be added to the last function comparison window
        """

    @typing.overload
    def createComparison(self, functions: collections.abc.Sequence):
        """
        Creates a function comparison window where each side can display any of the given functions.
        
        :param collections.abc.Sequence functions: the functions to compare
        """

    @typing.overload
    def createComparison(self, left: ghidra.program.model.listing.Function, right: ghidra.program.model.listing.Function):
        """
        Creates a function comparison window for the two given functions. Each side can select
        either function, but initially the left function will be shown in the left panel and the
        right function will be shown in the right panel.
        
        :param ghidra.program.model.listing.Function left: the function to initially show in the left panel
        :param ghidra.program.model.listing.Function right: the function to initially show in the right panel
        """

    def createComparisonViewer(self) -> ghidra.features.base.codecompare.panel.FunctionComparisonPanel:
        """
        Creates a new comparison view that the caller can install into their UI.  This is in contrast
        with :meth:`createCustomComparison(FunctionComparisonModel, Callback) <.createCustomComparison>`, which will install
        the new comparison into an existing UI.
         
        
        Note: clients are responsible for calling :meth:`FunctionComparisonPanel.dispose() <FunctionComparisonPanel.dispose>` when done
        using the panel.
        
        :return: the new panel
        :rtype: ghidra.features.base.codecompare.panel.FunctionComparisonPanel
        """

    def createCustomComparison(self, model: ghidra.features.base.codecompare.model.FunctionComparisonModel, closeListener: utility.function.Callback):
        """
        Creates a custom function comparison window. The default model shows all functions on both
        sides. This method allows the client to provide a custom comparison model which can have
        more control over what functions can be selected on each side. One such custom model
        is the :obj:`MatchedFunctionComparisonModel` which gives a unique set of functions on the
        right side, depending on what is selected on the left side.
         
        
        Note that function comparison windows created with this method are considered private for the
        client and are not available to be chosen for either of the above "add to" service methods. 
        Instead, the client that uses this model can retain a handle to the model and add or remove
        functions directly on the model.
        
        :param ghidra.features.base.codecompare.model.FunctionComparisonModel model: the custom function comparison model
        :param utility.function.Callback closeListener: an optional callback if the client wants to be notified when the 
        associated function comparison windows is closed.
        """


class AnalyzerType(java.lang.Enum[AnalyzerType]):
    """
    AnalyzerType defines various types of analyzers that Ghidra provides.
    
    Analyzers get kicked off based on certain events or conditions, such
    as a function being defined at a location.  Currently there are four types (although
    only three are used, Data really has no analyzers yet).
     
        BYTES - analyze anywhere defined bytes are present (block of memory added)
        INSTRUCTIONS - analyze anywhere instructions are defined
        FUNCTIONS - analyze where a function is defined
        FUNCTION-MODIFIERS - analyze functions whose modifiers have changed
            modifiers include:
            - FUNCTION_CHANGED_THUNK
                - FUNCTION_CHANGED_INLINE
                - FUNCTION_CHANGED_NORETURN
                - FUNCTION_CHANGED_CALL_FIXUP
                - FUNCTION_CHANGED_PURGE
        FUNCTION-SIGNATURES - analyze functions whose signatures have changed
            signature include:
                - FUNCTION_CHANGED_PARAMETERS
                - FUNCTION_CHANGED_RETURN
        DATA - analyze where data has been defined.
     
    An analyzer can be kicked off because something has caused a change to program,
    such as adding a function.  They can also be kicked off because a specific
    area of the program has been requested to be analyzed by the user.
    """

    class_: typing.ClassVar[java.lang.Class]
    BYTE_ANALYZER: typing.Final[AnalyzerType]
    INSTRUCTION_ANALYZER: typing.Final[AnalyzerType]
    FUNCTION_ANALYZER: typing.Final[AnalyzerType]
    FUNCTION_MODIFIERS_ANALYZER: typing.Final[AnalyzerType]
    FUNCTION_SIGNATURES_ANALYZER: typing.Final[AnalyzerType]
    DATA_ANALYZER: typing.Final[AnalyzerType]

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        """
        :return: the name of this AnalyzerType
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> AnalyzerType:
        ...

    @staticmethod
    def values() -> jpype.JArray[AnalyzerType]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class DataTypeArchiveService(java.lang.Object):
    """
    A service that manages a set of data type archives, allowing re-use of already open archives.
    """

    class_: typing.ClassVar[java.lang.Class]

    def closeArchive(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Closes the archive for the given :obj:`DataTypeManager`.  This will ignore request to 
        close the open Program's manager and the built-in manager.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager of the archive to close
        """

    def getBuiltInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the data type manager that has all of the built in types.
        
        :return: data type manager for built in data types
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    def getDataTypeManagers(self) -> jpype.JArray[ghidra.program.model.data.DataTypeManager]:
        """
        Gets the open data type managers.
        
        :return: the open data type managers.
        :rtype: jpype.JArray[ghidra.program.model.data.DataTypeManager]
        """

    @typing.overload
    def openArchive(self, file: generic.jar.ResourceFile, acquireWriteLock: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens the specified gdt (file based) data type archive.
        
        :param generic.jar.ResourceFile file: gdt file
        :param jpype.JBoolean or bool acquireWriteLock: true if write lock should be acquired (i.e., open for update)
        :return: the data type archive
        :rtype: ghidra.program.model.data.DataTypeManager
        :raises IOException: if an i/o error occurs opening the data type archive
        :raises DuplicateIdException: if another archive with the same ID is already open
        """

    @typing.overload
    def openArchive(self, domainFile: ghidra.framework.model.DomainFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens the specified project-located data type archive.
        
        :param ghidra.framework.model.DomainFile domainFile: archive file located in the current project
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to display progress during the opening
        :return: the data type archive
        :rtype: ghidra.program.model.data.DataTypeManager
        :raises IOException: if an i/o error occurs opening the data type archive
        :raises DuplicateIdException: if another archive with the same ID is already open
        :raises VersionException: if there is a version exception
        :raises CancelledException: if the user cancels
        """

    @typing.overload
    def openArchive(self, dataTypeArchive: ghidra.program.model.listing.DataTypeArchive) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        """
        A method to open an Archive for the given, pre-existing DataTypeArchive (like one that
        was opened during the import process.
        
        :param ghidra.program.model.listing.DataTypeArchive dataTypeArchive: the archive from which to create an Archive
        :return: an Archive based upon the given DataTypeArchive
        :rtype: ghidra.app.plugin.core.datamgr.archive.Archive
        """

    @typing.overload
    def openArchive(self, file: jpype.protocol.SupportsPath, acquireWriteLock: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        """
        A method to open an Archive for the given, pre-existing archive file (*.gdt)
        
        :param jpype.protocol.SupportsPath file: data type archive file
        :param jpype.JBoolean or bool acquireWriteLock: true if write lock should be acquired (i.e., open for update)
        :return: an Archive based upon the given archive files
        :rtype: ghidra.app.plugin.core.datamgr.archive.Archive
        :raises IOException: if an i/o error occurs opening the data type archive
        :raises DuplicateIdException: if another archive with the same ID is already open
        """

    def openDataTypeArchive(self, archiveName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens a data type archive that was built into the Ghidra installation.
         
        
        NOTE: This is predicated upon all archive files having a unique name within the installation.
         
        
        Any path prefix specified may prevent the file from opening (or reopening) correctly.
        
        :param java.lang.String or str archiveName: archive file name (i.e., "generic_C_lib")
        :return: the data type archive or null if an archive with the specified name
        can not be found.
        :rtype: ghidra.program.model.data.DataTypeManager
        :raises IOException: if an i/o error occurs opening the data type archive
        :raises DuplicateIdException: if another archive with the same ID is already open
        """

    @property
    def dataTypeManagers(self) -> jpype.JArray[ghidra.program.model.data.DataTypeManager]:
        ...

    @property
    def builtInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...


class ClipboardService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def deRegisterClipboardContentProvider(self, service: ClipboardContentProviderService):
        ...

    def registerClipboardContentProvider(self, service: ClipboardContentProviderService):
        ...


class EclipseIntegrationService(java.lang.Object):
    """
    Service that provides Eclipse-related functionality.
    """

    class_: typing.ClassVar[java.lang.Class]

    def connectToEclipse(self, port: typing.Union[jpype.JInt, int]) -> ghidra.app.plugin.core.eclipse.EclipseConnection:
        """
        Attempts to connect to Eclipse on the given port.  This may result in Eclipse
        being launched.  If the launch and/or connection fails, an error message will
        be displayed.
        
        :param jpype.JInt or int port: The port to connect to.
        :return: The (possibly failed) connection.  Check the status of the :obj:`EclipseConnection`
        for details on the connection.
        :rtype: ghidra.app.plugin.core.eclipse.EclipseConnection
        """

    def getEclipseDropinsDir(self) -> java.io.File:
        """
        Gets the Eclipse dropins directory.  If it doesn't exist, it will be created.
        
        :return: The Eclipse dropins directory.
        :rtype: java.io.File
        :raises FileNotFoundException: if the dropins directory was not found and could not be 
        created.
        """

    def getEclipseExecutableFile(self) -> java.io.File:
        """
        Gets the Eclipse executable file.
        
        :return: The Eclipse executable file.
        :rtype: java.io.File
        :raises FileNotFoundException: if the executable file does not exist.
        """

    def getEclipseIntegrationOptions(self) -> ghidra.framework.options.ToolOptions:
        """
        Gets the Eclipse Integration options.
        
        :return: The Eclipse Integration options.
        :rtype: ghidra.framework.options.ToolOptions
        """

    def getEclipseWorkspaceDir(self) -> java.io.File:
        """
        Gets the Eclipse workspace directory.  If it is defined, the directory may or may not exist.
        If it is undefined, Eclipse will be in control of selecting a workspace directory to use.
        
        :return: The Eclipse workspace directory. The directory may or may not exist.  Could return
        null if the workspace directory is undefined.
        :rtype: java.io.File
        """

    def handleEclipseError(self, error: typing.Union[java.lang.String, str], askAboutOptions: typing.Union[jpype.JBoolean, bool], t: java.lang.Throwable):
        """
        Displays the given Eclipse related error message in an error dialog.
        
        :param java.lang.String or str error: The error message to display in a dialog.
        :param jpype.JBoolean or bool askAboutOptions: True if we should ask the user if they want to be taken to the Eclipse
        options; otherwise, false.
        :param java.lang.Throwable t: An optional throwable to tie to the message.
        """

    def isEclipseFeatureInstalled(self, filter: java.io.FilenameFilter) -> bool:
        """
        Checks to see if a feature is installed in Eclipse.
        
        :param java.io.FilenameFilter filter: A filename filter that matches the feature file to check.
        :return: True if the specified feature is installed.
        :rtype: bool
        :raises FileNotFoundException: if Eclipse is not installed.
        """

    def offerGhidraDevInstallation(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Offers to install GhidraDev into Eclipse's dropins directory.
        
        :param ghidra.util.task.TaskMonitor monitor: The task monitor used to cancel the installation.
        """

    @property
    def eclipseExecutableFile(self) -> java.io.File:
        ...

    @property
    def eclipseIntegrationOptions(self) -> ghidra.framework.options.ToolOptions:
        ...

    @property
    def eclipseWorkspaceDir(self) -> java.io.File:
        ...

    @property
    def eclipseDropinsDir(self) -> java.io.File:
        ...

    @property
    def eclipseFeatureInstalled(self) -> jpype.JBoolean:
        ...


class ViewService(java.lang.Object):
    """
    Base interface class for the view providers and view manager service.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addToView(self, loc: ghidra.program.util.ProgramLocation) -> ghidra.program.model.address.AddressSetView:
        """
        Add the view that corresponds to the given program location.
        
        :param ghidra.program.util.ProgramLocation loc: program location to be added to the view
        :return: new addressSet for the added view
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getCurrentView(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the current view.
        """

    @property
    def currentView(self) -> ghidra.program.model.address.AddressSetView:
        ...


@deprecated("This is not a generally useful service, may go away at some point")
class MemorySearchService(java.lang.Object):
    """
    Service for invoking the :obj:`MemorySearchProvider`
    
    
    .. deprecated::
    
    This is not a generally useful service, may go away at some point
    """

    class_: typing.ClassVar[java.lang.Class]

    def createMemorySearchProvider(self, navigatable: ghidra.app.nav.Navigatable, input: typing.Union[java.lang.String, str], settings: ghidra.features.base.memsearch.gui.SearchSettings, useSelection: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new memory search provider window
        
        :param ghidra.app.nav.Navigatable navigatable: the navigatable used to get bytes to search
        :param java.lang.String or str input: the input string to search for
        :param ghidra.features.base.memsearch.gui.SearchSettings settings: the settings that determine how to interpret the input string
        :param jpype.JBoolean or bool useSelection: true if the provider should automatically restrict to a selection if
        a selection exists in the navigatable
        """


class StringValidatorQuery(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, stringValue: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, stringValue: typing.Union[java.lang.String, str], stringCharInfo: ghidra.app.plugin.core.strings.StringInfo):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def stringCharInfo(self) -> ghidra.app.plugin.core.strings.StringInfo:
        ...

    def stringValue(self) -> str:
        ...

    def toString(self) -> str:
        ...


class BookmarkService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def setBookmarksVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        ...


class ProgramTreeService(java.lang.Object):
    """
    Service provided by the program tree plugin to get the current view 
    (address set shown in the Code Browser), 
    and the name of the tree currently being viewed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getView(self) -> ghidra.program.model.address.AddressSet:
        """
        Get the address set of the current view (what is currently being shown in
        the Code Browser).
        """

    def getViewedTreeName(self) -> str:
        """
        Get the name of the tree currently being viewed.
        """

    def setGroupSelection(self, *groupPaths: ghidra.program.util.GroupPath):
        """
        Set the selection to the given group paths.
        
        :param jpype.JArray[ghidra.program.util.GroupPath] groupPaths: paths to select
        """

    def setViewedTree(self, treeName: typing.Union[java.lang.String, str]):
        """
        Set the current view to that of the given name. If treeName is not
        a known view, then nothing happens.
        
        :param java.lang.String or str treeName: name of the view
        """

    @property
    def view(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def viewedTreeName(self) -> java.lang.String:
        ...


class ProgramManager(java.lang.Object):
    """
    Service for managing programs. Multiple programs may be open in a tool, but only one is active at
    any given time.
    """

    class_: typing.ClassVar[java.lang.Class]
    OPEN_HIDDEN: typing.Final = 0
    """
    Program will be open in a Hidden state if not already open. This mode is generally used in
    conjunction with a persistent program owner.
    """

    OPEN_CURRENT: typing.Final = 1
    """
    Program will be open as the currently active program within the tool.
    """

    OPEN_VISIBLE: typing.Final = 2
    """
    Program will be open within the tool but no change will be made to the currently active
    program. If this is the only program open, it will become the currently active program.
    """


    def closeAllPrograms(self, ignoreChanges: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Closes all open programs in this tool. If this tool is the only tool with a program open and
        that program has changes, then the user will be prompted to close each such file. (Providing
        the ignoreChanges flag is false)
        
        :param jpype.JBoolean or bool ignoreChanges: if true, the programs will be closed without saving changes.
        :return: true if all programs were closed. Returns false if the user canceled the close while
                being prompted to save.
        :rtype: bool
        """

    def closeOtherPrograms(self, ignoreChanges: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Closes all open programs in this tool except the current program. If this tool is the only
        tool with a program open and that program has changes, then the user will be prompted to
        close each such file. (Providing the ignoreChanges flag is false)
        
        :param jpype.JBoolean or bool ignoreChanges: if true, the programs will be closed without saving changes.
        :return: true if all other programs were closed. Returns false if the user canceled the close
                while being prompted to save.
        :rtype: bool
        """

    @typing.overload
    def closeProgram(self) -> bool:
        """
        Closes the currently active program
        
        :return: true if the close is successful. false if the close fails or if there is no program
                currently active.
        :rtype: bool
        """

    @typing.overload
    def closeProgram(self, program: ghidra.program.model.listing.Program, ignoreChanges: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Closes the given program with the option of saving any changes. The exact behavior of this
        method depends on several factors. First of all, if any other tool has this program open,
        then the program is closed for this tool only and the user is not prompted to save the
        program regardless of the ignoreChanges flag. Otherwise, if ignoreChanges is false and
        changes have been made, the user is prompted to save the program.
        
        :param ghidra.program.model.listing.Program program: the program to close.
        :param jpype.JBoolean or bool ignoreChanges: if true, the program is closed without saving any changes.
        :return: true if the program was closed. Returns false if the user canceled the close while
                being prompted to save. Also returns false if the program passed in as a parameter is
                null.
        :rtype: bool
        """

    def getAllOpenPrograms(self) -> jpype.JArray[ghidra.program.model.listing.Program]:
        """
        Returns a list of all open program.
        
        :return: the programs
        :rtype: jpype.JArray[ghidra.program.model.listing.Program]
        """

    def getCurrentProgram(self) -> ghidra.program.model.listing.Program:
        """
        Return the program that is currently active.
        
        :return: may return null if no program is open
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgram(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Program:
        """
        Returns the first program in the list of open programs that contains the given address.
        Programs are searched in the order they were opened within a given priority. Program are
        initially opened with the PRIORITY_NORMAL priority, but can be set to have PRIORITY_HIGH or
        PRIORITY_LOW.
        
        :param ghidra.program.model.address.Address addr: the address for which to search.
        :return: the first program that can be found to contain the given address.
        :rtype: ghidra.program.model.listing.Program
        """

    def isVisible(self, program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the specified program is open and considered visible to the user.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: true if the specified program is open and considered visible to the user
        :rtype: bool
        """

    @typing.overload
    def openCachedProgram(self, domainFile: ghidra.framework.model.DomainFile, consumer: java.lang.Object) -> ghidra.program.model.listing.Program:
        """
        Opens a program or retrieves it from a cache. If the program is in the cache, the consumer
        will be added the program before returning it. Otherwise, the program will be opened with
        the consumer. In addition, opening or accessing a cached program, will guarantee that it will
        remain open for period of time, even if the caller of this method releases it from the 
        consumer that was passed in. If the program isn't accessed again, it will be eventually be
        released from the cache. If the program is still in use when the timer expires, the
        program will remain in the cache with a new full expiration time. Calling this method
        does not open the program in the tool.
        
        :param ghidra.framework.model.DomainFile domainFile: the DomainFile from which to open a program.
        :param java.lang.Object consumer: the consumer that is using the program. The caller is responsible for
        releasing (See :meth:`Program.release(Object) <Program.release>`) the consumer when done with the program.
        :return: the program for the given domainFile or null if unable to open the program
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def openCachedProgram(self, ghidraURL: java.net.URL, consumer: java.lang.Object) -> ghidra.program.model.listing.Program:
        """
        Opens a program or retrieves it from a cache. If the program is in the cache, the consumer
        will be added the program before returning it. Otherwise, the program will be opened with
        the consumer. In addition, opening or accessing a cached program, will guarantee that it will
        remain open for period of time, even if the caller of this method releases it from the 
        consumer that was passed in. If the program isn't accessed again, it will be eventually be
        released from the cache. If the program is still in use when the timer expires, the
        program will remain in the cache with a new full expiration time.  Calling this method
        does not open the program in the tool.
        
        :param java.net.URL ghidraURL: the ghidra URL from which to open a program.
        :param java.lang.Object consumer: the consumer that is using the program. The caller is responsible for
        releasing (See :meth:`Program.release(Object) <Program.release>`) the consumer when done with the program.
        :return: the program for the given URL or null if unable to open the program
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def openProgram(self, ghidraURL: java.net.URL, state: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Open the program corresponding to the given url.
        
        :param java.net.URL ghidraURL: valid server-based program URL
        :param jpype.JInt or int state: initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
                    states will be ignored if the program is already open.
        :return: the opened program or null if the user canceled the "open" or an error occurred
        :rtype: ghidra.program.model.listing.Program
        
        .. seealso::
        
            | :obj:`GhidraURL`
        """

    @typing.overload
    def openProgram(self, domainFile: ghidra.framework.model.DomainFile) -> ghidra.program.model.listing.Program:
        """
        Open the program for the given domainFile. Once open it will become the active program.
        
        :param ghidra.framework.model.DomainFile domainFile: domain file that has the program
        :return: the opened program or null if the user canceled the "open" or an error occurred
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def openProgram(self, df: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Opens the specified version of the program represented by the given DomainFile. This method
        should be used for shared DomainFiles. The newly opened file will be made the active program.
        
        :param ghidra.framework.model.DomainFile df: the DomainFile to open
        :param jpype.JInt or int version: the version of the Program to open
        :return: the opened program or null if the user canceled the "open" or an error occurred
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def openProgram(self, domainFile: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int], state: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Program:
        """
        Open the program for the given domainFile
        
        :param ghidra.framework.model.DomainFile domainFile: domain file that has the program
        :param jpype.JInt or int version: the version of the Program to open. Specify DomainFile.DEFAULT_VERSION for
                    file update mode.
        :param jpype.JInt or int state: initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
                    states will be ignored if the program is already open.
        :return: the opened program or null if the user canceled the "open" or an error occurred
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def openProgram(self, program: ghidra.program.model.listing.Program):
        """
        Opens the program to the tool. In this case the program is already open, but this tool may
        not have it registered as open. The program is made the active program.
        
        :param ghidra.program.model.listing.Program program: the program to register as open with the tool.
        """

    @typing.overload
    def openProgram(self, program: ghidra.program.model.listing.Program, state: typing.Union[jpype.JInt, int]):
        """
        Open the specified program in the tool.
        
        :param ghidra.program.model.listing.Program program: the program
        :param jpype.JInt or int state: initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
                    states will be ignored if the program is already open.
        """

    @deprecated("this method is no longer used by the system")
    def releaseProgram(self, program: ghidra.program.model.listing.Program, persistentOwner: java.lang.Object):
        """
        Release the persistent ownership of a program.
         
        
        The program will automatically be closed if it is hidden or was marked as temporary. If any
        of these closures corresponds to a program with changes the user will be given an opportunity
        to save or keep the program open.
         
        
        If persistentOwner is not the correct owner, the method will have no affect.
        
        :param ghidra.program.model.listing.Program program: the program
        :param java.lang.Object persistentOwner: the owner defined by :meth:`setPersistentOwner(Program, Object) <.setPersistentOwner>`
        
        .. deprecated::
        
        this method is no longer used by the system
        """

    @typing.overload
    def saveProgram(self):
        """
        Saves the current program, possibly prompting the user for a new name.
        """

    @typing.overload
    def saveProgram(self, program: ghidra.program.model.listing.Program):
        """
        Saves the specified program, possibly prompting the user for a new name.
        
        :param ghidra.program.model.listing.Program program: the program
        """

    @typing.overload
    def saveProgramAs(self):
        """
        Prompts the user to save the current program to a selected file.
        """

    @typing.overload
    def saveProgramAs(self, program: ghidra.program.model.listing.Program):
        """
        Prompts the user to save the specified program to a selected file.
        
        :param ghidra.program.model.listing.Program program: the program
        """

    def setCurrentProgram(self, p: ghidra.program.model.listing.Program):
        """
        Sets the given program to be the current active program in the tool.
        
        :param ghidra.program.model.listing.Program p: the program to make active.
        """

    @deprecated("this method is no longer used by the system")
    def setPersistentOwner(self, program: ghidra.program.model.listing.Program, owner: java.lang.Object) -> bool:
        """
        Establish a persistent owner on an open program. This will cause the program manager to imply
        make a program hidden if it is closed.
        
        :param ghidra.program.model.listing.Program program: the program
        :param java.lang.Object owner: the owner
        :return: true if program is open and another object is not already the owner, or the specified
                owner is already the owner.
        :rtype: bool
        
        .. deprecated::
        
        this method is no longer used by the system
        
        .. seealso::
        
            | :obj:`.releaseProgram(Program, Object)`
        """

    @property
    def currentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @currentProgram.setter
    def currentProgram(self, value: ghidra.program.model.listing.Program):
        ...

    @property
    def allOpenPrograms(self) -> jpype.JArray[ghidra.program.model.listing.Program]:
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class AnalyzerAdapter(AbstractAnalyzer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], priority: AnalysisPriority):
        ...


class AbstractAnalyzer(Analyzer):

    class_: typing.ClassVar[java.lang.Class]

    def analyzeLocation(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Analyze a single location
        
        :param ghidra.program.model.listing.Program program: - program to analyze
        :param ghidra.program.model.address.Address start: - location to start flowing constants
        :param ghidra.program.model.address.AddressSetView set: - restriction set of addresses to analyze
        :param ghidra.util.task.TaskMonitor monitor: - monitor to check canceled
        :return: - set of addresses actually flowed to
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException:
        """


class TerminalService(java.lang.Object):
    """
    A service that provides for the creation and management of DEC VT100 terminal emulators.
     
     
    
    These are perhaps better described as XTerm clones. It seems the term "VT100" is applied to any
    text display that interprets some number of ANSI escape codes. While the XTerm documentation does
    a decent job of listing which VT version (or Tektronix, or whatever terminal) that introduced or
    specified each code/sequence in the last 6 or so decades, applications don't really seem to care
    about the details. You set ``TERM=xterm``, and they just use whatever codes the feel like.
    Some make more conservative assumptions than others. For example, there is an escape sequence to
    insert a blank character, shifting the remaining characters in the line to the right. Despite
    using this, Bash (or perhaps Readline) will still re-send the remaining characters, just in case.
    It seems over the years, in an effort to be compatible with as many applications as possible,
    terminal emulators have implemented more and more escape codes, many of which were invented by
    XTerm, and some of which result from mis-reading documentation and/or replicating erroneous
    implementations.
     
     
    
    Perhaps our interpretation of the history is jaded, and as we learn more, our implementation can
    become more disciplined, but as it stands, our :obj:`TerminalPlugin` takes the *ad hoc*
    approach: We've implemented the sequences we need to make it compatible with the applications we
    intend to run, hoping that the resulting feature set will work with many others. It will likely
    need patching to add missing features over its lifetime. We make extensive use of the
    `XTerm control sequence
    documentation <https://invisible-island.net/xterm/ctlseqs/ctlseqs.html>`_, as well as the
    `Wikipedia article on ANSI escape
    codes <https://en.wikipedia.org/wiki/ANSI_escape_code>`_. Where the documentation lacks specificity or otherwise seems incorrect, we experiment
    with a reference implementation to discern and replicate its behavior. The clearest way we know
    to do this is to run the ``tty`` command from the reference terminal to get its
    pseudo-terminal (pty) file name. Then, we use Python from a separate terminal to write test
    sequences to it and/or read sequences from it. We use the ``sleep`` command to prevent Bash
    from reading its own terminal. This same process is applied to test our implementation.
     
     
    
    The applications we've tested with include, without regard to version:
     
    * ``bash``
    * ``less``
    * ``vim``
    * ``gdb -tui``
    * ``termmines`` (from our Debugger training exercises)
    
     
     
    
    Some known issues:
     
    * It seems Java does not provide all the key modifier information, esp., the meta key. Either
    that or Ghidra's intercepting them. Thus, we can't encode those modifiers.
    * Many control sequences are not implemented. They're intentionally left to be implemented on
    an as-needed basis.
    * We inherit many of the erroneous key encodings, e.g., for F1-F4, present in the reference
    implementation.
    * Character sets are incomplete. The box/line drawing set is most important to us as it's used
    by``gdb -tui``. Historically, these charsets are used to encode international characters.
    Modern systems (and terminal emulators) support Unicode (though perhaps only UTF-8), but it's not
    obvious how that interacts with the legacy charset switching. It's also likely many applications,
    despite UTF-8 being available, will still use the legacy charset switching, esp., for box
    drawing. Furthermore, because it's tedious work to figure the mapping for every character in a
    charset, we've only cared to implement a portion of the box-drawing charset, and it's sorely
    incomplete.
    """

    class_: typing.ClassVar[java.lang.Class]

    def cleanTerminated(self):
        """
        Remove all terminals whose sessions have terminated from the tool
         
         
        
        This is done automatically when creating any new terminal.
        """

    @typing.overload
    def createNullTerminal(self, helpPlugin: ghidra.framework.plugintool.Plugin, charset: java.nio.charset.Charset, outputCb: ghidra.app.plugin.core.terminal.vt.VtOutput) -> Terminal:
        """
        Create a terminal not connected to any particular application.
         
         
        
        To display application output, use :meth:`Terminal.injectDisplayOutput(java.nio.ByteBuffer) <Terminal.injectDisplayOutput>`.
        Application input is delivered to the given terminal output callback. If the application is
        connected via streams, esp., those from a pty, consider using
        :meth:`createWithStreams(Plugin, Charset, InputStream, OutputStream) <.createWithStreams>`, instead.
        
        :param ghidra.framework.plugintool.Plugin helpPlugin: the invoking plugin, which ought to provide a help topic for this terminal.
        :param java.nio.charset.Charset charset: the character set for the terminal. See note in
                    :meth:`createWithStreams(Plugin, Charset, InputStream, OutputStream) <.createWithStreams>`.
        :param ghidra.app.plugin.core.terminal.vt.VtOutput outputCb: callback for output from the terminal, i.e., the application's input.
        :return: the terminal
        :rtype: Terminal
        """

    @typing.overload
    def createNullTerminal(self, charset: java.nio.charset.Charset, outputCb: ghidra.app.plugin.core.terminal.vt.VtOutput) -> Terminal:
        """
        
        
        :param java.nio.charset.Charset charset: the character set for the terminal. See note in
                    :meth:`createWithStreams(Plugin, Charset, InputStream, OutputStream) <.createWithStreams>`.
        :param ghidra.app.plugin.core.terminal.vt.VtOutput outputCb: callback for output from the terminal, i.e., the application's input.
        :return: the terminal
        :rtype: Terminal
        
        .. seealso::
        
            | :obj:`.createNullTerminal(Plugin, Charset, VtOutput)`
        """

    @typing.overload
    def createWithStreams(self, helpPlugin: ghidra.framework.plugintool.Plugin, charset: java.nio.charset.Charset, in_: java.io.InputStream, out: java.io.OutputStream) -> Terminal:
        """
        Create a terminal connected to the application (or pty session) via the given streams.
        
        :param ghidra.framework.plugintool.Plugin helpPlugin: the invoking plugin, which ought to provide a help topic for this terminal.
        :param java.nio.charset.Charset charset: the character set for the terminal. **NOTE:** Only US-ASCII and UTF-8 have
                    been tested. So long as the bytes 0x00-0x7f map one-to-one with characters with
                    the same code point, it'll probably work. Charsets that require more than one byte
                    to decode those characters will almost certainly break things.
        :param java.io.InputStream in: the application's output, i.e., input for the terminal to display.
        :param java.io.OutputStream out: the application's input, i.e., output from the terminal's keyboard and mouse.
        :return: the terminal
        :rtype: Terminal
        """

    @typing.overload
    def createWithStreams(self, charset: java.nio.charset.Charset, in_: java.io.InputStream, out: java.io.OutputStream) -> Terminal:
        """
        
        
        :param java.nio.charset.Charset charset: the character set for the terminal. **NOTE:** Only US-ASCII and UTF-8 have
                    been tested. So long as the bytes 0x00-0x7f map one-to-one with characters with
                    the same code point, it'll probably work. Charsets that require more than one byte
                    to decode those characters will almost certainly break things.
        :param java.io.InputStream in: the application's output, i.e., input for the terminal to display.
        :param java.io.OutputStream out: the application's input, i.e., output from the terminal's keyboard and mouse.
        :return: the terminal
        :rtype: Terminal
        
        .. seealso::
        
            | :obj:`.createWithStreams(Plugin, Charset, InputStream, OutputStream)`
        """


class FieldMatcher(java.lang.Object):
    """
    This class allows clients to match on multiple field attributes, such as name and offset
    within a parent data type.
     
    
    Use :meth:`FieldMatcher(DataType) <.FieldMatcher>` as an 'empty' or 'ignored' field matcher to signal that any
    field match is considered value.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType):
        """
        Creates an 'empty' matcher that can be used to signal no specific field or offset match
        is required.
        
        :param ghidra.program.model.data.DataType dataType: the non-null data type.
        """

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, fieldName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, offset: typing.Union[jpype.JInt, int]):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getDisplayText(self) -> str:
        """
        Returns a display text for this field matcher, for example, ``Foo.bar``.
        
        :return: the display text
        :rtype: str
        """

    def getFieldName(self) -> str:
        """
        Returns the field name given to this matcher or will attempt to generate a default field
        name using the given data type and offset.
        
        :return: the field name or null
        :rtype: str
        """

    def isIgnored(self) -> bool:
        """
        Signals that no specific field match is required.
        
        :return: true if no field or offset has been specified.
        :rtype: bool
        """

    def matches(self, dtFieldName: typing.Union[java.lang.String, str], dtOffset: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @property
    def ignored(self) -> jpype.JBoolean:
        ...

    @property
    def displayText(self) -> java.lang.String:
        ...

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class DataTypeQueryService(java.lang.Object):
    """
    Simplified datatype service interface to provide query capabilities to a set of open datatype 
    managers.
    
    
    .. seealso::
    
        | :obj:`DataTypeUtilities`
    
        | :obj:`DataTypeManagerService`
    """

    class_: typing.ClassVar[java.lang.Class]

    def findDataTypes(self, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Finds all data types matching the given name.   This method will search all open data type
        archives.
         
        
        Unlike :meth:`DataTypeManagerService.findDataTypes(String, TaskMonitor) <DataTypeManagerService.findDataTypes>`, this method will
        not return ``.conflict`` data types.  If you need those types, then you must call each
        data type manager directly.
         
        
        In the list of types returned, the program data type manager's types will be in the list 
        before types from other archives.
        
        :param java.lang.String or str name: the data type name to find
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the data types
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        
        .. seealso::
        
            | :obj:`DataTypeManagerService.getDataTypeManagers()`
        """

    @deprecated("use promptForDataType(String)")
    def getDataType(self, filterText: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        This method simply calls :meth:`promptForDataType(String) <.promptForDataType>`
        
        
        .. deprecated::
        
        use :meth:`promptForDataType(String) <.promptForDataType>`
        """

    def getDataTypesByPath(self, path: ghidra.program.model.data.DataTypePath) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Get the data type for the given data type path.
         
        
        This method will check each open data type manager for a data type that matches the path.
         
        
        If a type is in the program data type manager, then it will be first in the returned list.
        
        :param ghidra.program.model.data.DataTypePath path: the path
        :return: the data type
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def getProgramDataTypeByPath(self, path: ghidra.program.model.data.DataTypePath) -> ghidra.program.model.data.DataType:
        """
        Get the data type for the given data type path from the program's data type manager.
        
        :param ghidra.program.model.data.DataTypePath path: the path
        :return: the data type; null if the type does not exist
        :rtype: ghidra.program.model.data.DataType
        """

    def getSortedCategoryPathList(self) -> java.util.List[ghidra.program.model.data.CategoryPath]:
        """
        Prompts the user for a data type.  The optional filter text will be used to filter the tree
        of available types.
        Gets the sorted list of all category paths known by this service via its owned 
        DataTypeManagers.  This method can be called frequently, as the underlying data is indexed 
        and only updated as changes are made.  The sorting of the list is done using the 
        natural sort of the :obj:`CategoryPath` objects.
        
        :return: the sorted list of known category paths.
        :rtype: java.util.List[ghidra.program.model.data.CategoryPath]
        """

    def getSortedDataTypeList(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Gets the sorted list of all datatypes known by this service via it's owned DataTypeManagers.
        This method can be called frequently, as the underlying data is indexed and only updated
        as changes are made.  The sorting of the list is done using the :obj:`DataTypeComparator` 
        whose primary sort is based upon the :obj:`DataTypeNameComparator`.
        
        :return: the sorted list of known data types.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    def promptForDataType(self, filterText: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
        """
        Obtain the preferred datatype which corresponds to the specified 
        datatype specified by filterText.  A tool-based service provider
        may prompt the user to select a datatype if more than one possibility
        exists.
        
        :param java.lang.String or str filterText: If not null, this text filters the visible data types to only show those
                        that start with the given text
        :return: the preferred data type (e.g., chosen by the user) or null if no match found 
        or selection was cancelled by user.
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def programDataTypeByPath(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def sortedCategoryPathList(self) -> java.util.List[ghidra.program.model.data.CategoryPath]:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dataTypesByPath(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...

    @property
    def sortedDataTypeList(self) -> java.util.List[ghidra.program.model.data.DataType]:
        ...


class GhidraScriptService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def refreshScriptList(self):
        ...

    def runScript(self, scriptName: typing.Union[java.lang.String, str], listener: ghidra.util.task.TaskListener):
        ...

    def tryToEditFileInEclipse(self, file: generic.jar.ResourceFile) -> bool:
        """
        Attempts to edit the provided file in Eclipse.
        
        :param generic.jar.ResourceFile file: The file to edit in Eclipse.
        :return: True if the file opened in Eclipse; otherwise, false.
        :rtype: bool
        """

    def tryToEditFileInVSCode(self, file: generic.jar.ResourceFile) -> bool:
        """
        Attempts to edit the provided file in Visual Studio Code.
        
        :param generic.jar.ResourceFile file: The file to edit in Visual Studio Code.
        :return: True if the file opened in Visual Studio Code; otherwise, false.
        :rtype: bool
        """


class DebuggerEmulationService(java.lang.Object):
    """
    A service for accessing managed emulators.
     
     
    
    Managed emulators are employed by the UI and trace manager to perform emulation requested by the
    user. Scripts may interact with these managed emulators, or they may instantiate their own
    unmanaged emulators, without using this service.
    """

    class EmulationResult(ghidra.trace.model.time.schedule.Scheduler.RunResult):

        class_: typing.ClassVar[java.lang.Class]

        def snapshot(self) -> int:
            """
            Get the (scratch) snapshot where the emulated state is stored
            
            :return: the snapshot
            :rtype: int
            """


    class RecordEmulationResult(java.lang.Record, DebuggerEmulationService.EmulationResult):
        """
        The result of letting the emulator "run free"
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule, snapshot: typing.Union[jpype.JLong, int], error: java.lang.Throwable):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def error(self) -> java.lang.Throwable:
            ...

        def hashCode(self) -> int:
            ...

        def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule:
            ...

        def snapshot(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class CachedEmulator(java.lang.Record):
        """
        An emulator managed by this service
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, trace: ghidra.trace.model.Trace, emulator: ghidra.pcode.emu.PcodeMachine[typing.Any], writer: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer):
            ...

        @typing.overload
        def __init__(self, trace: ghidra.trace.model.Trace, emulator: ghidra.pcode.emu.PcodeMachine[typing.Any], writer: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer, version: typing.Union[jpype.JLong, int]):
            ...

        def emulator(self) -> ghidra.pcode.emu.PcodeMachine[typing.Any]:
            """
            Get the emulator
             
             
            
            **WARNING:** This emulator belongs to this service. You may interrupt it, but stepping
            it, or otherwise manipulating it without the service's knowledge can lead to unintended
            consequences.
            
            :return: the emulator
            :rtype: ghidra.pcode.emu.PcodeMachine[typing.Any]
            """

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def isValid(self) -> bool:
            """
            Check if this cached emulator is still valid
            
            :return: true if valid
            :rtype: bool
            """

        def toString(self) -> str:
            ...

        def trace(self) -> ghidra.trace.model.Trace:
            """
            Get the trace to which the emulator is bound
            
            :return: the trace
            :rtype: ghidra.trace.model.Trace
            """

        def version(self) -> int:
            ...

        def writer(self) -> ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer:
            ...

        @property
        def valid(self) -> jpype.JBoolean:
            ...


    class EmulatorStateListener(java.lang.Object):
        """
        A listener for changes in emulator state
        """

        class_: typing.ClassVar[java.lang.Class]

        def running(self, emu: DebuggerEmulationService.CachedEmulator):
            """
            An emulator is running
            
            :param DebuggerEmulationService.CachedEmulator emu: the emulator
            """

        def stopped(self, emu: DebuggerEmulationService.CachedEmulator):
            """
            An emulator has stopped
            
            :param DebuggerEmulationService.CachedEmulator emu: the emulator
            """


    class_: typing.ClassVar[java.lang.Class]

    def addStateListener(self, listener: DebuggerEmulationService.EmulatorStateListener):
        """
        Add a listener for emulator state changes
        
        :param DebuggerEmulationService.EmulatorStateListener listener: the listener
        """

    def backgroundEmulate(self, platform: ghidra.trace.model.guest.TracePlatform, time: ghidra.trace.model.time.schedule.TraceSchedule) -> java.util.concurrent.CompletableFuture[java.lang.Long]:
        """
        Invoke :meth:`emulate(Trace, TraceSchedule, TaskMonitor) <.emulate>` in the background
         
         
        
        This is the preferred means of performing definite emulation. Because the underlying emulator
        may request a *blocking* read from a target, it is important that
        :meth:`emulate <.emulate>` is *never* called
        by the Swing thread.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the time coordinates, including initial snap, steps, and p-code steps
        :return: a future which completes with the result of
                :meth:`emulate <.emulate>`
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Long]
        """

    def backgroundRun(self, platform: ghidra.trace.model.guest.TracePlatform, from_: ghidra.trace.model.time.schedule.TraceSchedule, scheduler: ghidra.trace.model.time.schedule.Scheduler) -> java.util.concurrent.CompletableFuture[DebuggerEmulationService.EmulationResult]:
        """
        Invoke :meth:`run(TracePlatform, TraceSchedule, TaskMonitor, Scheduler) <.run>` in the background
         
         
        
        This is the preferred means of performing indefinite emulation, for the same reasons as
        :meth:`emulate <.backgroundEmulate>`.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule from: a schedule for the machine's initial state
        :param ghidra.trace.model.time.schedule.Scheduler scheduler: a thread scheduler for the emulator
        :return: a future which completes with the result of
                :meth:`run <.run>`.
        :rtype: java.util.concurrent.CompletableFuture[DebuggerEmulationService.EmulationResult]
        """

    @typing.overload
    def emulate(self, platform: ghidra.trace.model.guest.TracePlatform, time: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Perform emulation to realize the machine state of the given time coordinates
         
         
        
        Only those address ranges actually modified during emulation are written into the scratch
        space. It is the responsibility of anyone reading from scratch space to retrieve state and/or
        annotations from the initial snap, when needed. The scratch snapshot is given the description
        "``emu:[time]``", where ``[time]`` is the given time parameter as a string.
         
         
        
        The service may use a cached emulator in order to realize the requested machine state. This
        is especially important to ensure that a user stepping forward does not incur ever increasing
        costs. On the other hand, the service should be careful to invalidate cached results when the
        recorded machine state in a trace changes.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the time coordinates, including initial snap, steps, and p-code steps
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation and progress reporting
        :return: the snap in the trace's scratch space where the realized state is stored
        :rtype: int
        :raises CancelledException: if the emulation is cancelled
        """

    @typing.overload
    def emulate(self, trace: ghidra.trace.model.Trace, time: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Emulate using the trace's "host" platform
        
        :param ghidra.trace.model.Trace trace: the trace containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the time coordinates, including initial snap, steps, and p-code steps
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation and progress reporting
        :return: the snap in the trace's scratch space where the realize state is stored
        :rtype: int
        :raises CancelledException: if the emulation is cancelled
        
        .. seealso::
        
            | :obj:`.emulate(TracePlatform, TraceSchedule, TaskMonitor)`
        """

    def getBusyEmulators(self) -> java.util.Collection[DebuggerEmulationService.CachedEmulator]:
        """
        Get the emulators which are current executing
        
        :return: the collection
        :rtype: java.util.Collection[DebuggerEmulationService.CachedEmulator]
        """

    def getCachedEmulator(self, trace: ghidra.trace.model.Trace, time: ghidra.trace.model.time.schedule.TraceSchedule) -> ghidra.pcode.emu.PcodeMachine[typing.Any]:
        """
        Get the cached emulator for the given trace and time
         
         
        
        To guarantee the emulator is present, call
        :meth:`backgroundEmulate(TracePlatform, TraceSchedule) <.backgroundEmulate>` first.
         
        
        **WARNING:** This emulator belongs to this service. Stepping it, or otherwise manipulating
        it without the service's knowledge can lead to unintended consequences.
         
        
        TODO: Should cache by (Platform, Time) instead, but need a way to distinguish platform in the
        trace's time table.
        
        :param ghidra.trace.model.Trace trace: the trace containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the time coordinates, including initial snap, steps, and p-code steps
        :return: the copied p-code frame
        :rtype: ghidra.pcode.emu.PcodeMachine[typing.Any]
        """

    def getEmulatorFactories(self) -> java.util.Collection[ghidra.debug.api.emulation.EmulatorFactory]:
        """
        Get the available emulator factories
        
        :return: the collection of factories
        :rtype: java.util.Collection[ghidra.debug.api.emulation.EmulatorFactory]
        """

    def getEmulatorFactory(self) -> ghidra.debug.api.emulation.EmulatorFactory:
        """
        Get the current emulator factory
        
        :return: the factory
        :rtype: ghidra.debug.api.emulation.EmulatorFactory
        """

    def invalidateCache(self):
        """
        Invalidate the trace's cache of emulated states.
        """

    def launchProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.trace.model.Trace:
        """
        Load the given program into a trace suitable for emulation in the UI, starting at the given
        address
         
         
        
        Note that the program bytes are not actually loaded into the trace. Rather a static mapping
        is generated, allowing the emulator to load bytes from the target program lazily. The trace
        is automatically loaded into the UI (trace manager).
        
        :param ghidra.program.model.listing.Program program: the target program
        :param ghidra.program.model.address.Address address: the initial program counter
        :return: the resulting trace
        :rtype: ghidra.trace.model.Trace
        :raises IOException: if the trace cannot be created
        """

    def removeStateListener(self, listener: DebuggerEmulationService.EmulatorStateListener):
        """
        Remove a listener for emulator state changes
        
        :param DebuggerEmulationService.EmulatorStateListener listener: the listener
        """

    def run(self, platform: ghidra.trace.model.guest.TracePlatform, from_: ghidra.trace.model.time.schedule.TraceSchedule, monitor: ghidra.util.task.TaskMonitor, scheduler: ghidra.trace.model.time.schedule.Scheduler) -> DebuggerEmulationService.EmulationResult:
        """
        Allow the emulator to "run free" until it is interrupted or encounters an error
        
         
        
        The service may perform some preliminary emulation to realize the machine's initial state. If
        the monitor cancels during preliminary emulation, this method throws a
        :obj:`CancelledException`. If the monitor cancels the emulation during the run, it is
        treated the same as interruption. The machine state will be written to the trace in a scratch
        snap and the result returned. Note that the machine could be interrupted having only
        partially executed an instruction. Thus, the schedule may specify p-code operations. The
        schedule will place the program counter on the instruction (or p-code op) causing the
        interruption. Thus, except for breakpoints, attempting to step again will interrupt the
        emulator again.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform containing the initial state
        :param ghidra.trace.model.time.schedule.TraceSchedule from: a schedule for the machine's initial state
        :param ghidra.util.task.TaskMonitor monitor: a monitor cancellation
        :param ghidra.trace.model.time.schedule.Scheduler scheduler: a thread scheduler for the emulator
        :return: the result of emulation
        :rtype: DebuggerEmulationService.EmulationResult
        :raises CancelledException: if the user cancels the task
        """

    def setEmulatorFactory(self, factory: ghidra.debug.api.emulation.EmulatorFactory):
        """
        Set the current emulator factory
         
         
        
        TODO: Should this be set on a per-program, per-trace basis? Need to decide what is saved to
        the tool and what is saved to the program/trace. My inclination is to save current factory to
        the tool, but the config options for each factory to the program/trace.
         
         
        
        TODO: Should there be some opinion service for choosing default configs? Seems overly
        complicated for what it offers. For now, we won't save anything, we'll default to the
        (built-in) concrete emulator, and we won't have configuration options.
        
        :param ghidra.debug.api.emulation.EmulatorFactory factory: the chosen factory
        """

    @property
    def busyEmulators(self) -> java.util.Collection[DebuggerEmulationService.CachedEmulator]:
        ...

    @property
    def emulatorFactories(self) -> java.util.Collection[ghidra.debug.api.emulation.EmulatorFactory]:
        ...

    @property
    def emulatorFactory(self) -> ghidra.debug.api.emulation.EmulatorFactory:
        ...

    @emulatorFactory.setter
    def emulatorFactory(self, value: ghidra.debug.api.emulation.EmulatorFactory):
        ...


class DebuggerPlatformService(java.lang.Object):
    """
    A service to manage the current mapper for active traces
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCurrentMapperFor(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        """
        Get the current mapper for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the mapper, or null
        :rtype: ghidra.debug.api.platform.DebuggerPlatformMapper
        """

    def getMapper(self, trace: ghidra.trace.model.Trace, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        """
        Get a mapper applicable to the given object
         
         
        
        If the trace's current mapper is applicable to the object, it will be returned. Otherwise,
        the service will query the opinions for a new mapper, as in
        :meth:`getNewMapper(Trace, TraceObject, long) <.getNewMapper>` and set it as the current mapper before
        returning. If a new mapper is set, the trace is also initialized for that mapper.
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.trace.model.target.TraceObject object: the object for which a mapper is desired
        :param jpype.JLong or int snap: the snap, usually the current snap
        :return: the mapper, or null if no offer was provided
        :rtype: ghidra.debug.api.platform.DebuggerPlatformMapper
        """

    def getNewMapper(self, trace: ghidra.trace.model.Trace, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        """
        Get a new mapper for the given object, ignoring the trace's current mapper
         
         
        
        This will not replace the trace's current mapper, nor will it initialize the trace for the
        mapper.
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.trace.model.target.TraceObject object: the object for which a mapper is desired
        :param jpype.JLong or int snap: the snap, usually the current snap
        :return: the mapper, or null if no offer was provided
        :rtype: ghidra.debug.api.platform.DebuggerPlatformMapper
        """

    def setCurrentMapperFor(self, trace: ghidra.trace.model.Trace, focus: ghidra.trace.model.target.TraceObject, mapper: ghidra.debug.api.platform.DebuggerPlatformMapper, snap: typing.Union[jpype.JLong, int]):
        """
        Set the current mapper for the trace and initialize the trace for the mapper
        
        :param ghidra.trace.model.Trace trace: the trace whose mapper to assign and initialize
        :param ghidra.trace.model.target.TraceObject focus: the object of focus
        :param ghidra.debug.api.platform.DebuggerPlatformMapper mapper: the mapper
        :param jpype.JLong or int snap: the snap for initializing the trace
        """

    @property
    def currentMapperFor(self) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
        ...


class TraceRmiService(java.lang.Object):
    """
    A service (both in the Ghidra framework sense, and in the network sense) for connecting Trace
    RMI-based back-end debuggers.
     
     
    
    This service connects to back-end debuggers, and/or allows back-end debuggers to connect to it.
    Either way, Ghidra becomes the front-end, acting as the Trace RMI server, and the back-end
    debugger acts as the Trace RMI client. The Ghidra front-end may also send control commands to the
    back-end, e.g., to step, resume, or suspend the target.
    """

    class_: typing.ClassVar[java.lang.Class]

    def acceptOne(self, address: java.net.SocketAddress) -> ghidra.debug.api.tracermi.TraceRmiAcceptor:
        """
        Prepare to accept a single connection by listening on the given address.
         
         
        
        This essentially starts a server (separate from the one creased by :meth:`startServer() <.startServer>`)
        that will accept a single connection. The server is started by this method. The caller can
        then invoke (on the same thread) whatever back-end system or agent that is expected to
        connect back to this service. Assuming that system runs in the background, this thread can
        then invoke :meth:`TraceRmiAcceptor.accept() <TraceRmiAcceptor.accept>` to actually accept that connection. Once
        accepted, the service is terminated, and the server socket is closed. The client socket
        remains open.
        
        :param java.net.SocketAddress address: the socket address to bind, or null for ephemeral
        :return: the acceptor, which can be used to retrieve the ephemeral address and accept the
                actual connection
        :rtype: ghidra.debug.api.tracermi.TraceRmiAcceptor
        :raises IOException: on error
        """

    def addTraceServiceListener(self, listener: ghidra.debug.api.tracermi.TraceRmiServiceListener):
        """
        Add a listener for events on the Trace RMI service
        
        :param ghidra.debug.api.tracermi.TraceRmiServiceListener listener: the listener to add
        """

    def connect(self, address: java.net.SocketAddress) -> ghidra.debug.api.tracermi.TraceRmiConnection:
        """
        Assuming a back-end debugger is listening, connect to it.
        
        :param java.net.SocketAddress address: the address (and port) of the back-end system
        :return: the connection
        :rtype: ghidra.debug.api.tracermi.TraceRmiConnection
        :raises IOException: if the connection failed
        """

    def getAllAcceptors(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiAcceptor]:
        """
        Get all of the acceptors currently listening for a connection
        
        :return: the acceptors
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiAcceptor]
        """

    def getAllConnections(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiConnection]:
        """
        Get all of the active connections
        
        :return: the connections
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiConnection]
        """

    def getServerAddress(self) -> java.net.SocketAddress:
        """
        Get the address (and port) of the Trace RMI TCP server
        
        :return: 
        :rtype: java.net.SocketAddress
        """

    def isServerStarted(self) -> bool:
        """
        Check if the service is listening for inbound connections (other than those expected by
        :meth:`acceptOne(SocketAddress) <.acceptOne>`).
        
        :return: true if listening, false otherwise
        :rtype: bool
        """

    def removeTraceServiceListener(self, listener: ghidra.debug.api.tracermi.TraceRmiServiceListener):
        """
        Remove a listener for events on the Trace RMI service
        
        :param ghidra.debug.api.tracermi.TraceRmiServiceListener listener: the listener to remove
        """

    def setServerAddress(self, serverAddress: java.net.SocketAddress):
        """
        Set the address (and port) of the Trace RMI TCP server
        
        :param java.net.SocketAddress serverAddress: may be null to bind to ephemeral port
        """

    def startServer(self):
        """
        Start the Trace RMI TCP server
        
        :raises IOException:
        """

    def stopServer(self):
        """
        Stop the Trace RMI TCP server
        """

    @property
    def allConnections(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiConnection]:
        ...

    @property
    def serverStarted(self) -> jpype.JBoolean:
        ...

    @property
    def serverAddress(self) -> java.net.SocketAddress:
        ...

    @serverAddress.setter
    def serverAddress(self, value: java.net.SocketAddress):
        ...

    @property
    def allAcceptors(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiAcceptor]:
        ...


class DebuggerTraceManagerService(java.lang.Object):
    """
    The interface for managing open traces and navigating among them and their contents
    """

    class ActivationCause(java.lang.Enum[DebuggerTraceManagerService.ActivationCause]):
        """
        The reason coordinates were activated
        """

        class_: typing.ClassVar[java.lang.Class]
        USER: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The change was driven by the user
         
         
        
        TODO: Distinguish between API and GUI?
        """

        USER_ALT: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The request was driven by the user, but its some alternative view, e.g., to compare
        snapshots
        """

        TARGET_UPDATED: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        A trace was activated because a target was published or withdrawn
        """

        SYNC_MODEL: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The change was driven by the model activation, possibly indirectly by the user
        """

        FOLLOW_PRESENT: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The change was driven by the recorder advancing a snapshot
        """

        EMU_STATE_EDIT: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The tool is activating scratch coordinates to display an emulator state change
        """

        MAPPER_CHANGED: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The change was caused by a change to the mapper selection, probably indirectly by the
        user
        """

        ACTIVATE_DEFAULT: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        Some default coordinates were activated
         
         
        
        Please don't misunderstand this as the "default cause." Rather, e.g., when the current
        trace is closed, and the manager needs to activate new coordinates, it is activating
        "default coordinates."
        """

        RESTORE_STATE: typing.Final[DebuggerTraceManagerService.ActivationCause]
        """
        The tool is restoring its data state
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerTraceManagerService.ActivationCause:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerTraceManagerService.ActivationCause]:
            ...


    class BooleanChangeAdapter(ghidra.util.TriConsumer[java.lang.Boolean, java.lang.Boolean, java.lang.Void]):
        """
        An adapter that works nicely with an :obj:`AsyncReference`
         
         
        
        TODO: Seems this is still leaking an implementation detail
        """

        class_: typing.ClassVar[java.lang.Class]

        def changed(self, value: typing.Union[java.lang.Boolean, bool]):
            """
            The value has changed
            
            :param java.lang.Boolean or bool value: the new value
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def activate(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        """
        Activate the given coordinates, caused by the user
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the desired coordinates
        
        .. seealso::
        
            | :obj:`.activate(DebuggerCoordinates, ActivationCause)`
        """

    @typing.overload
    def activate(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, cause: DebuggerTraceManagerService.ActivationCause):
        """
        Activate the given coordinates, synchronizing the current target, if possible
         
         
        
        If asynchronous notification is needed, use
        :meth:`activateAndNotify(DebuggerCoordinates, ActivationCause) <.activateAndNotify>`.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the desired coordinates
        :param DebuggerTraceManagerService.ActivationCause cause: the cause of activation
        """

    def activateAndNotify(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, cause: DebuggerTraceManagerService.ActivationCause) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Activate the given coordinates with future notification
         
         
        
        This operation may be completed asynchronously, esp., if emulation is required to materialize
        the coordinates. The returned future is completed when the coordinates are actually
        materialized and active. The coordinates are "resolved" as a means of filling in missing
        parts. For example, if the thread is not specified, the manager may activate the last-active
        thread for the desired trace.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the desired coordinates
        :param DebuggerTraceManagerService.ActivationCause cause: the cause of the activation
        :return: a future which completes when emulation and navigation is complete
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def activateFrame(self, frameLevel: typing.Union[jpype.JInt, int]):
        """
        Activate the given stack frame
        
        :param jpype.JInt or int frameLevel: the level of the desired frame, 0 being innermost
        """

    def activateObject(self, object: ghidra.trace.model.target.TraceObject):
        """
        Activate the given object
        
        :param ghidra.trace.model.target.TraceObject object: the desired object
        """

    def activatePath(self, path: ghidra.trace.model.target.path.KeyPath):
        """
        Activate the given canonical object path
        
        :param ghidra.trace.model.target.path.KeyPath path: the desired path
        """

    def activatePlatform(self, platform: ghidra.trace.model.guest.TracePlatform):
        """
        Activate the given platform
        
        :param ghidra.trace.model.guest.TracePlatform platform: the desired platform
        """

    def activateSnap(self, snap: typing.Union[jpype.JLong, int]):
        """
        Activate the given snapshot key
        
        :param jpype.JLong or int snap: the desired snapshot key
        """

    def activateTarget(self, target: ghidra.debug.api.target.Target):
        """
        Activate the given target
        
        :param ghidra.debug.api.target.Target target: the desired target
        """

    def activateThread(self, thread: ghidra.trace.model.thread.TraceThread):
        """
        Activate the given thread
        
        :param ghidra.trace.model.thread.TraceThread thread: the desired thread
        """

    def activateTime(self, time: ghidra.trace.model.time.schedule.TraceSchedule):
        """
        Activate the given point in time, possibly invoking emulation
        
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the desired schedule
        """

    def activateTrace(self, trace: ghidra.trace.model.Trace):
        """
        Activate the given trace
        
        :param ghidra.trace.model.Trace trace: the desired trace
        """

    def addAutoCloseOnTerminateChangeListener(self, listener: DebuggerTraceManagerService.BooleanChangeAdapter):
        """
        Add a listener for changes to close-on-terminate enablement
        
        :param DebuggerTraceManagerService.BooleanChangeAdapter listener: the listener to receive change notifications
        """

    def addSaveTracesByDefaultChangeListener(self, listener: DebuggerTraceManagerService.BooleanChangeAdapter):
        """
        Add a listener for changes to save-by-default enablement
        
        :param DebuggerTraceManagerService.BooleanChangeAdapter listener: the listener to receive change notifications
        """

    def closeAllTraces(self):
        """
        Close all traces
        """

    def closeDeadTraces(self):
        """
        Close all traces which are not the destination of a live recording
         
         
        
        Operation of this method depends on the model service. If that service is not present, this
        method performs no operation at all.
        """

    def closeOtherTraces(self, keep: ghidra.trace.model.Trace):
        """
        Close all traces except the given one
        
        :param ghidra.trace.model.Trace keep: the trace to keep open
        """

    def closeTrace(self, trace: ghidra.trace.model.Trace):
        """
        Close the given trace
        
        :param ghidra.trace.model.Trace trace: the trace to close
        """

    def closeTraceNoConfirm(self, trace: ghidra.trace.model.Trace):
        """
        Close the given trace without confirmation
         
         
        
        Ordinarily, :meth:`closeTrace(Trace) <.closeTrace>` will prompt the user to confirm termination of live
        targets associated with traces to be closed. Such prompts can cause issues during automated
        tests.
        
        :param ghidra.trace.model.Trace trace: the trace to close
        """

    def findSnapshot(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> int:
        """
        If the given coordinates are already materialized, get the snapshot
         
         
        
        If the coordinates do not include a schedule, this simply returns the coordinates' snapshot.
        Otherwise, it searches for the first snapshot whose schedule is the coordinates' schedule.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
        :return: the materialized snapshot key, or null if not materialized.
        :rtype: int
        """

    def getCurrent(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Get the current coordinates
         
         
        
        This entails everything except the current address.
        
        :return: the current coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    def getCurrentFor(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Get the current coordinates for a given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the current coordinates for the trace
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    def getCurrentFrame(self) -> int:
        """
        Get the active frame
        
        :return: the active frame, or 0
        :rtype: int
        """

    def getCurrentObject(self) -> ghidra.trace.model.target.TraceObject:
        """
        Get the active object
        
        :return: the active object, or null
        :rtype: ghidra.trace.model.target.TraceObject
        """

    def getCurrentPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        """
        Get the active platform
        
        :return: the active platform, or null
        :rtype: ghidra.trace.model.guest.TracePlatform
        """

    def getCurrentSnap(self) -> int:
        """
        Get the active snap
         
         
        
        Note that if emulation was used to materialize the current coordinates, then the current snap
        will differ from the view's snap.
        
        :return: the active snap, or 0
        :rtype: int
        """

    def getCurrentThread(self) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the active thread
         
         
        
        It is possible to have an active trace, but no active thread.
        
        :return: the active thread, or null
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getCurrentTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the active trace
        
        :return: the active trace, or null
        :rtype: ghidra.trace.model.Trace
        """

    def getCurrentView(self) -> ghidra.trace.model.program.TraceProgramView:
        """
        Get the active view
         
         
        
        Every trace has an associated variable-snap view. When the manager navigates to a new point
        in time, it is accomplished by changing the snap of this view. This view is suitable for use
        in most places where a :obj:`Program` is ordinarily required.
        
        :return: the active view, or null
        :rtype: ghidra.trace.model.program.TraceProgramView
        """

    def getOpenTraces(self) -> java.util.Collection[ghidra.trace.model.Trace]:
        """
        Get all the open traces
        
        :return: all open traces
        :rtype: java.util.Collection[ghidra.trace.model.Trace]
        """

    def isAutoCloseOnTerminate(self) -> bool:
        """
        Check whether live traces are automatically closed upon target termination
        
        :return: true if automatically closed, false if left open
        :rtype: bool
        """

    def isSaveTracesByDefault(self) -> bool:
        """
        Check whether traces should by saved by default
        
        :return: true if saved by default, false otherwise
        :rtype: bool
        """

    def materialize(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> java.util.concurrent.CompletableFuture[java.lang.Long]:
        """
        Materialize the given coordinates to a snapshot in the same trace
         
         
        
        If the given coordinates do not require emulation, then this must complete immediately with
        the snapshot key given by the coordinates. If the given schedule is already materialized in
        the trace, then this may complete immediately with the previously-materialized snapshot key.
        Otherwise, this must invoke emulation, store the result into a chosen snapshot, and complete
        with its key.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates to materialize
        :return: a future that completes with the snapshot key of the materialized coordinates
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Long]
        """

    @typing.overload
    def openTrace(self, trace: ghidra.trace.model.Trace):
        """
        Open a trace
         
         
        
        This does not activate the trace. Use :meth:`activateTrace(Trace) <.activateTrace>` or
        :meth:`activateThread(TraceThread) <.activateThread>` if necessary.
        
        :param ghidra.trace.model.Trace trace: the trace to open
        """

    @typing.overload
    def openTrace(self, file: ghidra.framework.model.DomainFile, version: typing.Union[jpype.JInt, int]) -> ghidra.trace.model.Trace:
        """
        Open a trace from a domain file
        
        :param ghidra.framework.model.DomainFile file: the domain file to open
        :param jpype.JInt or int version: the version (read-only if non-default)
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        :raises ClassCastException: if the domain object contains a non-trace object
        """

    def openTraces(self, files: collections.abc.Sequence) -> java.util.Collection[ghidra.trace.model.Trace]:
        """
        Open traces from a collection of domain files
         
         
        
        Iterating the returned trace collection orders each trace by position of its file in the
        input file collection.
        
        :param collections.abc.Sequence files: the domain files
        :return: the traces opened
        :rtype: java.util.Collection[ghidra.trace.model.Trace]
        """

    def removeAutoCloseOnTerminateChangeListener(self, listener: DebuggerTraceManagerService.BooleanChangeAdapter):
        """
        Remove a listener for changes to close-on-terminate enablement
        
        :param DebuggerTraceManagerService.BooleanChangeAdapter listener: the listener receiving change notifications
        """

    def removeSaveTracesByDefaultChangeListener(self, listener: DebuggerTraceManagerService.BooleanChangeAdapter):
        """
        Remove a listener for changes to save-by-default enablement
        
        :param DebuggerTraceManagerService.BooleanChangeAdapter listener: the listener receiving change notifications
        """

    def resolveFrame(self, frameLevel: typing.Union[jpype.JInt, int]) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given frame level using the manager's "best judgment"
        
        :param jpype.JInt or int frameLevel: the frame level, 0 being the innermost
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveObject(self, object: ghidra.trace.model.target.TraceObject) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given object using the manager's "best judgment"
        
        :param ghidra.trace.model.target.TraceObject object: the object
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolvePath(self, path: ghidra.trace.model.target.path.KeyPath) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given object path using the manager's "best judgment"
        
        :param ghidra.trace.model.target.path.KeyPath path: the path
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolvePlatform(self, platform: ghidra.trace.model.guest.TracePlatform) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given platform using the manager's "best judgment"
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveSnap(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given snap using the manager's "best judgment"
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveTarget(self, target: ghidra.debug.api.target.Target) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given target using the manager's "best judgment"
        
        :param ghidra.debug.api.target.Target target: the target
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveThread(self, thread: ghidra.trace.model.thread.TraceThread) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given thread using the manager's "best judgment"
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveTime(self, time: ghidra.trace.model.time.schedule.TraceSchedule) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given time using the manager's "best judgment"
        
        :param ghidra.trace.model.time.schedule.TraceSchedule time: the time
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def resolveTrace(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given trace using the manager's "best judgment"
         
         
        
        The manager may use a variety of sources of context including the current trace, the last
        coordinates for a trace, the target's last/current activation, the list of live threads, etc.
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    def resolveView(self, view: ghidra.trace.model.program.TraceProgramView) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Resolve coordinates for the given view using the manager's "best judgment"
        
        :param ghidra.trace.model.program.TraceProgramView view: the view
        :return: the best coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        
        .. seealso::
        
            | :obj:`.resolveTrace(Trace)`
        """

    def saveTrace(self, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Save the trace to the "New Traces" folder of the project
         
         
        
        If a different domain file of the trace's name already exists, an incrementing integer is
        appended. Errors are handled in the same fashion as saving a program, so there is little/no
        need to invoke :meth:`CompletableFuture.exceptionally(java.util.function.Function) <CompletableFuture.exceptionally>` on the
        returned future. The future is returned as a means of registering follow-up actions.
         
         
        
        TODO: Support save-as, prompting to overwrite, etc?
        
        :param ghidra.trace.model.Trace trace: the trace to save
        :return: a future which completes when the save is finished
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def setAutoCloseOnTerminate(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Control whether live traces are automatically closed upon target termination
        
        :param jpype.JBoolean or bool enabled: true to automatically close, false to leave open
        """

    def setSaveTracesByDefault(self, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Control whether traces should be saved by default
        
        :param jpype.JBoolean or bool enabled: true to save by default, false otherwise
        """

    @property
    def autoCloseOnTerminate(self) -> jpype.JBoolean:
        ...

    @autoCloseOnTerminate.setter
    def autoCloseOnTerminate(self, value: jpype.JBoolean):
        ...

    @property
    def currentThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def current(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def saveTracesByDefault(self) -> jpype.JBoolean:
        ...

    @saveTracesByDefault.setter
    def saveTracesByDefault(self, value: jpype.JBoolean):
        ...

    @property
    def currentPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...

    @property
    def currentSnap(self) -> jpype.JLong:
        ...

    @property
    def currentFor(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def currentFrame(self) -> jpype.JInt:
        ...

    @property
    def currentView(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    @property
    def currentObject(self) -> ghidra.trace.model.target.TraceObject:
        ...

    @property
    def currentTrace(self) -> ghidra.trace.model.Trace:
        ...


class TraceRmiLauncherService(java.lang.Object):
    """
    The service for launching Trace RMI targets in the GUI.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffers(self, program: ghidra.program.model.listing.Program) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get all offers for the given program
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the offers
        :rtype: java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    def getSavedOffers(self, program: ghidra.program.model.listing.Program) -> java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        """
        Get offers with a saved configuration, ordered by most-recently-saved
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the offers
        :rtype: java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]
        """

    @property
    def offers(self) -> java.util.Collection[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        ...

    @property
    def savedOffers(self) -> java.util.List[ghidra.debug.api.tracermi.TraceRmiLaunchOffer]:
        ...


class DebuggerWatchesService(java.lang.Object):
    """
    A service interface for controlling the Watches window
    """

    class_: typing.ClassVar[java.lang.Class]

    def addWatch(self, expression: typing.Union[java.lang.String, str]) -> ghidra.debug.api.watch.WatchRow:
        """
        Add a watch
        
        :param java.lang.String or str expression: the Sleigh expression
        :return: the new row
        :rtype: ghidra.debug.api.watch.WatchRow
        """

    def getWatches(self) -> java.util.Collection[ghidra.debug.api.watch.WatchRow]:
        """
        Get the current watches
        
        :return: the unmodifiable collection of watches
        :rtype: java.util.Collection[ghidra.debug.api.watch.WatchRow]
        """

    def removeWatch(self, watch: ghidra.debug.api.watch.WatchRow):
        """
        Remove a watch
        
        :param ghidra.debug.api.watch.WatchRow watch: the row to remove
        """

    @property
    def watches(self) -> java.util.Collection[ghidra.debug.api.watch.WatchRow]:
        ...


class DebuggerStaticMappingService(java.lang.Object):
    """
    A service for consuming and mutating trace static mappings, i.e., relocations
     
     
    
    This service consumes and tracks all open traces' mappings, tracks when the destination programs
    are opened and closed, notifies listeners of changes in the tool's overall mapping picture, and
    provides for addition and validation of new mappings.
     
     
    
    Note, the relation of trace locations to program locations is many-to-one.
     
     
    
    This service also provides methods for proposing and adding mappings.
    """

    class MappedAddressRange(java.lang.Comparable[DebuggerStaticMappingService.MappedAddressRange]):
        """
        A pair for describing sets of mapped addresses
         
         
        
        Note, the natural order is by the *destination* address.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, srcRange: ghidra.program.model.address.AddressRange, dstRange: ghidra.program.model.address.AddressRange):
            ...

        def getDestinationAddressRange(self) -> ghidra.program.model.address.AddressRange:
            """
            Get the destination address range
            
            :return: the address range
            :rtype: ghidra.program.model.address.AddressRange
            """

        def getShift(self) -> int:
            """
            Get the shift from the source address range to this address range
             
             
            
            The meaning depends on what returned this view. If this view is the "static" range, then
            this shift describes what was added to the offset of the "dynamic" address to get a
            particular address in the "static" range.
            
            :return: the shift
            :rtype: int
            """

        def getSourceAddressRange(self) -> ghidra.program.model.address.AddressRange:
            """
            Get the source address range
            
            :return: the address range
            :rtype: ghidra.program.model.address.AddressRange
            """

        @typing.overload
        def mapDestinationToSource(self, daddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
            """
            Map an address in the destination range to the corresponding address in the source range
            
            :param ghidra.program.model.address.Address daddr: the destination address (not validated)
            :return: the source address
            :rtype: ghidra.program.model.address.Address
            """

        @typing.overload
        def mapDestinationToSource(self, drng: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
            """
            Map a sub-range of the destination to the corresponding sub-range of the source
            
            :param ghidra.program.model.address.AddressRange drng: the destination sub-range
            :return: the source sub-range
            :rtype: ghidra.program.model.address.AddressRange
            """

        @typing.overload
        def mapSourceToDestination(self, saddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
            """
            Map an address in the source range to the corresponding address in the destination range
            
            :param ghidra.program.model.address.Address saddr: the source address (not validated)
            :return: the destination address
            :rtype: ghidra.program.model.address.Address
            """

        @typing.overload
        def mapSourceToDestination(self, srng: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
            """
            Map a sub-range of the source to the corresponding sub-range of the destination
            
            :param ghidra.program.model.address.AddressRange srng: the source sub-range
            :return: the destination sub-range
            :rtype: ghidra.program.model.address.AddressRange
            """

        @property
        def destinationAddressRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def sourceAddressRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @property
        def shift(self) -> jpype.JLong:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, l: ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        """
        Add a listener for changes in mappings
         
         
        
        Note, the caller must ensure a strong reference to the listener is maintained, or it will be
        removed automatically.
        
        :param ghidra.debug.api.modules.DebuggerStaticMappingChangeListener l: the listener
        """

    def addIdentityMapping(self, from_: ghidra.trace.model.Trace, toProgram: ghidra.program.model.listing.Program, lifespan: ghidra.trace.model.Lifespan, truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add a static mapping from the given trace to the given program, using identical addresses
        
        :param ghidra.trace.model.Trace from: the source trace
        :param ghidra.program.model.listing.Program toProgram: the destination program
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the mapping
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries. If
                    false, overlapping entries are omitted.
        """

    @typing.overload
    def addMapping(self, from_: ghidra.trace.model.TraceLocation, to: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JLong, int], truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add a static mapping (relocation) from the given trace to the given program
        
        :param ghidra.trace.model.TraceLocation from: the source trace location, including lifespan
        :param ghidra.program.util.ProgramLocation to: the destination program location
        :param jpype.JLong or int length: the length of the mapped region, where 0 indicates ``1 << 64``.
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries
        :raises TraceConflictedMappingException: if a conflicting mapping overlaps the source and
                    ``truncateExisting`` is false.
        """

    @typing.overload
    def addMapping(self, entry: ghidra.debug.api.modules.MapEntry[typing.Any, typing.Any], truncateExisting: typing.Union[jpype.JBoolean, bool]):
        ...

    def addMappings(self, entries: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, truncateExisting: typing.Union[jpype.JBoolean, bool], description: typing.Union[java.lang.String, str]):
        ...

    def addModuleMappings(self, entries: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add several static mappings (relocations)
         
         
        
        This will group the entries by trace and add each's entries in a single transaction. If any
        entry fails, including due to conflicts, that failure is logged but ignored, and the
        remaining entries are processed.
         
         
        
        Any entries indicated for memorization will have their module paths added to the destination
        program's metadata.
        
        :param collections.abc.Sequence entries: the entries to add
        :param ghidra.util.task.TaskMonitor monitor: a monitor to cancel the operation
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries
        :raises CancelledException: if the user cancels
        :raises TraceConflictedMappingException: if a conflicting mapping overlaps the source and
                    ``truncateExisting`` is false.
        
        .. seealso::
        
            | :obj:`.addMapping(TraceLocation, ProgramLocation, long, boolean)`
        """

    def addRegionMappings(self, entries: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add several static mappings (relocations)
         
         
        
        This will group the entries by trace and add each's entries in a single transaction. If any
        entry fails, including due to conflicts, that failure is logged but ignored, and the
        remaining entries are processed.
        
        :param collections.abc.Sequence entries: the entries to add
        :param ghidra.util.task.TaskMonitor monitor: a monitor to cancel the operation
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries
        :raises CancelledException: if the user cancels
        
        .. seealso::
        
            | :obj:`.addMapping(TraceLocation, ProgramLocation, long, boolean)`
        """

    def addSectionMappings(self, entries: collections.abc.Sequence, monitor: ghidra.util.task.TaskMonitor, truncateExisting: typing.Union[jpype.JBoolean, bool]):
        """
        Add several static mappings (relocations)
         
         
        
        This will group the entries by trace and add each's entries in a single transaction. If any
        entry fails, including due to conflicts, that failure is logged but ignored, and the
        remaining entries are processed.
        
        :param collections.abc.Sequence entries: the entries to add
        :param ghidra.util.task.TaskMonitor monitor: a monitor to cancel the operation
        :param jpype.JBoolean or bool truncateExisting: true to delete or truncate the lifespan of overlapping entries
        :raises CancelledException: if the user cancels
        
        .. seealso::
        
            | :obj:`.addMapping(TraceLocation, ProgramLocation, long, boolean)`
        """

    def changesSettled(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Get a future which completes when pending changes have all settled
         
         
        
        The returned future completes after all change listeners have been invoked.
        
        :return: the future
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def findBestModuleProgram(self, space: ghidra.program.model.address.AddressSpace, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int]) -> ghidra.framework.model.DomainFile:
        """
        Find the best match among programs in the project for the given trace module
         
         
        
        The service maintains an index of likely module names to domain files in the active project.
        This will search that index for the module's full file path. Failing that, it will search
        just for the module's file name. Among the programs found, it first prefers those whose
        module name list includes the sought module. Then, it prefers those whose executable path
        (see :meth:`Program.setExecutablePath(String) <Program.setExecutablePath>`) matches the sought module. Finally, it
        prefers matches on the program name and the domain file name. Ties in name matching are
        broken by looking for domain files in the same folders as those programs already mapped into
        the trace in the given address space.
        
        :param ghidra.program.model.address.AddressSpace space: the fallback address space if the module is missing its base
        :param ghidra.trace.model.modules.TraceModule module: the trace module
        :param jpype.JLong or int snap: the snapshot to consider
        :return: the, possibly empty, set of probable matches
        :rtype: ghidra.framework.model.DomainFile
        """

    def getDynamicLocationFromStatic(self, view: ghidra.trace.model.program.TraceProgramView, loc: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        """
        Similar to :meth:`getOpenMappedLocation(Trace, ProgramLocation, long) <.getOpenMappedLocation>` but preserves details
         
         
        
        This method derives the source trace and snap from the given view. Additinoally, this will
        attempt to map over other "location" details, e.g., field, row, column.
        
        :param ghidra.trace.model.program.TraceProgramView view: the view, specifying the source trace and snap, to which we are mapping back
        :param ghidra.program.util.ProgramLocation loc: the destination location, from which we are mapping back.
        :return: the destination of the found mapping, or ``null`` if not mapped
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def getOpenMappedLocation(self, loc: ghidra.trace.model.TraceLocation) -> ghidra.program.util.ProgramLocation:
        """
        Map the given trace location to a program location, if the destination is open
        
        :param ghidra.trace.model.TraceLocation loc: the source location
        :return: the destination location, or ``null`` if not mapped, or not open
        :rtype: ghidra.program.util.ProgramLocation
        """

    @typing.overload
    def getOpenMappedLocation(self, trace: ghidra.trace.model.Trace, loc: ghidra.program.util.ProgramLocation, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.TraceLocation:
        """
        Map the given program location back to a source trace and snap
        
        :param ghidra.trace.model.Trace trace: the source trace, to which we are mapping back
        :param ghidra.program.util.ProgramLocation loc: the destination location, from which we are mapping back
        :param jpype.JLong or int snap: the source snap, to which we are mapping back
        :return: the source of the found mapping, or ``null`` if not mapped
        :rtype: ghidra.trace.model.TraceLocation
        """

    def getOpenMappedLocations(self, loc: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.trace.model.TraceLocation]:
        """
        Map the given program location back to open source trace locations
        
        :param ghidra.program.util.ProgramLocation loc: the program location
        :return: the, possibly empty, set of trace locations
        :rtype: java.util.Set[ghidra.trace.model.TraceLocation]
        """

    def getOpenMappedProgramsAtSnap(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> java.util.Set[ghidra.program.model.listing.Program]:
        """
        Collect all the open destination programs relevant for the given trace and snap
        
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :return: the set of open destination programs
        :rtype: java.util.Set[ghidra.program.model.listing.Program]
        """

    @typing.overload
    def getOpenMappedViews(self, trace: ghidra.trace.model.Trace, set: ghidra.program.model.address.AddressSetView, snap: typing.Union[jpype.JLong, int]) -> java.util.Map[ghidra.program.model.listing.Program, java.util.Collection[DebuggerStaticMappingService.MappedAddressRange]]:
        """
        Find/compute all destination address sets given a source trace address set
        
        :param ghidra.trace.model.Trace trace: the source trace
        :param ghidra.program.model.address.AddressSetView set: the source address set
        :param jpype.JLong or int snap: the source snap
        :return: a map of destination programs to corresponding computed destination address ranges
        :rtype: java.util.Map[ghidra.program.model.listing.Program, java.util.Collection[DebuggerStaticMappingService.MappedAddressRange]]
        """

    @typing.overload
    def getOpenMappedViews(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView) -> java.util.Map[ghidra.trace.model.TraceSpan, java.util.Collection[DebuggerStaticMappingService.MappedAddressRange]]:
        """
        Find/compute all source address sets given a destination program address set
        
        :param ghidra.program.model.listing.Program program: the destination program, from which we are mapping back
        :param ghidra.program.model.address.AddressSetView set: the destination address set, from which we are mapping back
        :return: a map of source traces to corresponding computed source address ranges
        :rtype: java.util.Map[ghidra.trace.model.TraceSpan, java.util.Collection[DebuggerStaticMappingService.MappedAddressRange]]
        """

    def getStaticLocationFromDynamic(self, loc: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation:
        """
        Similar to :meth:`getOpenMappedLocation(TraceLocation) <.getOpenMappedLocation>` but preserves details
         
         
        
        The given location's :meth:`ProgramLocation.getProgram() <ProgramLocation.getProgram>` method must return a
        :obj:`TraceProgramView`. It derives the trace and snap from that view. Additionally, this
        will attempt to map over other "location" details, e.g., field, row, column.
        
        :param ghidra.program.util.ProgramLocation loc: a location within a trace view
        :return: a mapped location in a program, or ``null``
        :rtype: ghidra.program.util.ProgramLocation
        """

    def openMappedProgramsInView(self, trace: ghidra.trace.model.Trace, set: ghidra.program.model.address.AddressSetView, snap: typing.Union[jpype.JLong, int], failures: java.util.Set[java.lang.Exception]) -> java.util.Set[ghidra.program.model.listing.Program]:
        """
        Open all destination programs in mappings intersecting the given source trace, address set,
        and snap
         
         
        
        Note, because the trace's mapping table contains :obj:`Program` URLs, it's possible the
        destination program(s) do not exist, and/or that there may be errors opening the destinations
        program(s).
         
         
        
        Note, the caller to this method should not expect the relevant mappings to be immediately
        loaded by the manager implementation. Instead, it should listen for the expected changes in
        mappings before proceeding.
        
        :param ghidra.trace.model.Trace trace: the source trace
        :param ghidra.program.model.address.AddressSetView set: the source address set
        :param jpype.JLong or int snap: the source snap
        :param java.util.Set[java.lang.Exception] failures: a, possibly empty, set of failures encountered when opening the programs
        :return: the set of destination programs in the relevant mappings, including those already
                open
        :rtype: java.util.Set[ghidra.program.model.listing.Program]
        """

    @typing.overload
    def proposeModuleMap(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program) -> ghidra.debug.api.modules.ModuleMapProposal:
        """
        Propose a module map for the given module to the given program
         
         
        
        Note, no sanity check is performed on the given parameters. This will simply propose the
        given module-program pair. It is strongly advised to use
        :meth:`ModuleMapProposal.computeScore() <ModuleMapProposal.computeScore>` to assess the proposal. Alternatively, use
        :meth:`proposeModuleMap(TraceModule, long, Collection) <.proposeModuleMap>` to have the service select the
        best-scored mapping from a collection of proposed programs.
        
        :param ghidra.trace.model.modules.TraceModule module: the module to consider
        :param jpype.JLong or int snap: the source snapshot key
        :param ghidra.program.model.listing.Program program: the destination program to consider
        :return: the proposal
        :rtype: ghidra.debug.api.modules.ModuleMapProposal
        """

    @typing.overload
    def proposeModuleMap(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> ghidra.debug.api.modules.ModuleMapProposal:
        """
        Compute the best-scored module map for the given module and programs
         
         
        
        Note, no sanity check is performed on any given module-program pair. Instead, the
        highest-scoring proposal is selected from the possible module-program pairs. In particular,
        the names of the programs vs. the module name may not be examined by the implementation.
        
        :param ghidra.trace.model.modules.TraceModule module: the module to consider
        :param jpype.JLong or int snap: the source snapshot key
        :param collections.abc.Sequence programs: a set of proposed destination programs
        :return: the best-scored proposal, or ``null`` if no program is proposed
        :rtype: ghidra.debug.api.modules.ModuleMapProposal
        
        .. seealso::
        
            | :obj:`ModuleMapProposal.computeScore()`
        """

    def proposeModuleMaps(self, modules: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> java.util.Map[ghidra.trace.model.modules.TraceModule, ghidra.debug.api.modules.ModuleMapProposal]:
        """
        Compute the "best" map of trace module to program for each given module given a collection of
        proposed programs.
         
         
        
        Note, this method will first examine module and program names in order to cull unlikely
        pairs. It then takes the best-scored proposal for each module. If a module has no likely
        paired program, then it is omitted from the result, i.e.., the returned map will have no
        ``null`` values.
        
        :param collections.abc.Sequence modules: the modules to map
        :param jpype.JLong or int snap: the source snapshot key
        :param collections.abc.Sequence programs: the set of proposed destination programs
        :return: the proposal
        :rtype: java.util.Map[ghidra.trace.model.modules.TraceModule, ghidra.debug.api.modules.ModuleMapProposal]
        """

    @typing.overload
    def proposeRegionMap(self, region: ghidra.trace.model.memory.TraceMemoryRegion, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock) -> ghidra.debug.api.modules.RegionMapProposal:
        """
        Propose a singleton region map from the given region to the given program memory block
         
         
        
        Note, no sanity check is performed on the given parameters. This will simply give a singleton
        map of the given entry. It is strongly advised to use
        :meth:`RegionMapProposal.computeScore() <RegionMapProposal.computeScore>` to assess the proposal. Alternatively, use
        :meth:`proposeRegionMaps(Collection, long, Collection) <.proposeRegionMaps>` to have the service select the
        best-scored mapping from a collection of proposed programs.
        
        :param ghidra.trace.model.memory.TraceMemoryRegion region: the region to map
        :param jpype.JLong or int snap: the source snapshot key
        :param ghidra.program.model.listing.Program program: the destination program
        :param ghidra.program.model.mem.MemoryBlock block: the memory block in the destination program
        :return: the proposed map
        :rtype: ghidra.debug.api.modules.RegionMapProposal
        """

    @typing.overload
    def proposeRegionMap(self, regions: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program) -> ghidra.debug.api.modules.RegionMapProposal:
        """
        Propose a region map for the given regions to the given program
         
         
        
        Note, no sanity check is performed on the given parameters. This will do its best to map
        regions to memory blocks in the given program. For the best results, regions should all
        comprise the same module, and the minimum address among the regions should be the module's
        base address. It is strongly advised to use :meth:`RegionMapProposal.computeScore() <RegionMapProposal.computeScore>` to
        assess the proposal. Alternatively, use
        :meth:`proposeRegionMaps(Collection, long, Collection) <.proposeRegionMaps>` to have the service select the
        best-scored mapping from a collection of proposed programs.
        
        :param collections.abc.Sequence regions: the regions to map
        :param jpype.JLong or int snap: the source snapshot key
        :param ghidra.program.model.listing.Program program: the destination program whose blocks to consider
        :return: the proposed map
        :rtype: ghidra.debug.api.modules.RegionMapProposal
        """

    def proposeRegionMaps(self, regions: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> java.util.Map[java.util.Collection[ghidra.trace.model.memory.TraceMemoryRegion], ghidra.debug.api.modules.RegionMapProposal]:
        """
        Propose the best-scored maps of trace regions to program memory blocks for each given
        "module" given a collection of proposed programs.
         
         
        
        Note, this method will first group regions into likely modules by parsing their names, then
        compare to program names in order to cull unlikely pairs. It then takes the best-scored
        proposal for each module. If a module has no likely paired program, then it is omitted from
        the result. For informational purposes, the keys in the returned map reflect the grouping of
        regions into likely modules. For the best results, the minimum address of each module should
        be among the regions.
        
        :param collections.abc.Sequence regions: the regions to map
        :param jpype.JLong or int snap: the source snapshot key
        :param collections.abc.Sequence programs: a set of proposed destination programs
        :return: the composite proposal
        :rtype: java.util.Map[java.util.Collection[ghidra.trace.model.memory.TraceMemoryRegion], ghidra.debug.api.modules.RegionMapProposal]
        """

    @typing.overload
    def proposeSectionMap(self, section: ghidra.trace.model.modules.TraceSection, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock) -> ghidra.debug.api.modules.SectionMapProposal:
        """
        Propose a singleton section map from the given section to the given program memory block
         
         
        
        Note, no sanity check is performed on the given parameters. This will simply give a singleton
        map of the given entry. It is strongly advised to use
        :meth:`SectionMapProposal.computeScore() <SectionMapProposal.computeScore>` to assess the proposal. Alternatively, use
        :meth:`proposeSectionMap(TraceModule, long, Collection) <.proposeSectionMap>` to have the service select the
        best-scored mapping from a collection of proposed programs.
        
        :param ghidra.trace.model.modules.TraceSection section: the section to map
        :param jpype.JLong or int snap: the source snapshot key
        :param ghidra.program.model.listing.Program program: the destination program
        :param ghidra.program.model.mem.MemoryBlock block: the memory block in the destination program
        :return: the proposed map
        :rtype: ghidra.debug.api.modules.SectionMapProposal
        """

    @typing.overload
    def proposeSectionMap(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program) -> ghidra.debug.api.modules.SectionMapProposal:
        """
        Propose a section map for the given module to the given program
         
         
        
        Note, no sanity check is performed on the given parameters. This will do its best to map
        sections from the given module to memory blocks in the given program. It is strongly advised
        to use :meth:`SectionMapProposal.computeScore() <SectionMapProposal.computeScore>` to assess the proposal. Alternatively, use
        :meth:`proposeSectionMap(TraceModule, long, Collection) <.proposeSectionMap>` to have the service select the
        best-scored mapping from a collection of proposed programs.
        
        :param ghidra.trace.model.modules.TraceModule module: the module whose sections to map
        :param jpype.JLong or int snap: the source snapshot key
        :param ghidra.program.model.listing.Program program: the destination program whose blocks to consider
        :return: the proposed map
        :rtype: ghidra.debug.api.modules.SectionMapProposal
        """

    @typing.overload
    def proposeSectionMap(self, module: ghidra.trace.model.modules.TraceModule, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> ghidra.debug.api.modules.SectionMapProposal:
        """
        Proposed the best-scored section map for the given module and programs
         
         
        
        Note, no sanity check is performed on any given module-program pair. Instead, the
        highest-scoring proposal is selected from the possible module-program pairs. In particular,
        the names of the programs vs. the module name may not be examined by the implementation.
        
        :param ghidra.trace.model.modules.TraceModule module: the module whose sections to map
        :param jpype.JLong or int snap: the source snapshot key
        :param collections.abc.Sequence programs: a set of proposed destination programs
        :return: the best-scored map, or ``null`` if no program is proposed
        :rtype: ghidra.debug.api.modules.SectionMapProposal
        
        .. seealso::
        
            | :obj:`SectionMapProposal.computeScore()`
        """

    def proposeSectionMaps(self, modules: collections.abc.Sequence, snap: typing.Union[jpype.JLong, int], programs: collections.abc.Sequence) -> java.util.Map[ghidra.trace.model.modules.TraceModule, ghidra.debug.api.modules.SectionMapProposal]:
        """
        Propose the best-scored maps of trace sections to program memory blocks for each given module
        given a collection of proposed programs.
         
         
        
        Note, this method will first examine module and program names in order to cull unlikely
        pairs. It then takes the best-scored proposal for each module. If a module has no likely
        paired program, then it is omitted from the result, i.e., the returned map will have no
        ``null`` values.
        
        :param collections.abc.Sequence modules: the modules to map
        :param jpype.JLong or int snap: the source snapshot key
        :param collections.abc.Sequence programs: a set of proposed destination programs
        :return: the composite proposal
        :rtype: java.util.Map[ghidra.trace.model.modules.TraceModule, ghidra.debug.api.modules.SectionMapProposal]
        """

    def removeChangeListener(self, l: ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        """
        Remove a listener for changes in mappings
        
        :param ghidra.debug.api.modules.DebuggerStaticMappingChangeListener l: the listener
        """

    @property
    def openMappedLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def openMappedLocations(self) -> java.util.Set[ghidra.trace.model.TraceLocation]:
        ...

    @property
    def staticLocationFromDynamic(self) -> ghidra.program.util.ProgramLocation:
        ...


class DebuggerAutoMappingService(java.lang.Object):
    """
    The service to query auto-map settings
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def getAutoMapSpec(self) -> ghidra.debug.api.action.AutoMapSpec:
        """
        Get the auto-map setting currently active in the Modules provider
        
        :return: the current setting
        :rtype: ghidra.debug.api.action.AutoMapSpec
        """

    @typing.overload
    def getAutoMapSpec(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.action.AutoMapSpec:
        """
        Get the current auto-map setting for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the auto-map setting for the trace, or the setting in the Modules provider, if the
                trace does not have its own setting.
        :rtype: ghidra.debug.api.action.AutoMapSpec
        """

    def setAutoMapSpec(self, spec: ghidra.debug.api.action.AutoMapSpec):
        """
        Set the current auto-map specification in the Modules provider
        
        :param ghidra.debug.api.action.AutoMapSpec spec: the new setting
        """

    @property
    def autoMapSpec(self) -> ghidra.debug.api.action.AutoMapSpec:
        ...

    @autoMapSpec.setter
    def autoMapSpec(self, value: ghidra.debug.api.action.AutoMapSpec):
        ...


class DebuggerConsoleService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addResolutionAction(self, action: docking.action.DockingActionIf):
        """
        Add an action which might be applied to an actionable log message
         
         
        
        Please invoke this method from the Swing thread. Only toolbar and pop-up menu placement is
        considered. Toolbar actions are placed as icon-only buttons in the "Actions" column for any
        log message where the action is applicable to the context given for that message. Pop-up
        actions are placed in the context menu when a single message is selected and the action is
        applicable to its given context. In most cases, the action should be presented both as a
        button and as a pop-up menu. Less commonly, an action may be presented only as a pop-up,
        likely because it is an uncommon resolution, or because you don't want the user to activated
        it accidentally. Rarely, if ever, should an action be a button, but not in the menu. The user
        may expect the menu to give more complete descriptions of actions presented as buttons.
         
         
        
        **IMPORTANT:** Unlike other action managers, you are required to remove your actions upon
        plugin disposal.
        
        :param docking.action.DockingActionIf action: the action
        """

    def getActionContexts(self) -> java.util.List[docking.ActionContext]:
        """
        Get the action context for all actionable messages
        
        :return: a copy of the collection of contexts, in no particular order
        :rtype: java.util.List[docking.ActionContext]
        """

    @typing.overload
    def log(self, icon: javax.swing.Icon, message: typing.Union[java.lang.String, str]):
        """
        Log a message to the console
         
         
        
        **WARNING:** See :meth:`log(Icon, String, Throwable, ActionContext) <.log>` regarding HTML.
        
        :param javax.swing.Icon icon: an icon for the message
        :param java.lang.String or str message: the HTML-formatted message
        """

    @typing.overload
    def log(self, icon: javax.swing.Icon, message: typing.Union[java.lang.String, str], error: java.lang.Throwable):
        """
        Log an error message to the console
         
         
        
        **WARNING:** See :meth:`log(Icon, String, Throwable, ActionContext) <.log>` regarding HTML.
        
        :param javax.swing.Icon icon: an icon for the message
        :param java.lang.String or str message: the HTML-formatted message
        :param java.lang.Throwable error: an exception, if applicable
        """

    @typing.overload
    def log(self, icon: javax.swing.Icon, message: typing.Union[java.lang.String, str], context: docking.ActionContext):
        """
        Log an actionable message to the console
         
         
        
        **WARNING:** See :meth:`log(Icon, String, Throwable, ActionContext) <.log>` regarding HTML.
        
        :param javax.swing.Icon icon: an icon for the message
        :param java.lang.String or str message: the HTML-formatted message
        :param docking.ActionContext context: an (immutable) context for actions
        """

    @typing.overload
    def log(self, icon: javax.swing.Icon, message: typing.Union[java.lang.String, str], error: java.lang.Throwable, context: docking.ActionContext):
        """
        Log an actionable error message to the console
         
         
        
        **WARNING:** The log accepts and will interpret HTML in its messages, allowing a rich and
        flexible display; however, you MUST sanitize any content derived from the user or target. We
        recommend using :meth:`HTMLUtilities.escapeHTML(String) <HTMLUtilities.escapeHTML>`.
        
        :param javax.swing.Icon icon: an icon for the message
        :param java.lang.String or str message: the HTML-formatted message
        :param java.lang.Throwable error: an exception, if applicable
        :param docking.ActionContext context: an (immutable) context for actions
        """

    def logContains(self, context: docking.ActionContext) -> bool:
        """
        Check if the console contains an actionable message for the given context
        
        :param docking.ActionContext context: the context to check for
        :return: true if present, false if absent
        :rtype: bool
        """

    def removeFromLog(self, context: docking.ActionContext):
        """
        Remove an actionable message from the console
         
         
        
        It is common courtesy to remove the entry when the user has resolved the issue, whether via
        the presented actions, or some other means. The framework does not do this automatically,
        because simply activating an action does not imply the issue will be resolved.
        
        :param docking.ActionContext context: the context of the entry to remove
        """

    def removeResolutionAction(self, action: docking.action.DockingActionIf):
        """
        Remove an action
         
         
        
        Please invoke this method from the Swing thread.
        
        :param docking.action.DockingActionIf action: the action
        """

    @property
    def actionContexts(self) -> java.util.List[docking.ActionContext]:
        ...


class DebuggerListingService(CodeViewerService):
    """
    A service providing access to the main listing panel
    """

    class LocationTrackingSpecChangeListener(java.lang.Object):
        """
        A listener for changes in location tracking specification
        """

        class_: typing.ClassVar[java.lang.Class]

        def locationTrackingSpecChanged(self, spec: ghidra.debug.api.action.LocationTrackingSpec):
            """
            The specification has changed
            
            :param ghidra.debug.api.action.LocationTrackingSpec spec: the new specification
            """


    class_: typing.ClassVar[java.lang.Class]

    def addTrackingSpecChangeListener(self, listener: DebuggerListingService.LocationTrackingSpecChangeListener):
        """
        Add a listener for changes to the tracking specification.
        
        :param DebuggerListingService.LocationTrackingSpecChangeListener listener: the listener to receive change notifications
        """

    def createListingBackgroundColorModel(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel) -> ghidra.debug.api.listing.MultiBlendedListingBackgroundColorModel:
        """
        Obtain a coloring background model suitable for the given listing
         
         
        
        This may be used, e.g., to style an alternative view in the same manner as listings managed
        by this service. Namely, this provides coloring for memory state and the user's cursor.
        Coloring for tracked locations and the marker service in general must still be added
        separately, since they incorporate additional dependencies.
        
        :param ghidra.app.util.viewer.listingpanel.ListingPanel listingPanel: the panel to be colored
        :return: a blended background color model implementing the common debugger listing style
        :rtype: ghidra.debug.api.listing.MultiBlendedListingBackgroundColorModel
        """

    def getAutoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        """
        Get the auto-read memory specification of the main listing.
        
        :return: the current specification
        :rtype: ghidra.debug.api.action.AutoReadMemorySpec
        """

    def getTrackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        """
        Get the tracking specification of the main listing.
        
        :return: the current specification
        :rtype: ghidra.debug.api.action.LocationTrackingSpec
        """

    def goTo(self, address: ghidra.program.model.address.Address, centerOnScreen: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Navigate to the given address
        
        :param ghidra.program.model.address.Address address: the desired address
        :param jpype.JBoolean or bool centerOnScreen: true to center the cursor in the listing
        :return: true if the request was effective
        :rtype: bool
        """

    def removeTrackingSpecChangeListener(self, listener: DebuggerListingService.LocationTrackingSpecChangeListener):
        """
        Remove a listener for changes to the tracking specification.
        
        :param DebuggerListingService.LocationTrackingSpecChangeListener listener: the listener receiving change notifications
        """

    def setCurrentSelection(self, selection: ghidra.program.util.ProgramSelection):
        """
        Set the selection of addresses in this listing.
        
        :param ghidra.program.util.ProgramSelection selection: the desired selection
        """

    def setTrackingSpec(self, spec: ghidra.debug.api.action.LocationTrackingSpec):
        """
        Set the tracking specification of the listing. Navigates immediately.
        
        :param ghidra.debug.api.action.LocationTrackingSpec spec: the desired specification
        """

    @property
    def trackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    @trackingSpec.setter
    def trackingSpec(self, value: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    @property
    def autoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...


class DebuggerTargetService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addTargetPublicationListener(self, listener: ghidra.debug.api.target.TargetPublicationListener):
        """
        Add a listener for target publication and withdrawal events
        
        :param ghidra.debug.api.target.TargetPublicationListener listener: the listener
        """

    def getPublishedTargets(self) -> java.util.List[ghidra.debug.api.target.Target]:
        """
        Get a list of all published targets
        
        :return: the list in no particular order
        :rtype: java.util.List[ghidra.debug.api.target.Target]
        """

    def getTarget(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.target.Target:
        """
        Get the target for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :return: the target, or null if there is no such target
        :rtype: ghidra.debug.api.target.Target
        """

    def publishTarget(self, target: ghidra.debug.api.target.Target):
        """
        Publish a target to the service and its listeners
        
        :param ghidra.debug.api.target.Target target: the new target
        """

    def removeTargetPublicationListener(self, listener: ghidra.debug.api.target.TargetPublicationListener):
        """
        Remove a listener for target publication and withdrawal events
        
        :param ghidra.debug.api.target.TargetPublicationListener listener: the listener
        """

    def withdrawTarget(self, target: ghidra.debug.api.target.Target):
        """
        Withdraw a target from the service and its listeners
        
        :param ghidra.debug.api.target.Target target: the (presumably invalidated) target
        """

    @property
    def publishedTargets(self) -> java.util.List[ghidra.debug.api.target.Target]:
        ...

    @property
    def target(self) -> ghidra.debug.api.target.Target:
        ...


class ProgressService(java.lang.Object):
    """
    A service for publishing and subscribing to tasks and progress notifications.
     
     
    
    This is an attempt to de-couple the concepts of task monitoring and task execution. The
    :obj:`PluginTool` has a system for submitting background tasks. It queues the task. When it
    reaches the front of the queue, it creates a :obj:`TaskMonitor`, starts a thread, and executes
    the task. Unfortunately, this tightly couples the progress reporting system with the execution
    model, which is not ideal. Moreover, the task queuing system is the only simple way to obtain a
    :obj:`TaskMonitor` with any semblance of central management or consistent presentation.
    Providers can (and often do) create their own :obj:`TaskMonitor`s, usually placed at the bottom
    of the provider when it is, e.g., updating a table.
     
     
    
    This service attempts to provide a centralized system for creating and presenting
    :obj:`TaskMonitor`s separate from the execution model. No particular execution model is
    required. Nor is the task implicitly associated to a specific thread. A client may use a single
    thread for all tasks, a single thread for each task, many threads for a task, etc. In fact, a
    client could even use an :obj:`ExecutorService`, without any care to how tasks are executed.
    Instead, a task need simply request a monitor, pass its handle as needed, and close it when
    finished. The information generated by such monitors is then forwarded to the subscriber which
    can determine how to present them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addProgressListener(self, listener: ghidra.debug.api.progress.ProgressListener):
        """
        Subscribe to task and progress events
        
        :param ghidra.debug.api.progress.ProgressListener listener: the listener
        """

    @typing.overload
    def execute(self, task: ghidra.util.task.Task) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        A drop-in replacement for :meth:`PluginTool.execute(Task) <PluginTool.execute>` that publishes progress via the
        service rather than displaying a dialog.
         
         
        
        In addition to changing how progress is displayed, this also returns a future so that task
        completion can be detected by the caller.
        
        :param ghidra.util.task.Task task: task to run in a new thread
        :return: a future which completes when the task is finished
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def execute(self, canCancel: typing.Union[jpype.JBoolean, bool], hasProgress: typing.Union[jpype.JBoolean, bool], isModal: typing.Union[jpype.JBoolean, bool], futureSupplier: java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]]) -> java.util.concurrent.CompletableFuture[T]:
        """
        Similar to :meth:`execute(Task) <.execute>`, but for asynchronous methods
        
        :param T: the type of future result:param jpype.JBoolean or bool canCancel: true if the task can be cancelled
        :param jpype.JBoolean or bool hasProgress: true if the task displays progress
        :param jpype.JBoolean or bool isModal: true if the task is modal (ignored)
        :param java.util.function.Function[ghidra.util.task.TaskMonitor, java.util.concurrent.CompletableFuture[T]] futureSupplier: the task which returns a future, given the task monitor
        :return: the future returned by the supplier
        :rtype: java.util.concurrent.CompletableFuture[T]
        """

    def getAllMonitors(self) -> java.util.Collection[ghidra.debug.api.progress.MonitorReceiver]:
        """
        Collect all the tasks currently in progress
         
         
        
        The subscriber ought to call this immediately after adding its listener, in order to catch up
        on tasks already in progress.
        
        :return: a collection of in-progress monitor proxies
        :rtype: java.util.Collection[ghidra.debug.api.progress.MonitorReceiver]
        """

    def publishTask(self) -> ghidra.debug.api.progress.CloseableTaskMonitor:
        """
        Publish a task and create a monitor for it
         
         
        
        This and the methods on :obj:`TaskMonitor` are the mechanism for clients to publish task and
        progress information. The monitor returned also extends :obj:`AutoCloseable`, allowing it to
        be used fairly safely when the execution model involves a single thread.
         
         
        try (CloseableTaskMonitor monitor = progressService.publishTask()) {
            // Do the computation and update the monitor accordingly.
        }
         
         
         
        
        If the above idiom is not used, e.g., because the monitor is passed among several
        :obj:`CompletableFuture`s, the client must take care to close it. While the service may make
        some effort to clean up dropped handles, this is just a safeguard to prevent stale monitors
        from being presented indefinitely. The service may complain loudly when it detects dropped
        monitor handles.
        
        :return: the monitor
        :rtype: ghidra.debug.api.progress.CloseableTaskMonitor
        """

    def removeProgressListener(self, listener: ghidra.debug.api.progress.ProgressListener):
        """
        Un-subscribe from task and progress events
        
        :param ghidra.debug.api.progress.ProgressListener listener: the listener
        """

    @property
    def allMonitors(self) -> java.util.Collection[ghidra.debug.api.progress.MonitorReceiver]:
        ...


class DebuggerControlService(java.lang.Object):

    class StateEditor(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getCoordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
            ...

        def getService(self) -> DebuggerControlService:
            ...

        def isRegisterEditable(self, register: ghidra.program.model.lang.Register) -> bool:
            ...

        def isVariableEditable(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> bool:
            ...

        def setRegister(self, value: ghidra.program.model.lang.RegisterValue) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            ...

        def setVariable(self, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            ...

        @property
        def service(self) -> DebuggerControlService:
            ...

        @property
        def coordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
            ...

        @property
        def registerEditable(self) -> jpype.JBoolean:
            ...


    class ControlModeChangeListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def modeChanged(self, trace: ghidra.trace.model.Trace, mode: ghidra.debug.api.control.ControlMode):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addModeChangeListener(self, listener: DebuggerControlService.ControlModeChangeListener):
        ...

    @typing.overload
    def createStateEditor(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> DebuggerControlService.StateEditor:
        ...

    @typing.overload
    def createStateEditor(self, trace: ghidra.trace.model.Trace) -> DebuggerControlService.StateEditor:
        """
        Create a state editor whose coordinates follow the trace manager for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace to follow
        :return: the editor
        :rtype: DebuggerControlService.StateEditor
        """

    @typing.overload
    def createStateEditor(self, view: ghidra.trace.model.program.TraceProgramView) -> DebuggerControlService.StateEditor:
        ...

    def getCurrentMode(self, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.control.ControlMode:
        ...

    def removeModeChangeListener(self, listener: DebuggerControlService.ControlModeChangeListener):
        ...

    def setCurrentMode(self, trace: ghidra.trace.model.Trace, mode: ghidra.debug.api.control.ControlMode):
        ...

    @property
    def currentMode(self) -> ghidra.debug.api.control.ControlMode:
        ...


class DebuggerLogicalBreakpointService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addChangeListener(self, l: ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener):
        """
        Add a listener for logical breakpoint changes.
         
         
        
        Logical breakpoints may change from time to time for a variety of reasons: A new trace is
        started; a static image is opened; the user adds or removes breakpoints; mappings change;
        etc. The service reacts to these events, reconciles the breakpoints, and invokes callbacks
        for the changes, allowing other UI components and services to update accordingly.
         
         
        
        The listening component must maintain a strong reference to the listener, otherwise it will
        be removed and garbage collected. Automatic removal is merely a resource-management
        protection; the listening component should politely remove its listener (see
        :meth:`removeChangeListener(LogicalBreakpointsChangeListener) <.removeChangeListener>` when no longer needed.
        
        :param ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener l: the listener
        """

    @staticmethod
    def addressFromLocation(loc: ghidra.program.util.ProgramLocation) -> ghidra.program.model.address.Address:
        """
        Get the address most likely intended by the user for a given location
         
         
        
        Program locations always have addresses at the start of a code unit, no matter how the
        location was produced. This attempts to interpret the context a bit deeper to discern the
        user's intent. At the moment, it seems reasonable to check if the location includes a code
        unit. If so, take its min address, i.e., the location's address. If not, take the location's
        byte address.
        
        :param ghidra.program.util.ProgramLocation loc: the location
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def anyMapped(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> bool:
        ...

    @typing.overload
    def anyMapped(self, col: collections.abc.Sequence) -> bool:
        ...

    def changesSettled(self) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Get a future which completes after pending changes have been processed
         
         
        
        The returned future completes after all change listeners have been invoked
        
        :return: the future
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def computeState(self, col: collections.abc.Sequence) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @typing.overload
    def computeState(self, col: collections.abc.Sequence, program: ghidra.program.model.listing.Program) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @typing.overload
    def computeState(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @typing.overload
    def computeState(self, col: collections.abc.Sequence, loc: ghidra.program.util.ProgramLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        ...

    @typing.overload
    def computeState(self, loc: ghidra.program.util.ProgramLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint.State:
        """
        Compute the state for a given address and program or trace view
        
        :param ghidra.program.util.ProgramLocation loc: the location
        :return: the breakpoint state
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint.State
        """

    def deleteAll(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Delete, if possible, a collection of logical breakpoints on target, if applicable
        
        :param collections.abc.Sequence col: the collection
        :param ghidra.trace.model.Trace trace: a trace, if the command should be limited to the given trace
        :return: a future which completes when all associated specifications have been deleted
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        
        .. seealso::
        
            | :obj:`.enableAll(Collection, Trace)`
        """

    def deleteLocs(self, col: collections.abc.Sequence) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Delete the given locations
        
        :param collections.abc.Sequence col: the trace breakpoints
        :return: a future which completes when the command has been processed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def disableAll(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Disable a collection of logical breakpoints on target, if applicable
        
        :param collections.abc.Sequence col: the collection
        :param ghidra.trace.model.Trace trace: a trace, if the command should be limited to the given trace
        :return: a future which completes when all associated specifications have been disabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        
        .. seealso::
        
            | :obj:`.enableAll(Collection, Trace)`
        """

    def disableLocs(self, col: collections.abc.Sequence) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Disable the given locations
        
        :param collections.abc.Sequence col: the trace breakpoints
        :return: a future which completes when the command has been processed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def enableAll(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Enable a collection of logical breakpoints on target, if applicable
         
         
        
        This method is preferable to calling :meth:`LogicalBreakpoint.enable() <LogicalBreakpoint.enable>` on each logical
        breakpoint, because depending on the debugger, a single breakpoint specification may produce
        several effective breakpoints, perhaps spanning multiple targets. While not terribly
        critical, this method will prevent multiple requests (which a debugger may consider
        erroneous) to enable the same specification, if that specification happens to be involved in
        more than one logical breakpoint in the given collection.
        
        :param collections.abc.Sequence col: the collection
        :param ghidra.trace.model.Trace trace: a trace, if the command should be limited to the given trace
        :return: a future which completes when all associated specifications have been enabled
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def enableLocs(self, col: collections.abc.Sequence) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Enable the given locations
        
        :param collections.abc.Sequence col: the trace breakpoints
        :return: a future which completes when the command has been processed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    def generateStatusEnable(self, col: collections.abc.Sequence, trace: ghidra.trace.model.Trace) -> str:
        """
        Generate an informational status message when enabling the selected breakpoints
         
         
        
        Breakpoint enabling may fail for a variety of reasons. Some of those reasons deal with the
        trace database and GUI rather than with the target. When enabling will not likely behave in
        the manner expected by the user, this should provide a message explaining why. For example,
        if a breakpoint has no locations on a target, then we already know "enable" will not work.
        This should explain the situation to the user. If enabling is expected to work, then this
        should return null.
        
        :param collections.abc.Sequence col: the collection we're about to enable
        :param ghidra.trace.model.Trace trace: a trace, if the command will be limited to the given trace
        :return: the status message, or null
        :rtype: str
        """

    @typing.overload
    def generateStatusToggleAt(self, bs: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint], loc: ghidra.program.util.ProgramLocation) -> str:
        """
        Generate an informational message when toggling the breakpoints
         
         
        
        This works in the same manner as :meth:`generateStatusEnable(Collection, Trace) <.generateStatusEnable>`, except it
        is for toggling breakpoints. If the breakpoint set is empty, this should return null, since
        the usual behavior in that case is to prompt to place a new breakpoint.
        
        :param java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint] bs: the set of logical breakpoints
        :param ghidra.program.util.ProgramLocation loc: a representative location
        :return: the status message, or null
        :rtype: str
        
        .. seealso::
        
            | :obj:`.generateStatusEnable(Collection, Trace)`
        """

    @typing.overload
    def generateStatusToggleAt(self, loc: ghidra.program.util.ProgramLocation) -> str:
        """
        Generate an informational message when toggling the breakpoints at the given location
         
         
        
        This works in the same manner as :meth:`generateStatusEnable(Collection, Trace) <.generateStatusEnable>`, except it
        is for toggling breakpoints at a given location. If there are no breakpoints at the location,
        this should return null, since the usual behavior in that case is to prompt to place a new
        breakpoint.
        
        :param ghidra.program.util.ProgramLocation loc: the location
        :return: the status message, or null
        :rtype: str
        
        .. seealso::
        
            | :obj:`.generateStatusEnable(Collection, Trace)`
        """

    def getAllBreakpoints(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get all logical breakpoints known to the tool.
        
        :return: the set of all logical breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    def getBreakpoint(self, loc: ghidra.trace.model.breakpoint.TraceBreakpointLocation) -> ghidra.debug.api.breakpoint.LogicalBreakpoint:
        """
        Get the logical breakpoint of which the given trace breakpoint is a part
         
         
        
        If the given trace breakpoint is not part of any logical breakpoint, e.g., because the trace
        is not opened in the tool or events are still being processed, then null is returned.
        
        :param ghidra.trace.model.breakpoint.TraceBreakpointLocation loc: the trace breakpoint location
        :return: the logical breakpoint, or null
        :rtype: ghidra.debug.api.breakpoint.LogicalBreakpoint
        """

    @typing.overload
    def getBreakpoints(self, program: ghidra.program.model.listing.Program) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Get a map of addresses to collected logical breakpoints for a given program.
         
         
        
        The program ought to be a program database, not a view of a trace.
        
        :param ghidra.program.model.listing.Program program: the program database
        :return: the map of logical breakpoints
        :rtype: java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    @typing.overload
    def getBreakpoints(self, trace: ghidra.trace.model.Trace) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Get a map of addresses to collected logical breakpoints for a given trace.
         
         
        
        The map only includes breakpoints visible in the trace's primary view. Visibility depends on
        the view's snapshot.
        
        :param ghidra.trace.model.Trace trace: the trace database
        :return: the map of logical breakpoints
        :rtype: java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    @typing.overload
    def getBreakpointsAt(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get the collected logical breakpoints at the given program location.
         
         
        
        The program ought to be a program database, not a view of a trace.
        
        :param ghidra.program.model.listing.Program program: the program database
        :param ghidra.program.model.address.Address address: the address
        :return: the set of logical breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    @typing.overload
    def getBreakpointsAt(self, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get the collected logical breakpoints at the given trace location.
         
         
        
        The set only includes breakpoints visible in the trace's primary view. Visibility depends on
        the view's snapshot.
        
        :param ghidra.trace.model.Trace trace: the trace database
        :param ghidra.program.model.address.Address address: the address
        :return: the set of logical breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    @typing.overload
    def getBreakpointsAt(self, loc: ghidra.program.util.ProgramLocation) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        """
        Get the collected logical breakpoints (at present) at the given location.
         
         
        
        The ``program`` field for the location may be either a program database (static image) or
        a view for a trace. If it is the latter, the view's snapshot is ignored in favor of the
        trace's primary view's snapshot.
         
         
        
        If ``program`` is a static image, this is equivalent to using
        :meth:`getBreakpointsAt(Program, Address) <.getBreakpointsAt>`. If ``program`` is a trace view, this is
        equivalent to using :meth:`getBreakpointsAt(Trace, Address) <.getBreakpointsAt>`.
        
        :param ghidra.program.util.ProgramLocation loc: the location
        :return: the set of logical breakpoints
        :rtype: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]
        """

    @typing.overload
    def placeBreakpointAt(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence, name: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Create an enabled breakpoint at the given program location and each mapped trace location.
         
         
        
        The implementation should take care not to create the same breakpoint multiple times. The
        risk of this happening derives from the possibility of one module mapped to multiple targets
        which are all managed by the same debugger, having a single breakpoint container.
        
        :param ghidra.program.model.listing.Program program: the static module image
        :param ghidra.program.model.address.Address address: the address in the image
        :param jpype.JLong or int length: size of the breakpoint, may be ignored by debugger
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        :param java.lang.String or str name: a name for the breakpoint. For no name, use the empty string
        :return: a future which completes when all relevant breakpoints have been placed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def placeBreakpointAt(self, trace: ghidra.trace.model.Trace, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence, name: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Create an enabled breakpoint at the given trace location and its mapped program location.
         
         
        
        If the breakpoint has no static location, then only the trace location is placed. Note, if
        this is the case, the breakpoint will have no name.
         
         
        
        Note for live targets, the debugger ultimately determines the placement behavior. If it is
        managing multiple targets, it is possible the breakpoint will be effective in another trace.
        This fact should be reflected correctly in the resulting logical markings once all resulting
        events have been processed.
        
        :param ghidra.trace.model.Trace trace: the given trace
        :param ghidra.program.model.address.Address address: the address in the trace (as viewed in the present)
        :param jpype.JLong or int length: size of the breakpoint, may be ignored by debugger
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        :param java.lang.String or str name: a name for the breakpoint
        :return: a future which completes when the breakpoint has been placed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def placeBreakpointAt(self, loc: ghidra.program.util.ProgramLocation, length: typing.Union[jpype.JLong, int], kinds: collections.abc.Sequence, name: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Create an enabled breakpoint at the given location.
         
         
        
        If the given location refers to a static image, this behaves as in
        :meth:`placeBreakpointAt(Program, Address, long, Collection, String) <.placeBreakpointAt>`. If it refers to a
        trace view, this behaves as in *
        :meth:`placeBreakpointAt(Trace, Address, long, Collection, String) <.placeBreakpointAt>`, ignoring the view's
        current snapshot in favor of the present. The name is only saved for a program breakpoint.
        
        :param ghidra.program.util.ProgramLocation loc: the location
        :param jpype.JLong or int length: size of the breakpoint, may be ignored by debugger
        :param collections.abc.Sequence kinds: the kinds of breakpoint
        :param java.lang.String or str name: an optional name for the breakpoint (null becomes the empty string)
        :return: a future which completes when the breakpoints have been placed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @staticmethod
    def programOrTrace(loc: ghidra.program.util.ProgramLocation, progFunc: java.util.function.BiFunction[ghidra.program.model.listing.Program, ghidra.program.model.address.Address, T], traceFunc: java.util.function.BiFunction[ghidra.trace.model.Trace, ghidra.program.model.address.Address, T]) -> T:
        ...

    def removeChangeListener(self, l: ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener):
        """
        Remove a listener for logical breakpoint changes.
        
        :param ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener l: the listener to remove
        
        .. seealso::
        
            | :obj:`.addChangeListener(LogicalBreakpointsChangeListener)`
        """

    @typing.overload
    def toggleBreakpointsAt(self, bs: java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint], location: ghidra.program.util.ProgramLocation, placer: java.util.function.Supplier[java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]]) -> java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Toggle the breakpoints at the given location
        
        :param java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint] bs: the set of breakpoints to toggle
        :param ghidra.program.util.ProgramLocation location: the location
        :param java.util.function.Supplier[java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]] placer: if the breakpoint set is empty, a routine for placing a breakpoint
        :return: a future which completes when the command has been processed
        :rtype: java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    @typing.overload
    def toggleBreakpointsAt(self, location: ghidra.program.util.ProgramLocation, placer: java.util.function.Supplier[java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]]) -> java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        """
        Toggle the breakpoints at the given location
        
        :param ghidra.program.util.ProgramLocation location: the location
        :param java.util.function.Supplier[java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]] placer: if there are no breakpoints, a routine for placing a breakpoint
        :return: a future which completes when the command has been processed
        :rtype: java.util.concurrent.CompletableFuture[java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]
        """

    @property
    def breakpointsAt(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    @property
    def allBreakpoints(self) -> java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]:
        ...

    @property
    def breakpoints(self) -> java.util.NavigableMap[ghidra.program.model.address.Address, java.util.Set[ghidra.debug.api.breakpoint.LogicalBreakpoint]]:
        ...

    @property
    def breakpoint(self) -> ghidra.debug.api.breakpoint.LogicalBreakpoint:
        ...


class InternalTraceRmiService(TraceRmiService):
    """
    The same as the :obj:`TraceRmiService`, but grants access to the internal types (without
    casting) to implementors of :obj:`TraceRmiLaunchOpinion`.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["GoToService", "ClipboardContentProviderService", "StringTranslationService", "MarkerService", "StringValidatorService", "DataTypeManagerService", "DataTypeReference", "AnalysisPriority", "FieldMouseHandlerService", "MarkerDescriptor", "DataService", "MarkerSet", "ConsoleService", "VSCodeIntegrationService", "ButtonPressedListener", "CodeFormatService", "ViewManagerService", "GraphDisplayBroker", "BlockModelService", "Terminal", "QueryData", "GoToOverrideService", "DataTypeReferenceFinder", "NavigationHistoryService", "GoToServiceListener", "FileImporterService", "BlockModelServiceListener", "CodeViewerService", "Analyzer", "FileSystemBrowserService", "HoverService", "CoordinatedListingPanelListener", "ProgramLocationPair", "StringValidityScore", "FunctionComparisonService", "AnalyzerType", "DataTypeArchiveService", "ClipboardService", "EclipseIntegrationService", "ViewService", "MemorySearchService", "StringValidatorQuery", "BookmarkService", "ProgramTreeService", "ProgramManager", "AnalyzerAdapter", "AbstractAnalyzer", "TerminalService", "FieldMatcher", "DataTypeQueryService", "GhidraScriptService", "DebuggerEmulationService", "DebuggerPlatformService", "TraceRmiService", "DebuggerTraceManagerService", "TraceRmiLauncherService", "DebuggerWatchesService", "DebuggerStaticMappingService", "DebuggerAutoMappingService", "DebuggerConsoleService", "DebuggerListingService", "DebuggerTargetService", "ProgressService", "DebuggerControlService", "DebuggerLogicalBreakpointService", "InternalTraceRmiService"]
