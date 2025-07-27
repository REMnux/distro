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
import ghidra.features.base.codecompare.model
import ghidra.features.base.memsearch.gui
import ghidra.formats.gfilesystem
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.block
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.service.graph
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
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.tree # type: ignore
import utility.function


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
        :raises UnsupportedOperationException:
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
        :raises UnsupportedOperationException:
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

    def terminated(self):
        """
        Notify the terminal that its session has terminated
         
         
        
        The title and sub title are adjust and all listeners are removed. If/when the terminal is
        closed, it is permanently removed from the tool.
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
        Return the name of this AnalyzerType.
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
    A service that manages a set of data type archives, allowing re-use of already open
    archives.
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
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor` to display progess during the opening
        :return: the data type archive
        :rtype: ghidra.program.model.data.DataTypeManager
        :raises IOException: if an i/o error occurs opening the data type archive
        :raises DuplicateIdException: if another archive with the same ID is already open
        :raises VersionException: 
        :raises CancelledException:
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

    def added(self, program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> bool:
        ...

    def getDefaultEnablement(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    @property
    def defaultEnablement(self) -> jpype.JBoolean:
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
    Simplified datatype service interface to provide query capabilities
    to a set of open datatype managers
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDataType(self, filterText: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.DataType:
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

    def getSortedDataTypeList(self) -> java.util.List[ghidra.program.model.data.DataType]:
        """
        Gets the sorted list of all datatypes known by this service via it's owned DataTypeManagers.
        This method can be called frequently, as the underlying data is indexed and only updated
        as changes are made.  The sorting of the list is done using the :obj:`DataTypeComparator` 
        whose primary sort is based upon the :obj:`DataTypeNameComparator`.
        
        :return: the sorted list of known data types.
        :rtype: java.util.List[ghidra.program.model.data.DataType]
        """

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
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



__all__ = ["GoToService", "ClipboardContentProviderService", "StringTranslationService", "MarkerService", "StringValidatorService", "DataTypeManagerService", "DataTypeReference", "AnalysisPriority", "FieldMouseHandlerService", "MarkerDescriptor", "DataService", "MarkerSet", "ConsoleService", "VSCodeIntegrationService", "ButtonPressedListener", "CodeFormatService", "ViewManagerService", "GraphDisplayBroker", "BlockModelService", "Terminal", "QueryData", "GoToOverrideService", "DataTypeReferenceFinder", "NavigationHistoryService", "GoToServiceListener", "FileImporterService", "BlockModelServiceListener", "CodeViewerService", "Analyzer", "FileSystemBrowserService", "HoverService", "CoordinatedListingPanelListener", "ProgramLocationPair", "StringValidityScore", "FunctionComparisonService", "AnalyzerType", "DataTypeArchiveService", "ClipboardService", "EclipseIntegrationService", "ViewService", "MemorySearchService", "StringValidatorQuery", "BookmarkService", "ProgramTreeService", "ProgramManager", "AnalyzerAdapter", "AbstractAnalyzer", "TerminalService", "FieldMatcher", "DataTypeQueryService", "GhidraScriptService"]
