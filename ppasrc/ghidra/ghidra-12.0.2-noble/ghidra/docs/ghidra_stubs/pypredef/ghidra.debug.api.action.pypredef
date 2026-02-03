from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.stack
import ghidra.trace.model.target
import ghidra.trace.util
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class AutoReadMemorySpecFactory(ghidra.util.classfinder.ExtensionPoint):
    """
    A discoverable factory of auto-read memory specifications
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def allSuggested(tool: ghidra.framework.plugintool.PluginTool) -> java.util.Map[java.lang.String, AutoReadMemorySpec]:
        """
        Get a copy of all the known and visible specifications
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool or context
        :return: the specifications by configuration name
        :rtype: java.util.Map[java.lang.String, AutoReadMemorySpec]
        """

    @staticmethod
    def fromConfigName(name: typing.Union[java.lang.String, str]) -> AutoReadMemorySpec:
        """
        Get the specification for the given configuration name
        
        :param java.lang.String or str name: the name
        :return: the spec, or null
        :rtype: AutoReadMemorySpec
        """

    def getSuggested(self, tool: ghidra.framework.plugintool.PluginTool) -> java.util.List[AutoReadMemorySpec]:
        """
        Get all the specifications currently suggested by this factory
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool or context
        :return: the list of suggested specifications
        :rtype: java.util.List[AutoReadMemorySpec]
        """

    def parseSpec(self, name: typing.Union[java.lang.String, str]) -> AutoReadMemorySpec:
        """
        Attempt to parse the given configuration name as a specification
        
        :param java.lang.String or str name: the configuration name, usually including a prefix unique to each factory
        :return: the specification, or null if this factory cannot parse it
        :rtype: AutoReadMemorySpec
        """

    @property
    def suggested(self) -> java.util.List[AutoReadMemorySpec]:
        ...


class AutoReadMemorySpec(java.lang.Object):
    """
    An interface for specifying how to automatically read target memory.
    """

    class AutoReadMemorySpecConfigFieldCodec(ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec[AutoReadMemorySpec]):
        """
        Codec for saving/restoring the auto-read specification
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getConfigName(self) -> str:
        """
        Get the configuration name
         
         
        
        This is the value stored in configuration files to identify this specification
        
        :return: the configuration name
        :rtype: str
        """

    def getEffective(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> AutoReadMemorySpec:
        """
        Get the "effective" specification.
         
        
        This allows a specification to defer to some other (possibly hidden) specification, depending
        on the coordinates.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the current coordinates
        :return: the specification
        :rtype: AutoReadMemorySpec
        """

    def getMenuIcon(self) -> javax.swing.Icon:
        """
        Get the icon for this specification
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getMenuName(self) -> str:
        """
        A human-readable name for this specification
         
         
        
        This is the text displayed in menus
        
        :return: the menu name, or null to omit from menus
        :rtype: str
        """

    def readMemory(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, visible: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[java.lang.Boolean]:
        """
        Perform the automatic read, if applicable
         
         
        
        Note, the implementation should perform all the error handling. The returned future is for
        follow-up purposes only, and should always complete normally. It should complete with true if
        any memory was actually loaded. Otherwise, it should complete with false.
         
         
        
        **NOTE:** This returns the future, rather than being synchronous, because not all specs
        will actually need to create a background task. If this were synchronous, the caller would
        have to invoke it from a background thread, requiring it to create that thread whether or not
        this method actually does anything.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool containing the provider
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the provider's current coordinates
        :param ghidra.program.model.address.AddressSetView visible: the provider's visible addresses
        :return: a future that completes when the memory has been read
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Boolean]
        """

    @property
    def configName(self) -> java.lang.String:
        ...

    @property
    def effective(self) -> AutoReadMemorySpec:
        ...

    @property
    def menuIcon(self) -> javax.swing.Icon:
        ...

    @property
    def menuName(self) -> java.lang.String:
        ...


class ActionSource(java.lang.Enum[ActionSource]):
    """
    Possible sources that drive actions or method invocations
     
     
    
    This is primarily used to determine where and how errors should be reported. Granted, this is
    only one factor in determining how to deliver an error message. In general, actions which are
    taken automatically should not cause disruptive error messages.
    """

    class_: typing.ClassVar[java.lang.Class]
    MANUAL: typing.Final[ActionSource]
    """
    The action was requested by the user, usually via a UI action. It is acceptable to display an
    error message.
    """

    AUTOMATIC: typing.Final[ActionSource]
    """
    The action was requested automatically, usually by some background thread. Error messages
    should probably be delivered to the log or Debug Console, since displaying an error pop-up
    would seem to "come from nowhere."
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ActionSource:
        ...

    @staticmethod
    def values() -> jpype.JArray[ActionSource]:
        ...


class LocationTracker(java.lang.Object):
    """
    The actual tracking logic for a location tracking spec
     
     
    
    In simple cases, the spec can implement this interface and return itself in
    :meth:`LocationTrackingSpec.getTracker() <LocationTrackingSpec.getTracker>`. If the tracker needs some state, then the spec should
    create a separate tracker.
    """

    class_: typing.ClassVar[java.lang.Class]

    def affectedByBytesChange(self, space: ghidra.program.model.address.AddressSpace, range: ghidra.trace.model.TraceAddressSnapRange, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if the address should be recomputed given the indicated value change
        
        :param ghidra.program.model.address.AddressSpace space: the space (address space, thread, frame) where the change occurred
        :param ghidra.trace.model.TraceAddressSnapRange range: the range (time and space) where the change occurred
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the provider's current coordinates
        :return: true if re-computation and "goto" is warranted
        :rtype: bool
        """

    def affectedByStackChange(self, stack: ghidra.trace.model.stack.TraceStack, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if the address should be recomputed given the indicated stack change
        
        :param ghidra.trace.model.stack.TraceStack stack: the stack that changed (usually it's PC / return offset)
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the provider's current coordinates
        :return: true if re-computation and "goto" is warranted
        :rtype: bool
        """

    def computeTraceAddress(self, provider: ghidra.framework.plugintool.ServiceProvider, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.address.Address:
        """
        Compute the trace address to "goto"
         
         
        
        If the coordinates indicate emulation, i.e., the schedule is non-empty, the trace manager
        will already have performed the emulation and stored the results in a "scratch" snap. In
        general, the location should be computed using that snap, i.e.,
        :meth:`DebuggerCoordinates.getViewSnap() <DebuggerCoordinates.getViewSnap>` rather than :meth:`DebuggerCoordinates.getSnap() <DebuggerCoordinates.getSnap>`.
        The address returned must be in the host platform's language, i.e., please use
        :meth:`TracePlatform.mapGuestToHost(Address) <TracePlatform.mapGuestToHost>`.
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the trace, thread, snap, etc., of the tool
        :return: the address to navigate to
        :rtype: ghidra.program.model.address.Address
        """

    def getDefaultGoToInput(self, provider: ghidra.framework.plugintool.ServiceProvider, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, location: ghidra.program.util.ProgramLocation) -> GoToInput:
        """
        Get the suggested input if the user activates "Go To" while this tracker is active
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the user's current coordinates
        :param ghidra.program.util.ProgramLocation location: the user's current location
        :return: the suggested address or Sleigh expression
        :rtype: GoToInput
        """

    def shouldDisassemble(self) -> bool:
        """
        Indicates whether the user should expect instructions at the tracked location.
         
         
        
        Essentially, is this tracking the program counter?
        
        :return: true to disassemble, false not to
        :rtype: bool
        """


class AutoMapSpec(ghidra.util.classfinder.ExtensionPoint):
    """
    An interface for specifying how to automatically map dynamic memory to static memory.
    """

    class Private(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class AutoMapSpecConfigFieldCodec(ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec[AutoMapSpec]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    PRIVATE: typing.Final[AutoMapSpec.Private]

    @staticmethod
    def allSpecs() -> java.util.Map[java.lang.String, AutoMapSpec]:
        ...

    @staticmethod
    def fromConfigName(name: typing.Union[java.lang.String, str]) -> AutoMapSpec:
        ...

    def getChangeTypes(self) -> java.util.Collection[ghidra.trace.util.TraceEvent[typing.Any, typing.Any]]:
        ...

    def getConfigName(self) -> str:
        ...

    def getInfoForObjects(self, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> str:
        ...

    def getMenuIcon(self) -> javax.swing.Icon:
        ...

    def getMenuName(self) -> str:
        ...

    def getTaskTitle(self) -> str:
        ...

    def hasTask(self) -> bool:
        ...

    def objectHasType(self, value: ghidra.trace.model.target.TraceObjectValue) -> bool:
        ...

    @typing.overload
    def performMapping(self, mappingService: ghidra.app.services.DebuggerStaticMappingService, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], programs: java.util.List[ghidra.program.model.listing.Program], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Perform the actual mapping
        
        :param ghidra.app.services.DebuggerStaticMappingService mappingService: the mapping service
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param java.util.List[ghidra.program.model.listing.Program] programs: the programs to consider
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: true if any mappings were added
        :rtype: bool
        :raises CancelledException: if the task monitor cancelled the task
        """

    @typing.overload
    def performMapping(self, mappingService: ghidra.app.services.DebuggerStaticMappingService, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], programManager: ghidra.app.services.ProgramManager, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Perform the actual mapping
        
        :param ghidra.app.services.DebuggerStaticMappingService mappingService: the mapping service
        :param ghidra.trace.model.Trace trace: the trace
        :param jpype.JLong or int snap: the snap
        :param ghidra.app.services.ProgramManager programManager: the program manager
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: true if any mappings were added
        :rtype: bool
        :raises CancelledException: if the task monitor cancelled the task
        """

    def programs(self, programManager: ghidra.app.services.ProgramManager) -> java.util.List[ghidra.program.model.listing.Program]:
        ...

    def runTask(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]):
        ...

    @property
    def configName(self) -> java.lang.String:
        ...

    @property
    def changeTypes(self) -> java.util.Collection[ghidra.trace.util.TraceEvent[typing.Any, typing.Any]]:
        ...

    @property
    def menuIcon(self) -> javax.swing.Icon:
        ...

    @property
    def menuName(self) -> java.lang.String:
        ...

    @property
    def taskTitle(self) -> java.lang.String:
        ...


class InstanceUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def collectUniqueInstances(cls: java.lang.Class[T], map: collections.abc.Mapping, keyFunc: java.util.function.Function[T, java.lang.String]):
        ...


class LocationTrackingSpecFactory(ghidra.util.classfinder.ExtensionPoint):
    """
    A discoverable factory of tracking specifications
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def allSuggested(tool: ghidra.framework.plugintool.PluginTool) -> java.util.Map[java.lang.String, LocationTrackingSpec]:
        """
        Get a copy of all the known specifications
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool or context
        :return: the specifications by configuration name
        :rtype: java.util.Map[java.lang.String, LocationTrackingSpec]
        """

    @staticmethod
    def fromConfigName(name: typing.Union[java.lang.String, str]) -> LocationTrackingSpec:
        """
        Get the specification for the given configuration name
        
        :param java.lang.String or str name: the name
        :return: the spec, or null
        :rtype: LocationTrackingSpec
        """

    def getSuggested(self, tool: ghidra.framework.plugintool.PluginTool) -> java.util.List[LocationTrackingSpec]:
        """
        Get all the specifications currently suggested by this factory
        
        :param ghidra.framework.plugintool.PluginTool tool: the plugin tool or context
        :return: the list of suggested specifications
        :rtype: java.util.List[LocationTrackingSpec]
        """

    def parseSpec(self, name: typing.Union[java.lang.String, str]) -> LocationTrackingSpec:
        """
        Attempt to parse the given configuration name as a specification
        
        :param java.lang.String or str name: the configuration name, usually including a prefix unique to each factory
        :return: the specification, or null if this factory cannot parse it
        :rtype: LocationTrackingSpec
        """

    @property
    def suggested(self) -> java.util.List[LocationTrackingSpec]:
        ...


class GoToInput(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, space: typing.Union[java.lang.String, str], offset: typing.Union[java.lang.String, str]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromAddress(address: ghidra.program.model.address.Address) -> GoToInput:
        ...

    @staticmethod
    def fromString(string: typing.Union[java.lang.String, str]) -> GoToInput:
        ...

    def hashCode(self) -> int:
        ...

    def offset(self) -> str:
        ...

    @staticmethod
    def offsetOnly(offset: typing.Union[java.lang.String, str]) -> GoToInput:
        ...

    def space(self) -> str:
        ...

    def toString(self) -> str:
        ...


class LocationTrackingSpec(java.lang.Object):
    """
    A specification for automatic navigation of the dynamic listing
     
     
    
    TODO: Some of these should be configurable and permit multiple instances so that common
    configurations can be saved. The most obvious use case would be a Sleigh expression. A user may
    want 3 different common expressions readily available in the drop-down list. It might make sense
    to generate a tracking specification from each Watch.
    """

    class TrackingSpecConfigFieldCodec(ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec[LocationTrackingSpec]):
        """
        Codec for saving/restoring the tracking specification
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def changeIsCurrent(space: ghidra.program.model.address.AddressSpace, range: ghidra.trace.model.TraceAddressSnapRange, current: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if the given trace-space and range refer to memory or the current frame
         
         
        
        If the space models memory, the thread and frame are not considered, in case, e.g., the
        tracked register is memory-mapped. If the space models registers, the thread and frame are
        considered and must match those given in the coordinates. Whatever the case, the span must
        include the snap of the coordinates. Otherwise, the change is not considered current.
        
        :param ghidra.program.model.address.AddressSpace space: the trace-space, giving thread, frame, and address space
        :param ghidra.trace.model.TraceAddressSnapRange range: the address range and time span of the change
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates current: the current coordinates
        :return: true if the change affects the tracked address for the given coordinates
        :rtype: bool
        """

    def computeTitle(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> str:
        """
        Compute a title prefix to indicate this tracking specification
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the current coordinates
        :return: a prefix, or ``null`` to use a default
        :rtype: str
        """

    def getConfigName(self) -> str:
        """
        Get the configuration name
         
         
        
        This is the value stored in configuration files to identify this specification
        
        :return: the configuration name
        :rtype: str
        """

    def getLocationLabel(self) -> str:
        """
        Get the name used in the location tracking label
        
        :return: the label
        :rtype: str
        """

    def getMenuIcon(self) -> javax.swing.Icon:
        """
        Get the icon for this specification
        
        :return: the icon
        :rtype: javax.swing.Icon
        """

    def getMenuName(self) -> str:
        """
        A human-readable name for this specification
         
         
        
        This is the text displayed in menus
        
        :return: the menu name
        :rtype: str
        """

    def getTracker(self) -> LocationTracker:
        """
        Get (or create) the actual location tracking logic
         
         
        
        Having a separate object from the spec gives implementations the option of keeping state on a
        per-window basis.
        
        :return: the tracker
        :rtype: LocationTracker
        """

    @property
    def configName(self) -> java.lang.String:
        ...

    @property
    def menuIcon(self) -> javax.swing.Icon:
        ...

    @property
    def tracker(self) -> LocationTracker:
        ...

    @property
    def menuName(self) -> java.lang.String:
        ...

    @property
    def locationLabel(self) -> java.lang.String:
        ...



__all__ = ["AutoReadMemorySpecFactory", "AutoReadMemorySpec", "ActionSource", "LocationTracker", "AutoMapSpec", "InstanceUtils", "LocationTrackingSpecFactory", "GoToInput", "LocationTrackingSpec"]
