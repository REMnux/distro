from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.action.builder
import docking.menu
import ghidra.app.plugin.core.debug.gui.breakpoint
import ghidra.app.plugin.core.debug.gui.colors
import ghidra.app.plugin.core.debug.gui.listing
import ghidra.app.util.viewer.listingpanel
import ghidra.debug.api.action
import ghidra.debug.api.tracemgr
import ghidra.debug.api.watch
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.program
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


class DebuggerAutoReadMemoryAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder[ghidra.debug.api.action.AutoReadMemorySpec]:
        ...


class NoneLocationTrackingSpec(java.lang.Enum[NoneLocationTrackingSpec], ghidra.debug.api.action.LocationTrackingSpec, ghidra.debug.api.action.LocationTracker):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[NoneLocationTrackingSpec]
    CONFIG_NAME: typing.Final = "TRACK_NONE"

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> NoneLocationTrackingSpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[NoneLocationTrackingSpec]:
        ...


class BasicAutoReadMemorySpec(java.lang.Enum[BasicAutoReadMemorySpec], ghidra.debug.api.action.AutoReadMemorySpec):

    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[BasicAutoReadMemorySpec]
    """
    Never automatically read memory
    """

    VISIBLE: typing.Final[BasicAutoReadMemorySpec]
    """
    Automatically read all visible memory
    """

    VIS_RO_ONCE: typing.Final[BasicAutoReadMemorySpec]
    """
    Automatically read all visible memory, unless it is read-only, in which case, only read it if
    it has not already been read.
    """

    LOAD_EMULATOR: typing.Final[BasicAutoReadMemorySpec]
    """
    Load memory from programs for "pure" emulation traces.
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BasicAutoReadMemorySpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[BasicAutoReadMemorySpec]:
        ...


class DebuggerGoToTrait(java.lang.Object):

    class GoToResult(java.lang.Record):
        """
        
        
        
        .. seealso::
        
            | :obj:`DebuggerGoToTrait.goTo(String, String)`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, address: ghidra.program.model.address.Address, success: typing.Union[java.lang.Boolean, bool]):
            ...

        def address(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def success(self) -> bool:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: ghidra.framework.plugintool.Plugin, provider: docking.ComponentProvider):
        ...

    def goTo(self, spaceName: typing.Union[java.lang.String, str], offset: typing.Union[java.lang.String, str]) -> java.util.concurrent.CompletableFuture[DebuggerGoToTrait.GoToResult]:
        """
        Go to the given address
         
         
        
        If parsing or evaluation fails, an exception is thrown, or the future completes
        exceptionally. If the address is successfully computed, then a result will be returned. The
        :meth:`GoToResult.address() <GoToResult.address>` method gives the parsed or computed address. The
        :meth:`GoToResult.success() <GoToResult.success>` method indicates whether the cursor was successfully set to that
        address.
        
        :param java.lang.String or str spaceName: the name of the address space
        :param java.lang.String or str offset: a simple offset or Sleigh expression
        :return: the result
        :rtype: java.util.concurrent.CompletableFuture[DebuggerGoToTrait.GoToResult]
        """

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def installAction(self) -> docking.action.DockingAction:
        ...


class NoneAutoMapSpec(ghidra.debug.api.action.AutoMapSpec):

    class_: typing.ClassVar[java.lang.Class]
    CONFIG_NAME: typing.Final = "0_MAP_NONE"

    def __init__(self):
        ...


class PCByStackLocationTrackingSpec(java.lang.Enum[PCByStackLocationTrackingSpec], ghidra.debug.api.action.LocationTrackingSpec, ghidra.debug.api.action.LocationTracker):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[PCByStackLocationTrackingSpec]
    CONFIG_NAME: typing.Final = "TRACK_PC_BY_STACK"

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PCByStackLocationTrackingSpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[PCByStackLocationTrackingSpec]:
        ...


class PCLocationTrackingSpec(java.lang.Enum[PCLocationTrackingSpec], ghidra.debug.api.action.LocationTrackingSpec, ghidra.debug.api.action.LocationTracker):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[PCLocationTrackingSpec]
    CONFIG_NAME: typing.Final = "TRACK_PC"

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PCLocationTrackingSpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[PCLocationTrackingSpec]:
        ...


class DebuggerTrackLocationTrait(java.lang.Object):

    class TrackCause(java.lang.Enum[DebuggerTrackLocationTrait.TrackCause]):

        class_: typing.ClassVar[java.lang.Class]
        USER: typing.Final[DebuggerTrackLocationTrait.TrackCause]
        DB_CHANGE: typing.Final[DebuggerTrackLocationTrait.TrackCause]
        NAVIGATION: typing.Final[DebuggerTrackLocationTrait.TrackCause]
        EMU_PATCH: typing.Final[DebuggerTrackLocationTrait.TrackCause]
        SPEC_CHANGE_API: typing.Final[DebuggerTrackLocationTrait.TrackCause]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerTrackLocationTrait.TrackCause:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerTrackLocationTrait.TrackCause]:
            ...


    @typing.type_check_only
    class ForTrackingListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ListingColorModel(ghidra.app.plugin.core.debug.gui.listing.DebuggerTrackedRegisterListingBackgroundColorModel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel):
            ...


    @typing.type_check_only
    class TrackSelectionGenerator(ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: ghidra.framework.plugintool.Plugin, provider: docking.ComponentProvider):
        ...

    def computeLabelText(self) -> str:
        ...

    def createListingBackgroundColorModel(self, listingPanel: ghidra.app.util.viewer.listingpanel.ListingPanel) -> ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel:
        ...

    def getDefaultGoToInput(self, loc: ghidra.program.util.ProgramLocation) -> ghidra.debug.api.action.GoToInput:
        ...

    def getSelectionGenerator(self) -> ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator:
        ...

    def getSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    def getStates(self) -> java.util.List[docking.menu.ActionState[ghidra.debug.api.action.LocationTrackingSpec]]:
        ...

    def getTrackedLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def installAction(self) -> docking.menu.MultiStateDockingAction[ghidra.debug.api.action.LocationTrackingSpec]:
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setSpec(self, spec: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def trackedLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def selectionGenerator(self) -> ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator:
        ...

    @property
    def defaultGoToInput(self) -> ghidra.debug.api.action.GoToInput:
        ...

    @property
    def spec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    @spec.setter
    def spec(self, value: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    @property
    def states(self) -> java.util.List[docking.menu.ActionState[ghidra.debug.api.action.LocationTrackingSpec]]:
        ...


class PCByRegisterLocationTrackingSpec(java.lang.Enum[PCByRegisterLocationTrackingSpec], RegisterLocationTrackingSpec):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[PCByRegisterLocationTrackingSpec]
    CONFIG_NAME: typing.Final = "TRACK_PC_BY_REGISTER"

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> PCByRegisterLocationTrackingSpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[PCByRegisterLocationTrackingSpec]:
        ...


class DebuggerReadsMemoryTrait(java.lang.Object):

    @typing.type_check_only
    class RefreshSelectedMemoryAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractRefreshSelectedMemoryAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg1. General"

        def __init__(self):
            ...

        def updateEnabled(self, context: docking.ActionContext):
            ...


    @typing.type_check_only
    class ForReadsTraceListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForVisibilityListener(ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, plugin: ghidra.framework.plugintool.Plugin, provider: docking.ComponentProvider):
        ...

    def getAutoSpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    def getDisplayListener(self) -> ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener:
        ...

    def getLastRead(self) -> java.util.concurrent.CompletableFuture[typing.Any]:
        ...

    def getVisible(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def installAutoReadAction(self) -> docking.menu.MultiStateDockingAction[ghidra.debug.api.action.AutoReadMemorySpec]:
        ...

    def installRefreshSelectedAction(self) -> docking.action.DockingAction:
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setAutoSpec(self, autoSpec: ghidra.debug.api.action.AutoReadMemorySpec):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def visible(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def displayListener(self) -> ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener:
        ...

    @property
    def autoSpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    @autoSpec.setter
    def autoSpec(self, value: ghidra.debug.api.action.AutoReadMemorySpec):
        ...

    @property
    def lastRead(self) -> java.util.concurrent.CompletableFuture[typing.Any]:
        ...


class ByModuleAutoMapSpec(ghidra.debug.api.action.AutoMapSpec):

    class_: typing.ClassVar[java.lang.Class]
    CONFIG_NAME: typing.Final = "1_MAP_BY_MODULE"

    def __init__(self):
        ...

    @staticmethod
    def instance() -> ByModuleAutoMapSpec:
        """
        Get the instance.
         
         
        
        Note this will not work until after the class searcher is done.
        
        :return: the instance
        :rtype: ByModuleAutoMapSpec
        """


class RegisterLocationTrackingSpec(ghidra.debug.api.action.LocationTrackingSpec, ghidra.debug.api.action.LocationTracker):

    class_: typing.ClassVar[java.lang.Class]

    def computeDefaultAddressSpace(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.address.AddressSpace:
        ...

    def computeRegister(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.lang.Register:
        ...


class BasicLocationTrackingSpecFactory(ghidra.debug.api.action.LocationTrackingSpecFactory):
    """
    The factory for the basic location tracking specs: NONE, PC, SP
    """

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[java.util.List[ghidra.debug.api.action.LocationTrackingSpec]]
    BY_CONFIG_NAME: typing.Final[java.util.Map[java.lang.String, ghidra.debug.api.action.LocationTrackingSpec]]

    def __init__(self):
        ...


class WatchLocationTrackingSpec(ghidra.debug.api.action.LocationTrackingSpec):
    """
    A tracking specification for the address of a given Sleigh expression
    """

    @typing.type_check_only
    class WatchLocationTracker(ghidra.debug.api.action.LocationTracker):
        """
        The tracking logic for a watch (Sleigh expression)
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    CONFIG_PREFIX: typing.Final = "TRACK_WATCH_"

    def __init__(self, expression: typing.Union[java.lang.String, str]):
        """
        Create a tracking specification from the given expression
        
        :param java.lang.String or str expression: the Sleigh expression whose address to follow
        """

    @staticmethod
    def fromWatch(watch: ghidra.debug.api.watch.WatchRow) -> WatchLocationTrackingSpec:
        """
        Derive a tracking specification from the given watch
        
        :param ghidra.debug.api.watch.WatchRow watch: the watch who address to follow
        :return: the tracking specification
        :rtype: WatchLocationTrackingSpec
        """

    @staticmethod
    def isTrackable(watch: ghidra.debug.api.watch.WatchRow) -> bool:
        ...


class DebuggerTrackLocationAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder[ghidra.debug.api.action.LocationTrackingSpec]:
        ...


class DebuggerProgramLocationActionContext(docking.ActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    def getHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getProgram(self) -> ghidra.trace.model.program.TraceProgramView:
        ...

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        ...

    def hasHighlight(self) -> bool:
        ...

    def hasSelection(self) -> bool:
        ...

    @property
    def highlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def program(self) -> ghidra.trace.model.program.TraceProgramView:
        ...


class BasicAutoReadMemorySpecFactory(ghidra.debug.api.action.AutoReadMemorySpecFactory):

    class_: typing.ClassVar[java.lang.Class]
    ALL: typing.Final[java.util.List[ghidra.debug.api.action.AutoReadMemorySpec]]
    BY_CONFIG_NAME: typing.Final[java.util.Map[java.lang.String, ghidra.debug.api.action.AutoReadMemorySpec]]

    def __init__(self):
        ...


class WatchLocationTrackingSpecFactory(ghidra.debug.api.action.LocationTrackingSpecFactory):
    """
    The factory for tracking specifications based on watches
     
     
    
    This will generate an "address-of-watch" tracking specification for each watch currently in the
    watches service, i.e., configured in the Watches window.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BySectionAutoMapSpec(ghidra.debug.api.action.AutoMapSpec):

    class_: typing.ClassVar[java.lang.Class]
    CONFIG_NAME: typing.Final = "1_MAP_BY_SECTION"

    def __init__(self):
        ...


class ByRegionAutoMapSpec(ghidra.debug.api.action.AutoMapSpec):

    class_: typing.ClassVar[java.lang.Class]
    CONFIG_NAME: typing.Final = "1_MAP_BY_REGION"

    def __init__(self):
        ...


class DebuggerGoToDialog(ghidra.app.plugin.core.debug.gui.breakpoint.AbstractDebuggerSleighInputDialog):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trait: DebuggerGoToTrait):
        ...

    def setOffset(self, offset: typing.Union[java.lang.String, str]):
        ...

    def show(self, factory: ghidra.program.model.address.AddressFactory, defaultInput: ghidra.debug.api.action.GoToInput):
        ...


class SPLocationTrackingSpec(java.lang.Enum[SPLocationTrackingSpec], RegisterLocationTrackingSpec):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[SPLocationTrackingSpec]
    CONFIG_NAME: typing.Final = "TRACK_SP"

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> SPLocationTrackingSpec:
        ...

    @staticmethod
    def values() -> jpype.JArray[SPLocationTrackingSpec]:
        ...


class OneToOneAutoMapSpec(ghidra.debug.api.action.AutoMapSpec):

    class_: typing.ClassVar[java.lang.Class]
    CONFIG_NAME: typing.Final = "2_MAP_ONE_TO_ONE"

    def __init__(self):
        ...



__all__ = ["DebuggerAutoReadMemoryAction", "NoneLocationTrackingSpec", "BasicAutoReadMemorySpec", "DebuggerGoToTrait", "NoneAutoMapSpec", "PCByStackLocationTrackingSpec", "PCLocationTrackingSpec", "DebuggerTrackLocationTrait", "PCByRegisterLocationTrackingSpec", "DebuggerReadsMemoryTrait", "ByModuleAutoMapSpec", "RegisterLocationTrackingSpec", "BasicLocationTrackingSpecFactory", "WatchLocationTrackingSpec", "DebuggerTrackLocationAction", "DebuggerProgramLocationActionContext", "BasicAutoReadMemorySpecFactory", "WatchLocationTrackingSpecFactory", "BySectionAutoMapSpec", "ByRegionAutoMapSpec", "DebuggerGoToDialog", "SPLocationTrackingSpec", "OneToOneAutoMapSpec"]
