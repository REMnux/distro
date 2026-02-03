from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.widgets.table
import ghidra.app.plugin.core.byteviewer # type: ignore
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.debug.gui.action
import ghidra.app.plugin.core.debug.gui.colors
import ghidra.app.plugin.core.debug.gui.model
import ghidra.app.plugin.core.debug.gui.model.columns
import ghidra.app.plugin.core.format # type: ignore
import ghidra.app.services
import ghidra.debug.api.action
import ghidra.debug.api.tracemgr
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.memory
import java.awt # type: ignore
import java.lang # type: ignore
import java.nio # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DebuggerMemoryBytesActionContext(ghidra.app.plugin.core.byteviewer.ByteViewerActionContext, ghidra.app.plugin.core.debug.gui.action.DebuggerProgramLocationActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.byteviewer.ProgramByteViewerComponentProvider):
        ...


class DebuggerMemoryBytesProvider(ghidra.app.plugin.core.byteviewer.ProgramByteViewerComponentProvider):

    @typing.type_check_only
    class ListenerForChanges(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForMemoryBytesGoToTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerGoToTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForMemoryBytesTrackingTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerTrackLocationTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForMemoryBytesReadsMemoryTrait(ghidra.app.plugin.core.debug.gui.action.DebuggerReadsMemoryTrait):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ForBytesClipboardProvider(ghidra.app.plugin.core.byteviewer.ByteViewerClipboardProvider):

        @typing.type_check_only
        class PasteIntoTargetCommand(ghidra.app.util.ByteCopier.PasteByteStringCommand, ghidra.app.plugin.core.debug.gui.PasteIntoTargetMixin):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TargetByteBlock(ghidra.app.plugin.core.byteviewer.MemoryByteBlock):
        """
        Override where edits are allowed and direct sets through the control service.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TargetByteBlockSet(ghidra.app.plugin.core.byteviewer.ProgramByteBlockSet):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def getAutoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    def getTrackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    def goToCoordinates(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def isFollowsCurrentThread(self) -> bool:
        ...

    def isMainViewer(self) -> bool:
        ...

    def setAutoReadMemorySpec(self, spec: ghidra.debug.api.action.AutoReadMemorySpec):
        ...

    def setFollowsCurrentThread(self, follows: typing.Union[jpype.JBoolean, bool]):
        ...

    def setTrackingSpec(self, spec: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...

    @property
    def followsCurrentThread(self) -> jpype.JBoolean:
        ...

    @followsCurrentThread.setter
    def followsCurrentThread(self, value: jpype.JBoolean):
        ...

    @property
    def trackingSpec(self) -> ghidra.debug.api.action.LocationTrackingSpec:
        ...

    @trackingSpec.setter
    def trackingSpec(self, value: ghidra.debug.api.action.LocationTrackingSpec):
        ...

    @property
    def autoReadMemorySpec(self) -> ghidra.debug.api.action.AutoReadMemorySpec:
        ...

    @autoReadMemorySpec.setter
    def autoReadMemorySpec(self, value: ghidra.debug.api.action.AutoReadMemorySpec):
        ...

    @property
    def mainViewer(self) -> jpype.JBoolean:
        ...


class CachedBytePage(java.lang.Object):

    @typing.type_check_only
    class CacheKey(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def coordinates(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def start(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class CacheEntry(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, page: jpype.JArray[jpype.JByte]):
            ...

        @typing.overload
        def __init__(self):
            ...

        def buf(self) -> java.nio.ByteBuffer:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def page(self) -> jpype.JArray[jpype.JByte]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getByte(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, address: ghidra.program.model.address.Address) -> int:
        ...

    def invalidate(self):
        ...


class DebuggerRegionsPanel(ghidra.app.plugin.core.debug.gui.model.AbstractObjectsTableBasedPanel[ghidra.trace.model.memory.TraceMemoryRegion]):

    @typing.type_check_only
    class RegionKeyColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RegionPathColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RegionNameColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RegionStartColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class RegionEndColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class RegionLengthColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectLengthColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RegionFlagColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[java.lang.Boolean]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, attributeName: typing.Union[java.lang.String, str]):
            ...


    class RegionReadColumn(DebuggerRegionsPanel.RegionFlagColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RegionWriteColumn(DebuggerRegionsPanel.RegionFlagColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class RegionExecuteColumn(DebuggerRegionsPanel.RegionFlagColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class RegionTableModel(ghidra.app.plugin.core.debug.gui.model.ObjectTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerRegionsProvider):
        ...

    def setSelectedRegions(self, sel: java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion]):
        ...


class DebuggerAddRegionDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLength(self) -> int:
        ...

    def setPath(self, path: typing.Union[java.lang.String, str]):
        ...

    def show(self, tool: ghidra.framework.plugintool.PluginTool, current: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    @property
    def length(self) -> jpype.JLong:
        ...


class DebuggerRegionsProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class MapRegionsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Regions"
        DESCRIPTION: typing.Final = "Map selected regions to program memory blocks"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_regions"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapRegionToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Map Region to "
        DESCRIPTION: typing.Final = "Map the selected region to the current program"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_region_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapRegionsToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Map Regions to "
        DESCRIPTION: typing.Final = "Map the selected (module) regions to the current program"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_regions_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class AddRegionAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Add Region"
        DESCRIPTION: typing.Final = "Manually add a region to the memory map"
        GROUP: typing.Final = "Dbg8. Maintenance"
        HELP_ANCHOR: typing.Final = "add_region"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class DeleteRegionsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Delete Regions"
        DESCRIPTION: typing.Final = "Delete one or more regions from the memory map"
        GROUP: typing.Final = "Dbg8. Maintenance"
        HELP_ANCHOR: typing.Final = "delete_regions"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ForceFullViewAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Force Full View"
        DESCRIPTION: typing.Final = "Ignore regions and fiew full address spaces"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "force_full_view"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class SelectAddressesAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg1. General"

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerRegionsPlugin):
        ...

    def askBlock(self, region: ghidra.trace.model.memory.TraceMemoryRegion, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...

    @staticmethod
    def computeBlock(location: ghidra.program.util.ProgramLocation) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @staticmethod
    def computeBlockName(location: ghidra.program.util.ProgramLocation) -> str:
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    def setLocation(self, location: ghidra.program.util.ProgramLocation):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setSelectedRegions(self, sel: java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion]):
        ...


class DebuggerRegionsPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerRegionMapProposalDialog(ghidra.app.plugin.core.debug.gui.AbstractDebuggerMapProposalDialog[ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry]):

    @typing.type_check_only
    class RegionMapTableColumns(java.lang.Enum[DebuggerRegionMapProposalDialog.RegionMapTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerRegionMapProposalDialog.RegionMapTableColumns, ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry]):

        class_: typing.ClassVar[java.lang.Class]
        REMOVE: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        REGION_NAME: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        DYNAMIC_BASE: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        CHOOSE: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        PROGRAM_NAME: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        BLOCK_NAME: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        STATIC_BASE: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]
        SIZE: typing.Final[DebuggerRegionMapProposalDialog.RegionMapTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerRegionMapProposalDialog.RegionMapTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerRegionMapProposalDialog.RegionMapTableColumns]:
            ...


    @typing.type_check_only
    class RegionMapPropsalTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerRegionMapProposalDialog.RegionMapTableColumns, ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerRegionsProvider):
        ...


class DebuggerMemoryByteViewerComponent(ghidra.app.plugin.core.byteviewer.ByteViewerComponent, ghidra.app.plugin.core.debug.gui.colors.SelectionTranslator):

    @typing.type_check_only
    class SelectionHighlightSelectionGenerator(ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TraceMemoryStateSelectionGenerator(ghidra.app.plugin.core.debug.gui.colors.SelectionGenerator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vpanel: DebuggerMemoryBytesPanel, layoutModel: ghidra.app.plugin.core.byteviewer.ByteViewerLayoutModel, model: ghidra.app.plugin.core.format.DataFormatModel, bytesPerLine: typing.Union[jpype.JInt, int], fm: java.awt.FontMetrics):
        ...


class DebuggerMemoryBytesPanel(ghidra.app.plugin.core.byteviewer.ByteViewerPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerMemoryBytesProvider):
        ...

    def getProvider(self) -> DebuggerMemoryBytesProvider:
        """
        TODO: I don't care for this
        """

    @property
    def provider(self) -> DebuggerMemoryBytesProvider:
        ...


class DebuggerRegionActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, selected: java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion], sourceComponent: java.awt.Component, forcedSingle: typing.Union[jpype.JBoolean, bool]):
        ...

    def getSelectedRegions(self) -> java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion]:
        ...

    def isForcedSingle(self) -> bool:
        ...

    @property
    def selectedRegions(self) -> java.util.Set[ghidra.trace.model.memory.TraceMemoryRegion]:
        ...

    @property
    def forcedSingle(self) -> jpype.JBoolean:
        ...


class DebuggerMemoryBytesPlugin(ghidra.app.plugin.core.byteviewer.AbstractByteViewerPlugin[DebuggerMemoryBytesProvider]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createViewerIfMissing(self, spec: ghidra.debug.api.action.LocationTrackingSpec, followsCurrentThread: typing.Union[jpype.JBoolean, bool]) -> DebuggerMemoryBytesProvider:
        ...

    def setTraceManager(self, traceManager: ghidra.app.services.DebuggerTraceManagerService):
        ...



__all__ = ["DebuggerMemoryBytesActionContext", "DebuggerMemoryBytesProvider", "CachedBytePage", "DebuggerRegionsPanel", "DebuggerAddRegionDialog", "DebuggerRegionsProvider", "DebuggerRegionsPlugin", "DebuggerRegionMapProposalDialog", "DebuggerMemoryByteViewerComponent", "DebuggerMemoryBytesPanel", "DebuggerRegionActionContext", "DebuggerMemoryBytesPlugin"]
