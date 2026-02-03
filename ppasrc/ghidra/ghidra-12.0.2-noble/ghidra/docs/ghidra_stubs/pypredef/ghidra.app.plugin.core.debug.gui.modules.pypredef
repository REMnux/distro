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
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui
import ghidra.app.plugin.core.debug.gui.model
import ghidra.app.plugin.core.debug.gui.model.columns
import ghidra.app.plugin.core.debug.utils
import ghidra.app.services
import ghidra.debug.api.action
import ghidra.debug.api.model
import ghidra.debug.api.modules
import ghidra.debug.api.tracemgr
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.modules
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DebuggerSectionsPanel(ghidra.app.plugin.core.debug.gui.model.AbstractObjectsTableBasedPanel[ghidra.trace.model.modules.TraceSection]):

    @typing.type_check_only
    class SectionStartColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SectionEndColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SectionNameColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SectionPathColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SectionModuleNameColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SectionLengthColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectLengthColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class SectionTableModel(ghidra.app.plugin.core.debug.gui.model.ObjectTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SectionsBySelectedModulesTableFilter(docking.widgets.table.TableFilter[ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerModulesProvider):
        ...

    def setFilteredBySelectedModules(self, filtered: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSelectedSections(self, sel: java.util.Set[ghidra.trace.model.modules.TraceSection]):
        ...


class DebuggerModuleMapProposalDialog(ghidra.app.plugin.core.debug.gui.AbstractDebuggerMapProposalDialog[ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry]):

    @typing.type_check_only
    class ModuleMapTableColumns(java.lang.Enum[DebuggerModuleMapProposalDialog.ModuleMapTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerModuleMapProposalDialog.ModuleMapTableColumns, ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry]):

        class_: typing.ClassVar[java.lang.Class]
        REMOVE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        MODULE_NAME: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        DYNAMIC_BASE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        CHOOSE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        PROGRAM_NAME: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        STATIC_BASE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        SIZE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]
        MEMORIZE: typing.Final[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerModuleMapProposalDialog.ModuleMapTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerModuleMapProposalDialog.ModuleMapTableColumns]:
            ...


    @typing.type_check_only
    class ModuleMapPropsalTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerModuleMapProposalDialog.ModuleMapTableColumns, ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    class_: typing.ClassVar[java.lang.Class]


class StaticMappingRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mapping: ghidra.trace.model.modules.TraceStaticMapping):
        ...

    def getBigLength(self) -> java.math.BigInteger:
        ...

    def getLength(self) -> int:
        ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    def getMapping(self) -> ghidra.trace.model.modules.TraceStaticMapping:
        ...

    def getShift(self) -> int:
        ...

    def getStaticAddress(self) -> str:
        ...

    def getStaticProgramURL(self) -> java.net.URL:
        ...

    def getTrace(self) -> ghidra.trace.model.Trace:
        ...

    def getTraceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def mapping(self) -> ghidra.trace.model.modules.TraceStaticMapping:
        ...

    @property
    def bigLength(self) -> java.math.BigInteger:
        ...

    @property
    def staticProgramURL(self) -> java.net.URL:
        ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan:
        ...

    @property
    def traceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def shift(self) -> jpype.JLong:
        ...

    @property
    def length(self) -> jpype.JLong:
        ...

    @property
    def staticAddress(self) -> java.lang.String:
        ...


class DebuggerAddMappingDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getLength(self) -> int:
        ...

    def setMappingService(self, mappingService: ghidra.app.services.DebuggerStaticMappingService):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...

    def setValues(self, program: ghidra.program.model.listing.Program, trace: ghidra.trace.model.Trace, progStart: ghidra.program.model.address.Address, traceStart: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], lifespan: ghidra.trace.model.Lifespan):
        """
        Set the values of the fields
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.program.model.address.Address progStart: the starting static address
        :param ghidra.program.model.address.Address traceStart: the starting dynamic address
        :param jpype.JLong or int length: the length (0 indicates the entire 64-bit range)
        :param ghidra.trace.model.Lifespan lifespan: the lifespan
        :raises AddressOverflowException: if the length is too large for either space
        """

    @property
    def length(self) -> jpype.JLong:
        ...


class DebuggerModuleActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, selected: java.util.Set[ghidra.trace.model.modules.TraceModule], sourceComponent: java.awt.Component, forcedSingle: typing.Union[jpype.JBoolean, bool]):
        ...

    def getSelectedModules(self) -> java.util.Set[ghidra.trace.model.modules.TraceModule]:
        ...

    def isForcedSingle(self) -> bool:
        ...

    @property
    def selectedModules(self) -> java.util.Set[ghidra.trace.model.modules.TraceModule]:
        ...

    @property
    def forcedSingle(self) -> jpype.JBoolean:
        ...


class DebuggerModulesPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerModulesProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.services.DebuggerAutoMappingService):

    @typing.type_check_only
    class MapIdenticallyAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Identically"
        DESCRIPTION: typing.Final = "Map the current trace to the current program using identical addresses"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_identically"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapManuallyAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Manually"
        DESCRIPTION: typing.Final = "Map the current trace to various programs manually"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_manually"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapModulesAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Modules"
        DESCRIPTION: typing.Final = "Map selected modules to program images"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_modules"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapModuleToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Map Module to "
        DESCRIPTION: typing.Final = "Map the selected module to the current program"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_module_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapSectionsAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Sections"
        DESCRIPTION: typing.Final = "Map selected sections to program memory blocks"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_sections"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapSectionToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Map Section to "
        DESCRIPTION: typing.Final = "Map the selected section to the current program"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_section_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapSectionsToAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME_PREFIX: typing.Final = "Map Sections to "
        DESCRIPTION: typing.Final = "Map the selected module sections to the current program"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "map_sections_to"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class AutoMapAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Auto-Map Target Memory"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Automatically map dynamic memory to static counterparts"
        GROUP: typing.Final = "Dbg9. Map Modules/Sections"
        HELP_ANCHOR: typing.Final = "auto_map"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder[ghidra.debug.api.action.AutoMapSpec]:
            ...


    @typing.type_check_only
    class ImportMissingModuleAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Import Missing Module"
        DESCRIPTION: typing.Final = "Import the missing module from disk"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "import_missing_module"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapMissingModuleAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Missing Module"
        DESCRIPTION: typing.Final = "Map the missing module to an existing import"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "map_missing_module"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapMissingProgramRetryAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Retry Map Missing Program"
        DESCRIPTION: typing.Final = "Retry mapping the missing program by finding its module"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "map_missing_program_retry"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapMissingProgramToCurrentAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Missing Program to Current Module"
        DESCRIPTION: typing.Final = "Map the missing program to the current module"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "map_missing_program_current"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class MapMissingProgramIdenticallyAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Map Missing Program Identically"
        DESCRIPTION: typing.Final = "Map the missing program to its trace identically"
        ICON: typing.Final[javax.swing.Icon]
        HELP_ANCHOR: typing.Final = "map_missing_program_identically"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ShowSectionsTableAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Show Sections Table"
        ICON: typing.Final[javax.swing.Icon]
        DESCRIPTION: typing.Final = "Toggle display fo the Sections Table pane"
        GROUP: typing.Final = "yyyy"
        ORDER: typing.Final = "1"
        HELP_ANCHOR: typing.Final = "show_sections_table"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class AutoMapState(ghidra.trace.model.TraceDomainObjectListener, ghidra.framework.model.TransactionListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, spec: ghidra.debug.api.action.AutoMapSpec):
            ...

        def dispose(self):
            ...

        def forceMap(self):
            ...


    @typing.type_check_only
    class SelectAddressesAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg1. General"

        def __init__(self):
            ...


    @typing.type_check_only
    class ImportFromFileSystemAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractImportFromFileSystemAction):

        class_: typing.ClassVar[java.lang.Class]
        GROUP: typing.Final = "Dbg1. General"

        def __init__(self):
            ...


    @typing.type_check_only
    class ForCleanupMappingChangeListener(ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerModulesPlugin):
        ...

    def askBlock(self, section: ghidra.trace.model.modules.TraceSection, program: ghidra.program.model.listing.Program, block: ghidra.program.model.mem.MemoryBlock) -> java.util.Map.Entry[ghidra.program.model.listing.Program, ghidra.program.model.mem.MemoryBlock]:
        ...

    def askProgram(self, program: ghidra.program.model.listing.Program) -> ghidra.framework.model.DomainFile:
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

    def programOpened(self, program: ghidra.program.model.listing.Program):
        ...

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setFilterSectionsByModules(self, filterSectionsByModules: typing.Union[jpype.JBoolean, bool]):
        ...

    def setLocation(self, location: ghidra.program.util.ProgramLocation):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setSelectedModules(self, sel: java.util.Set[ghidra.trace.model.modules.TraceModule]):
        ...

    def setSelectedSections(self, sel: java.util.Set[ghidra.trace.model.modules.TraceSection]):
        ...

    def setShowSectionsTable(self, showSectionsTable: typing.Union[jpype.JBoolean, bool]):
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...

    def traceOpened(self, trace: ghidra.trace.model.Trace):
        ...

    def writeConfigState(self, saveState: ghidra.framework.options.SaveState):
        ...


class DebuggerStaticMappingPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerStaticMappingActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerStaticMappingProvider, selected: collections.abc.Sequence, table: docking.widgets.table.GTable):
        ...

    def getSelectedMappings(self) -> java.util.Collection[StaticMappingRow]:
        ...

    @property
    def selectedMappings(self) -> java.util.Collection[StaticMappingRow]:
        ...


class DebuggerModulesPanel(ghidra.app.plugin.core.debug.gui.model.AbstractObjectsTableBasedPanel[ghidra.trace.model.modules.TraceModule]):

    @typing.type_check_only
    class ModuleBaseColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ModuleMaxColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectAddressColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ModuleNameColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ModuleMappingColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModulePathColumn(ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ModuleLengthColumn(ghidra.app.plugin.core.debug.gui.model.columns.AbstractTraceValueObjectLengthColumn):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ModuleTableModel(ghidra.app.plugin.core.debug.gui.model.ObjectTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerModulesProvider):
        ...

    @staticmethod
    def getSelectedAddressesFromContext(ctx: ghidra.debug.api.model.DebuggerObjectActionContext) -> ghidra.program.model.address.AddressSetView:
        ...

    def setSelectedModules(self, sel: java.util.Set[ghidra.trace.model.modules.TraceModule]):
        ...


class DebuggerStaticMappingProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.plugin.core.debug.gui.DebuggerProvider):

    @typing.type_check_only
    class StaticMappingTableColumns(java.lang.Enum[DebuggerStaticMappingProvider.StaticMappingTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerStaticMappingProvider.StaticMappingTableColumns, StaticMappingRow]):

        class_: typing.ClassVar[java.lang.Class]
        DYNAMIC_ADDRESS: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]
        STATIC_URL: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]
        STATIC_ADDRESS: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]
        LENGTH: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]
        SHIFT: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]
        LIFESPAN: typing.Final[DebuggerStaticMappingProvider.StaticMappingTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerStaticMappingProvider.StaticMappingTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerStaticMappingProvider.StaticMappingTableColumns]:
            ...


    @typing.type_check_only
    class MappingTableModel(ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel[DebuggerStaticMappingProvider.StaticMappingTableColumns, ghidra.util.database.ObjectKey, StaticMappingRow, ghidra.trace.model.modules.TraceStaticMapping]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class ListenerForStaticMappingDisplay(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerStaticMappingPlugin):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    def setSelectedMappings(self, sel: java.util.Set[ghidra.trace.model.modules.TraceStaticMapping]):
        ...

    def setTrace(self, trace: ghidra.trace.model.Trace):
        ...


class DebuggerSectionMapProposalDialog(ghidra.app.plugin.core.debug.gui.AbstractDebuggerMapProposalDialog[ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry]):

    @typing.type_check_only
    class SectionMapTableColumns(java.lang.Enum[DebuggerSectionMapProposalDialog.SectionMapTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerSectionMapProposalDialog.SectionMapTableColumns, ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry]):

        class_: typing.ClassVar[java.lang.Class]
        REMOVE: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        MODULE_NAME: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        SECTION_NAME: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        DYNAMIC_BASE: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        CHOOSE: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        PROGRAM_NAME: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        BLOCK_NAME: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        STATIC_BASE: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]
        SIZE: typing.Final[DebuggerSectionMapProposalDialog.SectionMapTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerSectionMapProposalDialog.SectionMapTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerSectionMapProposalDialog.SectionMapTableColumns]:
            ...


    @typing.type_check_only
    class SectionMapPropsalTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerSectionMapProposalDialog.SectionMapTableColumns, ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerModulesProvider):
        ...


class DebuggerSectionActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, selected: java.util.Set[ghidra.trace.model.modules.TraceSection], sourceComponent: java.awt.Component, forcedSingle: typing.Union[jpype.JBoolean, bool]):
        ...

    def getSelectedSections(self, allowExpansion: typing.Union[jpype.JBoolean, bool], snap: typing.Union[jpype.JLong, int]) -> java.util.Set[ghidra.trace.model.modules.TraceSection]:
        ...

    def isForcedSingle(self) -> bool:
        ...

    @property
    def forcedSingle(self) -> jpype.JBoolean:
        ...



__all__ = ["DebuggerSectionsPanel", "DebuggerModuleMapProposalDialog", "StaticMappingRow", "DebuggerAddMappingDialog", "DebuggerModuleActionContext", "DebuggerModulesPlugin", "DebuggerModulesProvider", "DebuggerStaticMappingPlugin", "DebuggerStaticMappingActionContext", "DebuggerModulesPanel", "DebuggerStaticMappingProvider", "DebuggerSectionMapProposalDialog", "DebuggerSectionActionContext"]
