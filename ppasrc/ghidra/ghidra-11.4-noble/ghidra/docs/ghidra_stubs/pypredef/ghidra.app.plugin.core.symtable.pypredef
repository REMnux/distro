from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.dnd
import docking.widgets.table
import ghidra.app.util
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.worker
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class SymbolTableDnDAdapter(SymbolTableDragProvider, java.awt.dnd.DropTargetListener):
    """
    A class to combine Symbol drag and drop operations into one class.  Clients will need to 
    implement methods for getting the selected symbols and then adding dropped symbols.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: ghidra.util.table.GhidraTable, model: docking.widgets.table.RowObjectTableModel[SymbolRowObject]):
        ...


@typing.type_check_only
class ReferenceProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def getTable(self) -> ghidra.util.table.GhidraTable:
        ...

    def updateTitle(self):
        ...

    @property
    def table(self) -> ghidra.util.table.GhidraTable:
        ...


class SymbolRowObject(java.lang.Comparable[SymbolRowObject]):
    """
    ``SymbolRowObject`` provides a lightweight :obj:`Symbol`
    table row object which may be used to acquire an associated symbol.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, s: ghidra.program.model.symbol.Symbol):
        """
        Construct a symbol row object.
        Symbol must supply program object.
        
        :param ghidra.program.model.symbol.Symbol s: program symbol
        """

    def compareTo(self, other: SymbolRowObject) -> int:
        """
        The ``AbstractSortedTableModel.EndOfChainComparator`` makes it 
        necessary to implement this method to avoid use of identity hash equality
        when two instances are otherwise equal.
        """

    def getID(self) -> int:
        """
        Get symbol id used to acquire symbol from program
        
        :return: symbol id
        :rtype: int
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get the symbol associated with this row object.  If symbol no longer exists
        null may be returned.
        
        :return: associated symbol or null if symbol not found or has been deleted
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...


class SymbolRowObjectToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[SymbolRowObject, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractSymbolTableModel(ghidra.util.table.AddressBasedTableModel[SymbolRowObject]):

    @typing.type_check_only
    class NameTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, ghidra.program.model.symbol.Symbol]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PinnedTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.Boolean]):

        @typing.type_check_only
        class PinnedRenderer(docking.widgets.table.GBooleanCellRenderer, ghidra.util.table.column.AbstractWrapperTypeColumnRenderer[java.lang.Boolean]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocationTableColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[SymbolRowObject, ghidra.util.table.field.AddressBasedLocation]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolTypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class VariableSymbolLocation(ghidra.util.table.field.AddressBasedLocation):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DataTypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class NamespaceTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SourceTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, ghidra.program.model.symbol.SourceType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReferenceCountTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.Integer]):

        @typing.type_check_only
        class ReferenceCountRenderer(docking.widgets.table.GTableCellRenderer, ghidra.util.table.column.AbstractWrapperTypeColumnRenderer[java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OffcutReferenceCountTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.Integer]):

        @typing.type_check_only
        class OffcutReferenceCountRenderer(docking.widgets.table.GTableCellRenderer, ghidra.util.table.column.AbstractWrapperTypeColumnRenderer[java.lang.Integer]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UserTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OriginalNameColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SimplifiedNameColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[SymbolRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    LABEL_COL: typing.Final = 0
    LOCATION_COL: typing.Final = 1
    TYPE_COL: typing.Final = 2
    DATA_TYPE_COL: typing.Final = 3
    NAMESPACE_COL: typing.Final = 4
    SOURCE_COL: typing.Final = 5
    REFS_COL: typing.Final = 6

    def getFilter(self) -> SymbolFilter:
        ...

    def getKeyCount(self) -> int:
        ...

    def getProgramLocation(self, row: typing.Union[jpype.JInt, int]) -> ghidra.program.util.ProgramLocation:
        ...

    def getSymbolRenderer(self) -> SymbolRenderer:
        ...

    @property
    def filter(self) -> SymbolFilter:
        ...

    @property
    def keyCount(self) -> jpype.JInt:
        ...

    @property
    def symbolRenderer(self) -> SymbolRenderer:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class SymbolRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[SymbolRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class SymbolProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ReferencePanel(javax.swing.JPanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class SymbolTableDragProvider(docking.dnd.GTableDragProvider[SymbolRowObject]):
    """
    A class that provides the ability to start the dragging of :obj:`Symbol`s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: docking.widgets.table.GTable, model: docking.widgets.table.RowObjectTableModel[SymbolRowObject]):
        ...


class SymbolFilter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def accepts(self, s: ghidra.program.model.symbol.Symbol, p: ghidra.program.model.listing.Program) -> bool:
        ...

    def acceptsAll(self) -> bool:
        ...

    def acceptsDefaultLabelSymbols(self) -> bool:
        ...

    def acceptsOnlyCodeSymbols(self) -> bool:
        ...


class SymbolTablePlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to display the symbol table for a program.
    Allows navigation and changing the symbol name.
    """

    @typing.type_check_only
    class AbstractSymbolUpdateJob(ghidra.util.worker.Job):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CodeAddedRemoveJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolAddedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolRemovedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolChangedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolSourceChangedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolSetAsPrimaryJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReferenceAddedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReferenceRemovedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalEntryChangedJob(SymbolTablePlugin.AbstractSymbolUpdateJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        """
        Tells a plugin that it is no longer needed.
        The plugin should remove itself from anything that
        it is registered to and release any resources.
        """


@typing.type_check_only
class SymbolPanel(javax.swing.JPanel):

    @typing.type_check_only
    class NameOnlyRowTransformer(docking.widgets.table.DefaultRowFilterTransformer[SymbolRowObject]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class TransientSymbolTableDnDAdapter(SymbolTableDnDAdapter):
    """
    A class to enable drag and drop for temporary symbol tables.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, table: ghidra.util.table.GhidraTable, model: TransientSymbolTableModel):
        ...


@typing.type_check_only
class SymbolTableModel(AbstractSymbolTableModel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FilterDialog(docking.ReusableDialogComponentProvider):

    @typing.type_check_only
    class FilterCheckboxItemListener(java.awt.event.ItemListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def adjustFilter(self, provider: docking.ComponentProvider, model: SymbolTableModel):
        ...


class TransientSymbolTableModel(AbstractSymbolTableModel):
    """
    A symbol table model meant to show a temporary table of symbols.  The symbols in the table can
    be removed from the table by the user.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, rowObjects: java.util.HashSet[SymbolRowObject]):
        ...

    def addSymbols(self, symbolRowObjects: java.util.List[SymbolRowObject]):
        """
        Adds the given rows to this table
        
        :param java.util.List[SymbolRowObject] symbolRowObjects: the rows to add
        """


class SymbolRenderer(ghidra.util.table.GhidraTableCellRenderer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setSymbolInspector(self, inspector: ghidra.app.util.SymbolInspector):
        ...


@typing.type_check_only
class DeletedSymbolRowObject(SymbolRowObject):
    """
    ``DeletedSymbolRowObject`` provides a lightweight :obj:`Symbol`
    table row object which may be used for a deleted symbol when attempting 
    to update table model.
    """

    class_: typing.ClassVar[java.lang.Class]


class NewSymbolFilter(SymbolFilter):

    @typing.type_check_only
    class AdvancedFilter(NewSymbolFilter.Filter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Filter(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, oldFilter: SymbolFilter):
        ...

    def getActiveAdvancedFilterCount(self) -> int:
        ...

    def getActiveSourceFilterCount(self) -> int:
        ...

    def getActiveTypeFilterCount(self) -> int:
        ...

    @property
    def activeAdvancedFilterCount(self) -> jpype.JInt:
        ...

    @property
    def activeTypeFilterCount(self) -> jpype.JInt:
        ...

    @property
    def activeSourceFilterCount(self) -> jpype.JInt:
        ...


class SymbolEditor(javax.swing.DefaultCellEditor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SymbolReferenceModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.model.symbol.Reference]):

    @typing.type_check_only
    class SubroutineTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.model.symbol.Reference, java.lang.String], ghidra.util.table.field.ProgramLocationTableColumn[ghidra.program.model.symbol.Reference, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["SymbolTableDnDAdapter", "ReferenceProvider", "SymbolRowObject", "SymbolRowObjectToProgramLocationTableRowMapper", "AbstractSymbolTableModel", "SymbolRowObjectToAddressTableRowMapper", "SymbolProvider", "ReferencePanel", "SymbolTableDragProvider", "SymbolFilter", "SymbolTablePlugin", "SymbolPanel", "TransientSymbolTableDnDAdapter", "SymbolTableModel", "FilterDialog", "TransientSymbolTableModel", "SymbolRenderer", "DeletedSymbolRowObject", "NewSymbolFilter", "SymbolEditor", "SymbolReferenceModel"]
