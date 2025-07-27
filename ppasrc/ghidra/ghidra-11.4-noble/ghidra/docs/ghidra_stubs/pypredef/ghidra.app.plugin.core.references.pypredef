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
import ghidra.app.cmd.data
import ghidra.app.context
import ghidra.app.util
import ghidra.app.util.viewer.field
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore


@typing.type_check_only
class EditMemoryReferencePanel(EditReferencePanel):

    @typing.type_check_only
    class HistoryTableModel(javax.swing.table.AbstractTableModel):

        class_: typing.ClassVar[java.lang.Class]

        def getAddress(self, rowIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
            ...

        @property
        def address(self) -> ghidra.program.model.address.Address:
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ParameterConflictException(java.lang.Exception):
    """
    ``ParameterConflictException`` indicates that the 
    stack offset conflicts with an existing function parameter.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class InstructionPanelListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dropSupported(self) -> bool:
        ...

    def operandSelected(self, opIndex: typing.Union[jpype.JInt, int], subIndex: typing.Union[jpype.JInt, int]):
        ...

    def selectionDropped(self, set: ghidra.program.model.address.AddressSetView, cu: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int]):
        ...


class ReferencesPlugin(ghidra.framework.plugintool.Plugin):

    @typing.type_check_only
    class CreateRefActionWrapper(ghidra.app.context.ListingContextAction):
        """
        Wrapper class for createRefAction, allowing deprecated key bindings to
        set for specific reference class.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def addReference(self, fromCodeUnit: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType) -> bool:
        ...

    @typing.overload
    def addReference(self, fromCodeUnit: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int], extName: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str]) -> bool:
        ...

    def getCodeUnitFormat(self) -> ghidra.app.util.viewer.field.BrowserCodeUnitFormat:
        ...

    def getSymbolInspector(self) -> ghidra.app.util.SymbolInspector:
        ...

    @typing.overload
    def updateReference(self, editRef: ghidra.program.model.symbol.StackReference, fromCodeUnit: ghidra.program.model.listing.CodeUnit, stackOffset: typing.Union[jpype.JInt, int], refType: ghidra.program.model.symbol.RefType) -> bool:
        ...

    @typing.overload
    def updateReference(self, editRef: ghidra.program.model.symbol.ExternalReference, fromCodeUnit: ghidra.program.model.listing.CodeUnit, extName: typing.Union[java.lang.String, str], path: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str]) -> bool:
        ...

    @property
    def codeUnitFormat(self) -> ghidra.app.util.viewer.field.BrowserCodeUnitFormat:
        ...

    @property
    def symbolInspector(self) -> ghidra.app.util.SymbolInspector:
        ...


@typing.type_check_only
class EditExternalReferencePanel(EditReferencePanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class EditReferencesProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.framework.model.DomainObjectListener, javax.swing.event.ChangeListener):

    @typing.type_check_only
    class ReferenceInfo(java.lang.Object):
        """
        Fun little storage object
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefTypeCellEditor(javax.swing.DefaultCellEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CellEditComboBox(javax.swing.JComboBox[ghidra.program.model.symbol.RefType]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefCellBooleanRenderer(docking.widgets.table.GBooleanCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefCellBooleanEditor(javax.swing.DefaultCellEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RefCellTextRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def dispose(self):
        ...

    @typing.overload
    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @typing.overload
    def getCodeUnit(self, currProgram: ghidra.program.model.listing.Program, currLocation: ghidra.program.util.ProgramLocation) -> ghidra.program.model.listing.CodeUnit:
        ...

    def getInitLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def initLocation(self) -> ghidra.program.util.ProgramLocation:
        ...


class OffsetTableDialog(docking.DialogComponentProvider):
    """
    Dialog to prompt for base address and the size of the data type that
    will be used in creating an offset table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getBaseAddress(self) -> ghidra.program.model.address.Address:
        ...

    def setBaseAddress(self, address: ghidra.program.model.address.Address):
        ...

    @property
    def baseAddress(self) -> ghidra.program.model.address.Address:
        ...

    @baseAddress.setter
    def baseAddress(self, value: ghidra.program.model.address.Address):
        ...


class OffsetTablePlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to create offset tables based on a selection of data.  A dialog is
    displayed so that the user can enter a base address and the 
    data type size. Data of the appropriate type is created; a reference to 
    the base address + offset is placed on the operand index for each data 
    that was created. The offset is the value of the data type.
    """

    @typing.type_check_only
    class ClearCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyCreateDataCmd(ghidra.app.cmd.data.CreateDataCmd):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        
        
        :param pluginName: :param ghidra.framework.plugintool.PluginTool tool:
        """


@typing.type_check_only
class EditStackReferencePanel(EditReferencePanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DeleteReferencesAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ReferencesPlugin):
        ...


class CreateDefaultReferenceAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ReferencesPlugin):
        ...


@typing.type_check_only
class InstructionPanel(javax.swing.JPanel, javax.swing.event.ChangeListener):

    @typing.type_check_only
    class LabelMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InstructionPanelDroppable(docking.dnd.Droppable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EditRegisterReferencePanel(EditReferencePanel):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ReservedNameException(java.lang.Exception):
    """
    ``ReservedNameException`` indicates that the specified name
    is reserved for system use.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EditReferencesModel(docking.widgets.table.AbstractSortedTableModel[ghidra.program.model.symbol.Reference]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class EditReferenceDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ReferencesPlugin):
        ...

    def initDialog(self, cu: ghidra.program.model.listing.CodeUnit, opIndex: typing.Union[jpype.JInt, int], subIndex: typing.Union[jpype.JInt, int], ref: ghidra.program.model.symbol.Reference):
        ...


@typing.type_check_only
class EditReferencePanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def requestFocus(self):
        """
        Places focus in the first focusable component within this panel.
        
        
        .. seealso::
        
            | :obj:`java.awt.Component.requestFocus()`
        """


class ExternalReferencesProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    ComponentProvider that displays a table of External Programs.
    """

    @typing.type_check_only
    class ExternalNamesRow(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalNamesTableModel(docking.widgets.table.AbstractSortedTableModel[ExternalReferencesProvider.ExternalNamesRow]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ReferencesPlugin):
        ...

    def getSelectedExternalNames(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def selectedExternalNames(self) -> java.util.List[java.lang.String]:
        ...



__all__ = ["EditMemoryReferencePanel", "ParameterConflictException", "InstructionPanelListener", "ReferencesPlugin", "EditExternalReferencePanel", "EditReferencesProvider", "OffsetTableDialog", "OffsetTablePlugin", "EditStackReferencePanel", "DeleteReferencesAction", "CreateDefaultReferenceAction", "InstructionPanel", "EditRegisterReferencePanel", "ReservedNameException", "EditReferencesModel", "EditReferenceDialog", "EditReferencePanel", "ExternalReferencesProvider"]
