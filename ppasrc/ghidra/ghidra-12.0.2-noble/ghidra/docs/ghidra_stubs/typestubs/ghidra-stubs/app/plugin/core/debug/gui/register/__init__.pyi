from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action.builder
import docking.actions
import docking.widgets.table
import ghidra.app.plugin.core.data
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui
import ghidra.base.widgets.table
import ghidra.debug.api.tracemgr
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.util.classfinder
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


class DebuggerRegistersProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.app.plugin.core.debug.gui.DebuggerProvider, docking.actions.PopupActionProvider):

    @typing.type_check_only
    class ClearRegisterType(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Clear Register Type"
        DESCRIPTION: typing.Final = "Clear the register\'s data type"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class RegisterTypeSettings(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Register Type Settings"
        DESCRIPTION: typing.Final = "Set the register\'s data type settings"
        HELP_ANCHOR: typing.Final = "type_settings"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class RegisterDataSettingsDialog(ghidra.app.plugin.core.data.DataSettingsDialog):
        """
        This only exists so that tests can access it
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: ghidra.program.model.listing.Data):
            ...


    @typing.type_check_only
    class RegisterTableColumns(java.lang.Enum[DebuggerRegistersProvider.RegisterTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerRegistersProvider.RegisterTableColumns, RegisterRow]):

        class_: typing.ClassVar[java.lang.Class]
        FAV: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]
        NUMBER: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]
        NAME: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]
        VALUE: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]
        TYPE: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]
        REPR: typing.Final[DebuggerRegistersProvider.RegisterTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerRegistersProvider.RegisterTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerRegistersProvider.RegisterTableColumns]:
            ...


    @typing.type_check_only
    class RegistersTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerRegistersProvider.RegisterTableColumns, RegisterRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    @typing.type_check_only
    class TraceChangeListener(ghidra.trace.model.TraceDomainObjectListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class RegisterValueCellRenderer(docking.widgets.table.HexDefaultGColumnRenderer[java.math.BigInteger]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RegisterDataTypeEditor(ghidra.base.widgets.table.DataTypeTableCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def cloneAsDisconnected(self) -> DebuggerRegistersProvider:
        ...

    @staticmethod
    def collectCommonRegisters(cSpec: ghidra.program.model.lang.CompilerSpec) -> java.util.LinkedHashSet[ghidra.program.model.lang.Register]:
        """
        Gather general registers, the program counter, and the stack pointer
         
        
        This excludes the context register
         
        
        TODO: Several pspec files need adjustment to clean up "common registers"
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler spec
        :return: the set of "common" registers
        :rtype: java.util.LinkedHashSet[ghidra.program.model.lang.Register]
        """

    def computeDefaultRegisterFavorites(self, platform: ghidra.trace.model.guest.TracePlatform) -> java.util.LinkedHashSet[ghidra.program.model.lang.Register]:
        ...

    def computeDefaultRegisterSelection(self, platform: ghidra.trace.model.guest.TracePlatform) -> java.util.LinkedHashSet[ghidra.program.model.lang.Register]:
        ...

    def coordinatesActivated(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Notify this provider of new coordinates
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the new coordinates
        :return: true if the new coordinates caused the table to update
        :rtype: bool
        """

    def getCurrent(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    def getRegisterRow(self, register: ghidra.program.model.lang.Register) -> RegisterRow:
        ...

    def isFavorite(self, register: ghidra.program.model.lang.Register) -> bool:
        ...

    def readDataState(self, saveState: ghidra.framework.options.SaveState):
        ...

    def setSelectedRegistersAndLoad(self, selectedRegisters: collections.abc.Sequence) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        ...

    def setSelectedRow(self, row: RegisterRow):
        ...

    def writeDataState(self, saveState: ghidra.framework.options.SaveState):
        ...

    @property
    def current(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def favorite(self) -> jpype.JBoolean:
        ...

    @property
    def registerRow(self) -> RegisterRow:
        ...


class DebuggerAvailableRegistersActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, selection: collections.abc.Sequence):
        ...

    def getSelection(self) -> java.util.Collection[AvailableRegisterRow]:
        ...

    @property
    def selection(self) -> java.util.Collection[AvailableRegisterRow]:
        ...


class AvailableRegisterRow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, number: typing.Union[jpype.JInt, int], register: ghidra.program.model.lang.Register):
        ...

    def getBits(self) -> int:
        ...

    def getContains(self) -> str:
        ...

    def getGroup(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getNumber(self) -> int:
        ...

    def getParentName(self) -> str:
        ...

    def getRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def isKnown(self) -> bool:
        ...

    def isSelected(self) -> bool:
        ...

    def setKnown(self, known: typing.Union[jpype.JBoolean, bool]):
        ...

    def setSelected(self, select: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def number(self) -> jpype.JInt:
        ...

    @property
    def parentName(self) -> java.lang.String:
        ...

    @property
    def contains(self) -> java.lang.String:
        ...

    @property
    def known(self) -> jpype.JBoolean:
        ...

    @known.setter
    def known(self, value: jpype.JBoolean):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def bits(self) -> jpype.JInt:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...

    @selected.setter
    def selected(self, value: jpype.JBoolean):
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def group(self) -> java.lang.String:
        ...


class DebuggerAvailableRegistersDialog(docking.ReusableDialogComponentProvider):

    @typing.type_check_only
    class AvailableRegisterTableColumns(java.lang.Enum[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns], docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns, AvailableRegisterRow]):

        class_: typing.ClassVar[java.lang.Class]
        SELECTED: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        NUMBER: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        NAME: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        BITS: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        KNOWN: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        GROUP: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        CONTAINS: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]
        PARENT: typing.Final[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns:
            ...

        @staticmethod
        def values() -> jpype.JArray[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns]:
            ...


    @typing.type_check_only
    class AvailableRegistersTableModel(docking.widgets.table.DefaultEnumeratedColumnTableModel[DebuggerAvailableRegistersDialog.AvailableRegisterTableColumns, AvailableRegisterRow]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def setKnown(self, known: collections.abc.Sequence):
        ...

    def setLanguage(self, language: ghidra.program.model.lang.Language):
        ...

    def setSelection(self, selection: collections.abc.Sequence):
        ...


class DebuggerRegistersPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def encodeSetsByCSpec(setsByCSpec: collections.abc.Mapping) -> str:
        ...

    @staticmethod
    def readSetsByCSpec(setsByCSpec: collections.abc.Mapping, encoded: typing.Union[java.lang.String, str]):
        ...


class RegisterRow(java.lang.Object):
    """
    A row displayed in the registers table of the Debugger
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCurrent(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        """
        Get the table's current coordinates (usually also the tool's)
        
        :return: the coordinates
        :rtype: ghidra.debug.api.tracemgr.DebuggerCoordinates
        """

    def getData(self) -> ghidra.program.model.listing.Data:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the data type of the register
        
        :return: the data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getName(self) -> str:
        """
        Get the register's name
        
        :return: the name
        :rtype: str
        """

    def getNumber(self) -> int:
        """
        The index where this register appears in the language's :meth:`Language.getRegisters() <Language.getRegisters>` list
        
        :return: the index
        :rtype: int
        """

    def getRegister(self) -> ghidra.program.model.lang.Register:
        """
        Get the register
        
        :return: the register
        :rtype: ghidra.program.model.lang.Register
        """

    def getRepresentation(self) -> str:
        """
        Get the value of the register as represented by its data type
        
        :return: the value
        :rtype: str
        """

    def getValue(self) -> java.math.BigInteger:
        """
        Get the value of the register
         
         
        
        TODO: Perhaps some caching for all these getters which rely on the DB, since they could be
        invoked on every repaint.
        
        :return: the value
        :rtype: java.math.BigInteger
        """

    def isChanged(self) -> bool:
        """
        Check if the register's value changed since last navigation or command
        
        :return: true if changed
        :rtype: bool
        """

    def isFavorite(self) -> bool:
        """
        Check if this register is one of the user's favorites
        
        :return: true if favorite
        :rtype: bool
        """

    def isKnown(self) -> bool:
        """
        Check if the register's value is (completely) known
        
        :return: true if known
        :rtype: bool
        """

    def isRepresentationEditable(self) -> bool:
        """
        Check if the register's value can be set via its data type's representation
        
        :return: true if the representation cell is editable
        :rtype: bool
        """

    def isValueEditable(self) -> bool:
        """
        Check if the register can be edited
        
        :return: true if editable
        :rtype: bool
        """

    def setDataType(self, dataType: ghidra.program.model.data.DataType):
        """
        Assign a data type to the register
         
         
        
        This is memorized in the trace for the current and future snaps
        
        :param ghidra.program.model.data.DataType dataType: the data type
        """

    def setFavorite(self, favorite: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this register is one of the user's favorites
         
         
        
        Note: Favorites are memorized on a per-compiler-spec (ABI, almost) basis.
        
        :param jpype.JBoolean or bool favorite: true if favorite
        """

    def setRepresentation(self, representation: typing.Union[java.lang.String, str]):
        """
        Set the value of the register as represented by its data type
        
        :param java.lang.String or str representation: the value to set
        """

    def setValue(self, value: java.math.BigInteger):
        """
        Attempt to set the register's value
         
         
        
        The edit will be directed according to the tool's current control mode. See
        :meth:`DebuggerControlService.getCurrentMode(Trace) <DebuggerControlService.getCurrentMode>`
        
        :param java.math.BigInteger value: the value
        """

    @property
    def representationEditable(self) -> jpype.JBoolean:
        ...

    @property
    def data(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType):
        ...

    @property
    def valueEditable(self) -> jpype.JBoolean:
        ...

    @property
    def representation(self) -> java.lang.String:
        ...

    @representation.setter
    def representation(self, value: java.lang.String):
        ...

    @property
    def number(self) -> jpype.JInt:
        ...

    @property
    def current(self) -> ghidra.debug.api.tracemgr.DebuggerCoordinates:
        ...

    @property
    def known(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def favorite(self) -> jpype.JBoolean:
        ...

    @favorite.setter
    def favorite(self, value: jpype.JBoolean):
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...

    @value.setter
    def value(self, value: java.math.BigInteger):
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class DebuggerRegisterColumnFactory(ghidra.util.classfinder.ExtensionPoint):
    """
    A factory for adding a custom column to the Registers table
     
     
    
    All discovered factories' columns are automatically added as hidden columns to the Registers
    table.
    """

    class_: typing.ClassVar[java.lang.Class]

    def create(self) -> docking.widgets.table.DynamicTableColumn[RegisterRow, typing.Any, typing.Any]:
        """
        Create the column
        
        :return: the column
        :rtype: docking.widgets.table.DynamicTableColumn[RegisterRow, typing.Any, typing.Any]
        """


class DebuggerRegisterActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: DebuggerRegistersProvider, selected: RegisterRow, source: docking.widgets.table.GTable):
        ...

    def getSelected(self) -> RegisterRow:
        ...

    @property
    def selected(self) -> RegisterRow:
        ...



__all__ = ["DebuggerRegistersProvider", "DebuggerAvailableRegistersActionContext", "AvailableRegisterRow", "DebuggerAvailableRegistersDialog", "DebuggerRegistersPlugin", "RegisterRow", "DebuggerRegisterColumnFactory", "DebuggerRegisterActionContext"]
