from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.tree
import ghidra.app.plugin
import ghidra.app.util.viewer.field
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.table
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class RegisterTreeGroupNode(SearchableRegisterTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str]):
        ...

    def addRegister(self, register: ghidra.program.model.lang.Register):
        ...


@typing.type_check_only
class RegisterValueRange(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, range: ghidra.program.model.address.AddressRange, value: java.math.BigInteger, isDefault: typing.Union[jpype.JBoolean, bool]):
        ...

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getValue(self) -> java.math.BigInteger:
        ...

    def isDefault(self) -> bool:
        ...

    def setEndAddress(self, maxAddress: ghidra.program.model.address.Address):
        ...

    @property
    def default(self) -> jpype.JBoolean:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...

    @endAddress.setter
    def endAddress(self, value: ghidra.program.model.address.Address):
        ...


class RegisterPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Shows the registers available in a program along with any values that are set.
    """

    @typing.type_check_only
    class RegisterTransitionFieldMouseHandler(ghidra.app.util.viewer.field.FieldMouseHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class RegisterTreeNode(SearchableRegisterTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, register: ghidra.program.model.lang.Register):
        ...

    def getRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class RegisterTree(docking.widgets.tree.GTree):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def selectRegister(self, register: ghidra.program.model.lang.Register):
        ...

    def updateFilterList(self):
        ...


class RegisterManagerProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class MyDomainObjectListener(ghidra.framework.model.DomainObjectListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getSelectedRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def selectRegister(self, register: ghidra.program.model.lang.Register):
        ...

    def setLocation(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...

    @property
    def selectedRegister(self) -> ghidra.program.model.lang.Register:
        ...


class SetRegisterValueDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def getRegisterValue(self) -> java.math.BigInteger:
        ...

    def getSelectRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def selectRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def registerValue(self) -> java.math.BigInteger:
        ...


@typing.type_check_only
class RegisterTreeRootNode(SearchableRegisterTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def setRegisters(self, registers: jpype.JArray[ghidra.program.model.lang.Register]):
        ...


@typing.type_check_only
class EditRegisterValueDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getValue(self) -> java.math.BigInteger:
        ...

    def wasCancelled(self) -> bool:
        ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def value(self) -> java.math.BigInteger:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class RegisterWrapper(java.lang.Comparable[RegisterWrapper]):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RegisterValueRenderer(docking.widgets.table.GTableCellRenderer):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SearchableRegisterTreeNode(docking.widgets.tree.GTreeNode):

    class_: typing.ClassVar[java.lang.Class]

    def findNode(self, register: ghidra.program.model.lang.Register) -> docking.widgets.tree.GTreeNode:
        ...


@typing.type_check_only
class RegisterValueRangeComparator(java.util.Comparator[RegisterValueRange]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sortColumn: typing.Union[jpype.JInt, int]):
        ...


@typing.type_check_only
class RegisterValuesPanel(javax.swing.JPanel):

    @typing.type_check_only
    class RegisterValuesTableModel(docking.widgets.table.AbstractSortedTableModel[RegisterValueRange], ghidra.util.table.ProgramTableModel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["RegisterTreeGroupNode", "RegisterValueRange", "RegisterPlugin", "RegisterTreeNode", "RegisterTree", "RegisterManagerProvider", "SetRegisterValueDialog", "RegisterTreeRootNode", "EditRegisterValueDialog", "RegisterWrapper", "RegisterValueRenderer", "SearchableRegisterTreeNode", "RegisterValueRangeComparator", "RegisterValuesPanel"]
