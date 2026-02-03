from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.util.bin.format.elf.relocation
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.reloc
import ghidra.util.classfinder
import ghidra.util.table
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore


class RelocationFixupCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: RelocationFixupHandler, oldImageBase: ghidra.program.model.address.Address, newImageBase: ghidra.program.model.address.Address):
        ...


class InstructionStasher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        ...

    def restore(self):
        ...


class RelocationFixupPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class Pe32RelocationFixupHandler(RelocationFixupHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ElfRelocationFixupHandler(RelocationFixupHandler):

    class_: typing.ClassVar[java.lang.Class]

    def getRelocationType(self, type: typing.Union[jpype.JInt, int]) -> ghidra.app.util.bin.format.elf.relocation.ElfRelocationType:
        """
        Get the relocation type enum value which corresponds to the specified type value.
        
        :param jpype.JInt or int type: relocation type value
        :return: relocation type enum value or null if type not found or this handler was not
        constructed with a :obj:`ElfRelocationType` enum class.  The returned value may be
        safely cast to the relocation enum class specified during handler construction.
        :rtype: ghidra.app.util.bin.format.elf.relocation.ElfRelocationType
        """

    @property
    def relocationType(self) -> ghidra.app.util.bin.format.elf.relocation.ElfRelocationType:
        ...


class RelocationTablePlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.model.DomainObjectListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class RelocationProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GenericRefernenceBaseRelocationFixupHandler(RelocationFixupHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class RelocationTableModel(ghidra.util.table.AddressBasedTableModel[RelocationTableModel.RelocationRowObject]):

    @typing.type_check_only
    class RelocationRowObject(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, r: ghidra.program.model.reloc.Relocation, relocationIndex: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class RelocationStatusColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RelocationTypeColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RelocationValueColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RelocationOriginalBytesColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RelocationCurrentBytesColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RelocationNameColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[RelocationTableModel.RelocationRowObject, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        ...


class Pe64RelocationFixupHandler(RelocationFixupHandler):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class RelocationFixupHandler(ghidra.util.classfinder.ExtensionPoint):

    class_: typing.ClassVar[java.lang.Class]

    def handlesProgram(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def process64BitRelocation(self, program: ghidra.program.model.listing.Program, relocation: ghidra.program.model.reloc.Relocation, oldImageBase: ghidra.program.model.address.Address, newImageBase: ghidra.program.model.address.Address) -> bool:
        ...

    def processRelocation(self, program: ghidra.program.model.listing.Program, relocation: ghidra.program.model.reloc.Relocation, oldImageBase: ghidra.program.model.address.Address, newImageBase: ghidra.program.model.address.Address) -> bool:
        ...


class RelocationToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[RelocationTableModel.RelocationRowObject, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["RelocationFixupCommand", "InstructionStasher", "RelocationFixupPlugin", "Pe32RelocationFixupHandler", "ElfRelocationFixupHandler", "RelocationTablePlugin", "RelocationProvider", "GenericRefernenceBaseRelocationFixupHandler", "RelocationTableModel", "Pe64RelocationFixupHandler", "RelocationFixupHandler", "RelocationToAddressTableRowMapper"]
