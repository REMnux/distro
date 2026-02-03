from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.table
import ghidra.app.cmd.memory
import ghidra.app.plugin
import ghidra.app.plugin.core.misc
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.table
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing.event # type: ignore


class UninitializedBlockCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, block: ghidra.program.model.mem.MemoryBlock):
        ...


class MoveBlockDialog(docking.DialogComponentProvider, ghidra.app.cmd.memory.MoveBlockListener):
    """
    Dialog that uses a model to validate the fields for moving a block of memory.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemoryMapModel(docking.widgets.table.AbstractSortedTableModel[ghidra.program.model.mem.MemoryBlock], ghidra.util.table.ProgramTableModel):
    """
    Table Model for a Table where each entry represents a MemoryBlock from a Program's Memory.
    """

    @typing.type_check_only
    class MemoryMapComparator(java.util.Comparator[ghidra.program.model.mem.MemoryBlock]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, sortColumn: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getBlockAt(self, rowIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.mem.MemoryBlock:
        ...

    @property
    def blockAt(self) -> ghidra.program.model.mem.MemoryBlock:
        ...


@typing.type_check_only
class AddBlockDialog(docking.DialogComponentProvider, javax.swing.event.ChangeListener):
    """
    ``AddBlockDialog`` manages the dialog for adding and
    editing MemoryBlocks.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class AddBlockModel(java.lang.Object):
    """
    Model to manage adding a memory block.
    """

    @typing.type_check_only
    class InitializedType(java.lang.Enum[AddBlockModel.InitializedType]):

        class_: typing.ClassVar[java.lang.Class]
        UNINITIALIZED: typing.Final[AddBlockModel.InitializedType]
        INITIALIZED_FROM_VALUE: typing.Final[AddBlockModel.InitializedType]
        INITIALIZED_FROM_FILE_BYTES: typing.Final[AddBlockModel.InitializedType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AddBlockModel.InitializedType:
            ...

        @staticmethod
        def values() -> jpype.JArray[AddBlockModel.InitializedType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        ...


@typing.type_check_only
class MemoryMapManager(java.lang.Object):
    """
    Helper class to make changes to memory blocks.
    """

    @typing.type_check_only
    class SplitBlockCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MergeBlocksCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class MemoryMapPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    ``MemoryMapPlugin`` displays a memory map of all blocks in
    the current program's memory.  Options for Adding, Editing, and Deleting
    those memory blocks are available.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def dispose(self):
        """
        Tells a plugin that it is no longer needed.  The plugin should remove
        itself from anything that it is registered to and release any resources.
        """

    def domainObjectChanged(self, ev: ghidra.framework.model.DomainObjectChangedEvent):
        """
        This is the callback method for DomainObjectChangedEvents.
        """


@typing.type_check_only
class ExpandBlockDialog(docking.DialogComponentProvider, javax.swing.event.ChangeListener):
    """
    Dialog to expand the size of a block; uses a model to validate
    the fields and expand the block.
    """

    @typing.type_check_only
    class LengthChangeListener(javax.swing.event.ChangeListener):
        """
        Listener on the length text fields; update other fields
        according to the entered value.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressChangeListener(java.util.function.Consumer[ghidra.program.model.address.Address]):
        """
        Listener on the AddressInput field; update length field when the 
        address input field changes.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ExpandBlockDownModel(ExpandBlockModel):
    """
    Model to expand a block and extend its ending address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: tool needed for the edits
        :param ghidra.program.model.listing.Program program: affected program
        """


@typing.type_check_only
class MemoryMapProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    Provider for the memory map Component.
    """

    @typing.type_check_only
    class MouseHandler(java.awt.event.MouseAdapter):
        """
        Class to Handle Mouse events on Memory Map Table component
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class KeyHandler(java.awt.event.KeyAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MemoryMapTable(ghidra.util.table.GhidraTable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MemoryMapAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ExpandBlockModel(ghidra.framework.model.DomainObjectListener):
    """
    Base class for a model that expands a memory block.
    """

    @typing.type_check_only
    class ExpandBlockCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ImageBaseDialog(docking.DialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SetBaseCommand(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SplitBlockDialog(docking.DialogComponentProvider):
    """
    Dialog to split a memory block.
    """

    @typing.type_check_only
    class LengthChangeListener(javax.swing.event.ChangeListener):
        """
        Listener on the RegisterField inputs; update other fields when either
        of these fields change.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, source: ghidra.app.plugin.core.misc.RegisterField):
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MoveBlockModel(ghidra.framework.model.DomainObjectListener):
    """
    Model for moving a memory block; this class does validation of the new start
    and end address for the block, and starts the task to do the move.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ExpandBlockUpModel(ExpandBlockModel):
    """
    Model to manage the values for expanding a block up.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["UninitializedBlockCmd", "MoveBlockDialog", "MemoryMapModel", "AddBlockDialog", "AddBlockModel", "MemoryMapManager", "MemoryMapPlugin", "ExpandBlockDialog", "ExpandBlockDownModel", "MemoryMapProvider", "ExpandBlockModel", "ImageBaseDialog", "SetBaseCommand", "SplitBlockDialog", "MoveBlockModel", "ExpandBlockUpModel"]
