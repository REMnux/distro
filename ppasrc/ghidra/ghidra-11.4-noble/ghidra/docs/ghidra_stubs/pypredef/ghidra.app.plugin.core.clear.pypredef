from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.context
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore


class ClearOptions(java.lang.Object):

    class ClearType(java.lang.Enum[ClearOptions.ClearType]):

        class_: typing.ClassVar[java.lang.Class]
        INSTRUCTIONS: typing.Final[ClearOptions.ClearType]
        DATA: typing.Final[ClearOptions.ClearType]
        SYMBOLS: typing.Final[ClearOptions.ClearType]
        COMMENTS: typing.Final[ClearOptions.ClearType]
        PROPERTIES: typing.Final[ClearOptions.ClearType]
        FUNCTIONS: typing.Final[ClearOptions.ClearType]
        REGISTERS: typing.Final[ClearOptions.ClearType]
        EQUATES: typing.Final[ClearOptions.ClearType]
        USER_REFERENCES: typing.Final[ClearOptions.ClearType]
        ANALYSIS_REFERENCES: typing.Final[ClearOptions.ClearType]
        IMPORT_REFERENCES: typing.Final[ClearOptions.ClearType]
        DEFAULT_REFERENCES: typing.Final[ClearOptions.ClearType]
        BOOKMARKS: typing.Final[ClearOptions.ClearType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ClearOptions.ClearType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ClearOptions.ClearType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor that will clear everything!
        """

    @typing.overload
    def __init__(self, defaultClearState: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShouldClear(self, type: ClearOptions.ClearType, shouldClear: typing.Union[jpype.JBoolean, bool]):
        ...

    def shouldClear(self, type: ClearOptions.ClearType) -> bool:
        ...


class ClearFlowDialog(docking.DialogComponentProvider):
    """
    Dialog that shows options for "Clear Flow and Repair." User can choose to clear
    symbols and data.  
    Instructions and associated functions, references, etc. are always cleared.
    Optional repair may also be selected.
    """

    class_: typing.ClassVar[java.lang.Class]

    def okCallback(self):
        """
        Gets called when the user clicks on the OK Action for the dialog.
        """

    def setProgramActionContext(self, context: ghidra.app.context.ListingActionContext):
        ...


class ClearFlowAndRepairCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    @typing.type_check_only
    class BlockVertex(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, startAddr: ghidra.program.model.address.Address, clearData: typing.Union[jpype.JBoolean, bool], clearLabels: typing.Union[jpype.JBoolean, bool], repair: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, startAddrs: ghidra.program.model.address.AddressSetView, clearData: typing.Union[jpype.JBoolean, bool], clearLabels: typing.Union[jpype.JBoolean, bool], repair: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, startAddrs: ghidra.program.model.address.AddressSetView, protectedSet: ghidra.program.model.address.AddressSetView, clearData: typing.Union[jpype.JBoolean, bool], clearLabels: typing.Union[jpype.JBoolean, bool], repair: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    @typing.overload
    def clearBadBookmarks(program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    @typing.overload
    def clearBadBookmarks(program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...


class ClearDialog(docking.DialogComponentProvider):
    """
    Dialog that shows options for "Clear All." User can choose to clear
    symbols, comments, properties, code, and functions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def okCallback(self):
        """
        Gets called when the user clicks on the OK Action for the dialog.
        """

    def setProgramActionContext(self, context: ghidra.app.context.ListingActionContext):
        ...


class ClearPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin that manages the 'clear' and 'clear with options' operations on a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ClearCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cu: ghidra.program.model.listing.CodeUnit, options: ClearOptions):
        """
        A convenience constructor to clear a single code unit.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit to clear
        :param ClearOptions options: the options used while clearing
        """

    @typing.overload
    def __init__(self, view: ghidra.program.model.address.AddressSetView, options: ClearOptions):
        """
        Clears using the given address set and options.
        
        :param ghidra.program.model.address.AddressSetView view: the addresses over which to clear
        :param ClearOptions options: the options used while clearing
        """

    @typing.overload
    def __init__(self, view: ghidra.program.model.address.AddressSetView):
        """
        Clears over the given range, **clearing only code**.  To clear other items,
        use :meth:`ClearCmd(AddressSetView,ClearOptions) <.ClearCmd>`.
        
        :param ghidra.program.model.address.AddressSetView view: the addresses over which to clear
        """



__all__ = ["ClearOptions", "ClearFlowDialog", "ClearFlowAndRepairCmd", "ClearDialog", "ClearPlugin", "ClearCmd"]
