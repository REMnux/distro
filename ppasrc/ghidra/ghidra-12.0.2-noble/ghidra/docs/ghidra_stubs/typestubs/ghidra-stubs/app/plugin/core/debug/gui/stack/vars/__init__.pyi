from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import generic.theme
import ghidra.app.decompiler
import ghidra.app.decompiler.component.hover
import ghidra.app.plugin.core.codebrowser.hover
import ghidra.app.plugin.core.debug.stack
import ghidra.app.plugin.core.hover
import ghidra.debug.api.tracemgr
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.pcode.eval
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.memory
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


K = typing.TypeVar("K")
T = typing.TypeVar("T")
V = typing.TypeVar("V")


class VariableValueUtils(java.lang.Enum[VariableValueUtils]):
    """
    Various utilities for evaluating statically-defined variables in the context of a dynamic trace.
    """

    @typing.type_check_only
    class RequiresFrameEvaluator(ghidra.pcode.eval.AbstractVarnodeEvaluator[java.lang.Boolean]):
        """
        An "evaluator" which simply determines whether actual evaluation will require a frame for
        context
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefaultSpaceSettings(ghidra.docking.settings.Settings):
        """
        A settings that provides the given space as the default for pointers
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, delegate: ghidra.docking.settings.Settings, space: ghidra.program.model.address.AddressSpace):
            ...


    class VariableEvaluator(java.lang.Object):
        """
        A class which supports evaluating variables
        """

        @typing.type_check_only
        class ListenerForChanges(ghidra.trace.model.TraceDomainObjectListener):
            """
            A listener that invalidates the stack unwind whenever the trace's bytes change
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self):
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates):
            """
            Construct an evaluator for the given tool and coordinates
            
            :param ghidra.framework.plugintool.PluginTool tool: the tool
            :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
            """

        def dispose(self):
            """
            Dispose of this evaluator, removing its listener
            """

        def getGlobalsFakeFrame(self) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]:
            """
            Get a fake frame for global / static variables
            
            :return: the fake frame
            :rtype: ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]
            """

        def getRawRegisterValue(self, register: ghidra.program.model.lang.Register) -> ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue:
            """
            Obtain the value of a register
             
             
            
            In order to accommodate user-provided types on registers, it's preferable to obtain the
            data unit using :meth:`getRegisterUnit(Register) <.getRegisterUnit>`. Fall back to this method only if that
            one fails.
            
            :param ghidra.program.model.lang.Register register: the register
            :return: the "raw" value of the register
            :rtype: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue
            """

        def getRegisterUnit(self, register: ghidra.program.model.lang.Register) -> ghidra.trace.model.listing.TraceData:
            """
            Get the data unit for a register
             
             
            
            This accounts for memory-mapped registers.
            
            :param ghidra.program.model.lang.Register register: the register
            :return: the data unit, or null if undefined or mismatched
            :rtype: ghidra.trace.model.listing.TraceData
            """

        @typing.overload
        def getRepresentation(self, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], type: ghidra.program.model.data.DataType, settings: ghidra.docking.settings.Settings) -> str:
            """
            Get the representation of a variable's value according to a given data type
            
            :param ghidra.program.model.address.Address address: the best static address giving the location of the variable
            :param jpype.JArray[jpype.JByte] bytes: the bytes giving the variable's value
            :param ghidra.program.model.data.DataType type: the type of the variable
            :param ghidra.docking.settings.Settings settings: settings to configure the data type
            :return: the string representation, or null
            :rtype: str
            """

        @typing.overload
        def getRepresentation(self, frame: ghidra.app.plugin.core.debug.stack.UnwoundFrame[typing.Any], address: ghidra.program.model.address.Address, value: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue, type: ghidra.program.model.data.DataType) -> str:
            """
            Get the representation of a variable's value according to a given data type
            
            :param ghidra.app.plugin.core.debug.stack.UnwoundFrame[typing.Any] frame: the frame that evaluated the variable's value
            :param ghidra.program.model.address.Address address: the best static address giving the location of the variable. Note that the
                        address given by :meth:`WatchValue.address() <WatchValue.address>` is its dynamic address. The
                        static address should instead be taken from the variable's storage or a p-code
                        op's output varnode.
            :param ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue value: the value of the variable
            :param ghidra.program.model.data.DataType type: the type of the variable
            :return: the string representation, or null
            :rtype: str
            """

        def getStackFrame(self, function: ghidra.program.model.listing.Function, warnings: ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet, monitor: ghidra.util.task.TaskMonitor, required: typing.Union[jpype.JBoolean, bool]) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]:
            """
            Get the stack frame for the given function at or beyond the coordinates' frame level
            
            :param ghidra.program.model.listing.Function function: the desired function
            :param ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet warnings: a place to emit warnings
            :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
            :param jpype.JBoolean or bool required: whether to throw an exception or register a warning
            :return: the frame if found, or null
            :rtype: ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]
            """

        def invalidateCache(self):
            """
            Invalidate the stack unwind
            """

        @property
        def registerUnit(self) -> ghidra.trace.model.listing.TraceData:
            ...

        @property
        def globalsFakeFrame(self) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]:
            ...

        @property
        def rawRegisterValue(self) -> ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def collectSymbolStorage(line: ghidra.app.decompiler.ClangLine) -> ghidra.program.model.address.AddressSet:
        """
        Collect the addresses used for storage by any symbol in the given line of decompiled C code
         
         
        
        It's not the greatest, but any variable to be evaluated should only be expressed in terms of
        symbols on the same line (at least by the decompiler's definition, wrapping shouldn't count
        against us). This can be used to determine where evaluation should cease descending into
        defining p-code ops. See :meth:`requiresFrame(Program, PcodeOp, AddressSetView) <.requiresFrame>`, and
        :meth:`UnwoundFrame.evaluate(Program, PcodeOp, AddressSetView) <UnwoundFrame.evaluate>`.
        
        :param ghidra.app.decompiler.ClangLine line: the line
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def computeFrameSearchRange(coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.program.model.address.AddressRange:
        """
        Compute the address range where annotated frames would be expected in the listing
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
        :return: the range, usually from stack pointer to the end of the stack segment
        :rtype: ghidra.program.model.address.AddressRange
        """

    @staticmethod
    def containsVarnode(set: ghidra.program.model.address.AddressSetView, vn: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the given address set completely contains the given varnode
        
        :param ghidra.program.model.address.AddressSetView set: the set
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: true if completely contained
        :rtype: bool
        """

    @staticmethod
    def fabricateStorage(hVar: ghidra.program.model.pcode.HighVariable) -> ghidra.program.model.listing.VariableStorage:
        """
        Create a :obj:`VariableStorage` object for the given high variable
         
         
        
        This is not necessarily the same as the variable's symbol's storage. In fact, if the variable
        represents a field, it is likely a subset of the symbol's storage.
        
        :param ghidra.program.model.pcode.HighVariable hVar: the high variable
        :return: the storage
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    @staticmethod
    def findDeref(factory: ghidra.program.model.address.AddressFactory, vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.pcode.PcodeOp:
        """
        Find the descendant that dereferences this given varnode
         
         
        
        This searches only one hop for a :obj:`PcodeOp.LOAD` or :obj:`PcodeOp.STORE`. If it find a
        load, it simply returns it. If it find a store, it generates the inverse load and returns it.
        This latter behavior ensures we can evaluate the lval or a decompiled assignment statement.
        
        :param ghidra.program.model.address.AddressFactory factory: an address factory for generating unique varnodes
        :param ghidra.program.model.pcode.Varnode vn: the varnode for which a dereference is expected
        :return: the dereference, as a :obj:`PcodeOp.LOAD`
        :rtype: ghidra.program.model.pcode.PcodeOp
        """

    @staticmethod
    def findStackVariable(function: ghidra.program.model.listing.Function, stackAddress: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Variable:
        """
        Find the function's variable whose storage contains the given stack offset
        
        :param ghidra.program.model.listing.Function function: the function
        :param ghidra.program.model.address.Address stackAddress: the stack offset
        :return: the variable, or null
        :rtype: ghidra.program.model.listing.Variable
        """

    @staticmethod
    def findVariable(function: ghidra.program.model.listing.Function, register: ghidra.program.model.lang.Register) -> ghidra.program.model.listing.Variable:
        """
        Find the function's variable whose storage is exactly the given register
        
        :param ghidra.program.model.listing.Function function: the function
        :param ghidra.program.model.lang.Register register: the register
        :return: the variable, or null
        :rtype: ghidra.program.model.listing.Variable
        """

    @staticmethod
    def getInstanceInSymbolStorage(hVar: ghidra.program.model.pcode.HighVariable) -> ghidra.program.model.pcode.Varnode:
        """
        Find an instance that occurs in the variable's symbol's storage
         
         
        
        This goal is to find a stable location for evaluating the high variable, rather than some
        temporary register or worse unique location. If no satisfying instance is found, it defaults
        to the variable's representative instance.
        
        :param ghidra.program.model.pcode.HighVariable hVar: the high variable
        :return: the instance found
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @staticmethod
    def getProgramCounter(platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the program counter from the innermost frame of the given thread's stack
         
         
        
        This will prefer the program counter in the :obj:`TraceStackFrame`. If that's not available,
        it will use the value of the program counter register from the thread's register bank for
        frame 0.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JLong or int snap: the snapshot key
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getProgramCounterFromRegisters(platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the program counter for the given thread's innermost frame using its
        :obj:`TraceMemorySpace`, i.e., registers
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JLong or int snap: the snapshot key
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getProgramCounterFromStack(platform: ghidra.trace.model.guest.TracePlatform, thread: ghidra.trace.model.thread.TraceThread, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Get the program counter for the given thread's innermost frame using its :obj:`TraceStack`
         
         
        
        This will prefer the program counter in the :obj:`TraceStackFrame`. If that's not available,
        it will use the value of the program counter register from the thread's register bank for
        frame 0.
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform
        :param ghidra.trace.model.thread.TraceThread thread: the thread
        :param jpype.JLong or int snap: the snapshot key
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def hasFreshUnwind(tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> bool:
        """
        Check if the unwound frames annotated in the listing are "fresh"
         
         
        
        It can be difficult to tell. The heuristic we use is if the PC of the innermost frame agrees
        with the PC recorded for the current thread.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
        :return: true if the unwind appears fresh
        :rtype: bool
        """

    @staticmethod
    def locateFrame(tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, function: ghidra.program.model.listing.Function) -> ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame:
        """
        Locate an already unwound frame in the listing at the given coordinates
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool for context, especially for mappings to static programs
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates to search. Note that recursive calls are distinguished by
                    the coordinates' frame level, though unwinding starts at frame 0.
        :param ghidra.program.model.listing.Function function: the function the allocated the desired frame / call record
        :return: the frame or null
        :rtype: ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame
        
        .. seealso::
        
            | :obj:`AnalysisUnwoundFrame.applyToListing(int, TaskMonitor)`
        """

    @staticmethod
    def locateInnermost(tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates) -> ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame:
        """
        Find the innermost frame for the given coordinates
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates
        :return: the frame, or null
        :rtype: ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame
        """

    @staticmethod
    def rangeFromVarnode(vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.address.AddressRange:
        """
        Convert the given varnode to an address range
        
        :param ghidra.program.model.pcode.Varnode vn: the varnode
        :return: the address range
        :rtype: ghidra.program.model.address.AddressRange
        """

    @staticmethod
    @typing.overload
    def requiresFrame(program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, symbolStorage: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Check if evaluation of the given storage will require a frame
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.listing.VariableStorage storage: the storage to evaluate
        :param ghidra.program.model.address.AddressSetView symbolStorage: the leaves of evaluation, usually storage used by symbols in scope. See
                    :meth:`collectSymbolStorage(ClangLine) <.collectSymbolStorage>`
        :return: true if a frame is required, false otherwise
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def requiresFrame(program: ghidra.program.model.listing.Program, varnode: ghidra.program.model.pcode.Varnode, symbolStorage: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Check if evaluation of the given varnode will require a frame
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.pcode.Varnode varnode: the varnode to evaluate
        :param ghidra.program.model.address.AddressSetView symbolStorage: the leaves of evaluation, usually storage used by symbols in scope. See
                    :meth:`collectSymbolStorage(ClangLine) <.collectSymbolStorage>`
        :return: true if a frame is required, false otherwise
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def requiresFrame(program: ghidra.program.model.listing.Program, op: ghidra.program.model.pcode.PcodeOp, symbolStorage: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Check if evaluation of the given p-code op will require a frame
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.pcode.PcodeOp op: the op whose output to evaluation
        :param ghidra.program.model.address.AddressSetView symbolStorage: the leaves of evaluation, usually storage used by symbols in scope. See
                    :meth:`collectSymbolStorage(ClangLine) <.collectSymbolStorage>`
        :return: true if a frame is required, false otherwise
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> VariableValueUtils:
        ...

    @staticmethod
    def values() -> jpype.JArray[VariableValueUtils]:
        ...


class VariableValueHoverPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getHoverService(self) -> VariableValueHoverService:
        ...

    @property
    def hoverService(self) -> VariableValueHoverService:
        ...


class VariableValueTable(java.lang.Object):
    """
    A table for display in a variable value hover
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, row: VariableValueRow):
        """
        Add a row to the table
         
        
        At most one of each row type can be present. Adding a row whose type already exists will
        remove the old row of the same type.
        
        :param VariableValueRow row:
        """

    def get(self, key: VariableValueRow.RowKey) -> VariableValueRow:
        """
        Get the row of the given type
        
        :param VariableValueRow.RowKey key: the key / type
        :return: the row, or null
        :rtype: VariableValueRow
        """

    def getNumRows(self) -> int:
        """
        Count the number of rows
        
        :return: the count
        :rtype: int
        """

    def remove(self, key: VariableValueRow.RowKey):
        """
        Remove the row of the given type
        
        :param VariableValueRow.RowKey key: the key / type
        """

    def reportDetails(self):
        ...

    def toHtml(self) -> str:
        """
        Render the table as HTML for display in the GUI
         
         
        
        The rows are always ordered as in :obj:`RowKey`.
        
        :return: the HTML string
        :rtype: str
        """

    @property
    def numRows(self) -> jpype.JInt:
        ...


class VariableValueHoverService(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ghidra.app.plugin.core.codebrowser.hover.ListingHoverService, ghidra.app.decompiler.component.hover.DecompilerHoverService):

    @typing.type_check_only
    class LRUCache(java.util.LinkedHashMap[K, V], typing.Generic[K, V]):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self):
            ...

        @typing.overload
        def __init__(self, maxSize: typing.Union[jpype.JInt, int]):
            ...


    class TableFiller(java.lang.Object):

        @typing.type_check_only
        class MappedLocation(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def dynAddr(self) -> ghidra.program.model.address.Address:
                ...

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def stAddr(self) -> ghidra.program.model.address.Address:
                ...

            def stProg(self) -> ghidra.program.model.listing.Program:
                ...

            def toString(self) -> str:
                ...


        @typing.type_check_only
        class CopyCase(java.lang.Object, typing.Generic[T]):

            class_: typing.ClassVar[java.lang.Class]

            def evaluate(self, program: ghidra.program.model.listing.Program, varnode: ghidra.program.model.pcode.Varnode, symbolStorage: ghidra.program.model.address.AddressSetView) -> T:
                ...


        @typing.type_check_only
        class DefaultCase(java.lang.Object, typing.Generic[T]):

            class_: typing.ClassVar[java.lang.Class]

            def evaluate(self, program: ghidra.program.model.listing.Program, op: ghidra.program.model.pcode.PcodeOp, symbolStorage: ghidra.program.model.address.AddressSetView) -> T:
                ...


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, table: VariableValueTable, tool: ghidra.framework.plugintool.PluginTool, current: ghidra.debug.api.tracemgr.DebuggerCoordinates, eval: VariableValueUtils.VariableEvaluator, warnings: ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet):
            ...

        def fillCodeUnit(self, unit: ghidra.trace.model.listing.TraceCodeUnit, stProg: ghidra.program.model.listing.Program, stAddr: ghidra.program.model.address.Address) -> VariableValueTable:
            ...

        def fillComponent(self, token: ghidra.app.decompiler.ClangFieldToken, symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillComposite(self, hSym: ghidra.program.model.pcode.HighSymbol, hVar: ghidra.program.model.pcode.HighVariable, symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillDefinedData(self, data: ghidra.trace.model.listing.TraceData) -> VariableValueTable:
            ...

        def fillFrameOp(self, frame: ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue], program: ghidra.program.model.listing.Program, name: typing.Union[java.lang.String, str], type: ghidra.program.model.data.DataType, op: ghidra.program.model.pcode.PcodeOp, symbolStorage: ghidra.program.model.address.AddressSetView) -> VariableValueTable:
            ...

        def fillFrameStorage(self, frame: ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue], name: typing.Union[java.lang.String, str], type: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage) -> VariableValueTable:
            ...

        @typing.overload
        def fillHighVariable(self, hVar: ghidra.program.model.pcode.HighVariable, name: typing.Union[java.lang.String, str], symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        @typing.overload
        def fillHighVariable(self, hVar: ghidra.program.model.pcode.HighVariable, symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillInstruction(self, ins: ghidra.trace.model.listing.TraceInstruction) -> VariableValueTable:
            ...

        def fillMemory(self, programOrView: ghidra.program.model.listing.Program, refAddress: ghidra.program.model.address.Address) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillOperand(self, opLoc: ghidra.program.util.OperandFieldLocation, ins: ghidra.program.model.listing.Instruction) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillPcodeOp(self, function: ghidra.program.model.listing.Function, name: typing.Union[java.lang.String, str], type: ghidra.program.model.data.DataType, op: ghidra.program.model.pcode.PcodeOp, symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillReference(self, unit: ghidra.program.model.listing.CodeUnit, refAddress: ghidra.program.model.address.Address) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillRegister(self, ins: ghidra.program.model.listing.Instruction, register: ghidra.program.model.lang.Register) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillRegisterNoFrame(self, register: ghidra.program.model.lang.Register) -> VariableValueTable:
            ...

        def fillStack(self, ins: ghidra.program.model.listing.Instruction, stackAddress: ghidra.program.model.address.Address) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillStorage(self, function: ghidra.program.model.listing.Function, name: typing.Union[java.lang.String, str], type: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, symbolStorage: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillToken(self, token: ghidra.app.decompiler.ClangToken) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillUndefinedUnit(self, dynData: ghidra.trace.model.listing.TraceData, stProg: ghidra.program.model.listing.Program, stAddr: ghidra.program.model.address.Address) -> VariableValueTable:
            ...

        def fillVariable(self, variable: ghidra.program.model.listing.Variable) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
            ...

        def fillWatchValue(self, frame: ghidra.app.plugin.core.debug.stack.UnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue], address: ghidra.program.model.address.Address, type: ghidra.program.model.data.DataType, value: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue) -> VariableValueTable:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def fillVariableValueTable(self, table: VariableValueTable, programLocation: ghidra.program.util.ProgramLocation, current: ghidra.debug.api.tracemgr.DebuggerCoordinates, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, warnings: ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet) -> java.util.concurrent.CompletableFuture[VariableValueTable]:
        ...

    def traceClosed(self, trace: ghidra.trace.model.Trace):
        ...


class VariableValueRow(java.lang.Object):
    """
    A row to be displayed in a variable value hover's table
    """

    class RowKey(java.lang.Enum[VariableValueRow.RowKey]):
        """
        A key naming a given row type
         
         
        
        This ensures the rows always appear in conventional order, and that there is only one of
        each.
        """

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final[VariableValueRow.RowKey]
        FRAME: typing.Final[VariableValueRow.RowKey]
        STORAGE: typing.Final[VariableValueRow.RowKey]
        TYPE: typing.Final[VariableValueRow.RowKey]
        INSTRUCTION: typing.Final[VariableValueRow.RowKey]
        LOCATION: typing.Final[VariableValueRow.RowKey]
        BYTES: typing.Final[VariableValueRow.RowKey]
        INTEGER: typing.Final[VariableValueRow.RowKey]
        VALUE: typing.Final[VariableValueRow.RowKey]
        STATUS: typing.Final[VariableValueRow.RowKey]
        WARNINGS: typing.Final[VariableValueRow.RowKey]
        ERROR: typing.Final[VariableValueRow.RowKey]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> VariableValueRow.RowKey:
            ...

        @staticmethod
        def values() -> jpype.JArray[VariableValueRow.RowKey]:
            ...


    class NameRow(java.lang.Record, VariableValueRow):
        """
        A row for the variable's name
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class FrameRow(java.lang.Record, VariableValueRow):
        """
        A row for the frame used to compute the location and value
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, frame: ghidra.app.plugin.core.debug.stack.UnwoundFrame[typing.Any]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def frame(self) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame[typing.Any]:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class StorageRow(java.lang.Record, VariableValueRow):
        """
        A row for the variable's statically-defined storage
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, storage: ghidra.program.model.listing.VariableStorage):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromCodeUnit(unit: ghidra.program.model.listing.CodeUnit) -> VariableValueRow.StorageRow:
            ...

        def hashCode(self) -> int:
            ...

        def storage(self) -> ghidra.program.model.listing.VariableStorage:
            ...

        def toString(self) -> str:
            ...


    class TypeRow(java.lang.Record, VariableValueRow):
        """
        A row for the variable's type
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, type: ghidra.program.model.data.DataType):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ghidra.program.model.data.DataType:
            ...


    class InstructionRow(java.lang.Record, VariableValueRow):
        """
        If an operand refers to code, a row for the target instruction
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, instruction: ghidra.program.model.listing.Instruction):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def instruction(self) -> ghidra.program.model.listing.Instruction:
            ...

        def toString(self) -> str:
            ...


    class LocationRow(java.lang.Record, VariableValueRow):
        """
        A row for the variable's dynamic location
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, locString: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromCodeUnit(unit: ghidra.program.model.listing.CodeUnit) -> VariableValueRow.LocationRow:
            """
            Create a row from the given code unit
            
            :param ghidra.program.model.listing.CodeUnit unit: the unit
            :return: the row
            :rtype: VariableValueRow.LocationRow
            """

        @staticmethod
        def fromRange(range: ghidra.program.model.address.AddressRange) -> VariableValueRow.LocationRow:
            """
            Create a row from the given range
            
            :param ghidra.program.model.address.AddressRange range: the range
            :return: the row
            :rtype: VariableValueRow.LocationRow
            """

        @staticmethod
        def fromWatchValue(value: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue, language: ghidra.program.model.lang.Language) -> VariableValueRow.LocationRow:
            """
            Create a row from the given watch value
            
            :param ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue value: the value
            :param ghidra.program.model.lang.Language language: the language (for register name substitution)
            :return: the row
            :rtype: VariableValueRow.LocationRow
            """

        def hashCode(self) -> int:
            ...

        def locString(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class BytesRow(java.lang.Record, VariableValueRow):
        """
        A row to display the bytes in the variable
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, value: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue):
            """
            Create a row from a given watch value
            
            :param ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue value: the value
            """

        @typing.overload
        def __init__(self, bytes: ghidra.pcode.exec_.DebuggerPcodeUtils.PrettyBytes, state: ghidra.trace.model.memory.TraceMemoryState):
            ...

        def bytes(self) -> ghidra.pcode.exec_.DebuggerPcodeUtils.PrettyBytes:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromCodeUnit(unit: ghidra.trace.model.listing.TraceCodeUnit, snap: typing.Union[jpype.JLong, int]) -> VariableValueRow.BytesRow:
            """
            Create a row from a given code unit
            
            :param ghidra.trace.model.listing.TraceCodeUnit unit: unit
            :param jpype.JLong or int snap: the snapshot key
            :return: the row
            :rtype: VariableValueRow.BytesRow
            """

        @staticmethod
        def fromRange(platform: ghidra.trace.model.guest.TracePlatform, range: ghidra.program.model.address.AddressRange, snap: typing.Union[jpype.JLong, int]) -> VariableValueRow.BytesRow:
            """
            Create a row from a given range
            
            :param ghidra.trace.model.guest.TracePlatform platform: the platform (for trace memory and language)
            :param ghidra.program.model.address.AddressRange range: the range
            :param jpype.JLong or int snap: the snapshot key
            :return: the row
            :rtype: VariableValueRow.BytesRow
            """

        def hashCode(self) -> int:
            ...

        def state(self) -> ghidra.trace.model.memory.TraceMemoryState:
            ...

        def toString(self) -> str:
            ...


    class IntegerRow(java.lang.Record, VariableValueRow):
        """
        A row to display a variable's value as an integer in various formats
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, bytes: VariableValueRow.BytesRow):
            """
            Create a row from the given :obj:`BytesRow`
            
            :param VariableValueRow.BytesRow bytes: the bytes row
            """

        @typing.overload
        def __init__(self, value: ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue):
            """
            Create a row from the given watch value
            
            :param ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue value: the value
            """

        @typing.overload
        def __init__(self, bytes: ghidra.pcode.exec_.DebuggerPcodeUtils.PrettyBytes, state: ghidra.trace.model.memory.TraceMemoryState):
            ...

        def bytes(self) -> ghidra.pcode.exec_.DebuggerPcodeUtils.PrettyBytes:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromCodeUnit(unit: ghidra.trace.model.listing.TraceCodeUnit, snap: typing.Union[jpype.JLong, int]) -> VariableValueRow.IntegerRow:
            """
            Create a row from a given code unit
            
            :param ghidra.trace.model.listing.TraceCodeUnit unit: the unit
            :param jpype.JLong or int snap: the snapshot key
            :return: the row
            :rtype: VariableValueRow.IntegerRow
            """

        def hashCode(self) -> int:
            ...

        def state(self) -> ghidra.trace.model.memory.TraceMemoryState:
            ...

        def toString(self) -> str:
            ...


    class ValueRow(java.lang.Record, VariableValueRow):
        """
        A row to display the variable's value in its type's default representation
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: typing.Union[java.lang.String, str], state: ghidra.trace.model.memory.TraceMemoryState):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def state(self) -> ghidra.trace.model.memory.TraceMemoryState:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> str:
            ...


    class StatusRow(java.lang.Record, VariableValueRow):
        """
        A row to indicate the computation status, in case it takes a moment
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, status: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def status(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class WarningsRow(java.lang.Record, VariableValueRow):
        """
        A row to display the warnings encountered while unwinding the frame used to evaluate the
        variable
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, warnings: ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def warnings(self) -> ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet:
            ...


    class ErrorRow(java.lang.Record, VariableValueRow):
        """
        A row to display an error in case the table is incomplete
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, error: java.lang.Throwable):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def error(self) -> java.lang.Throwable:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    COLOR_ERROR: typing.Final[generic.theme.GColor]
    COLOR_STALE: typing.Final[generic.theme.GColor]

    @staticmethod
    @typing.overload
    def computeState(trace: ghidra.trace.model.Trace, space: ghidra.program.model.address.AddressSpace, range: ghidra.program.model.address.AddressRange, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.memory.TraceMemoryState:
        """
        Compute the memory state of a given range
         
         
        
        If any part of the range is not :obj:`TraceMemoryState.KNOWN` the result is
        :obj:`TraceMemoryState.UNKNOWN`.
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.program.model.address.AddressSpace space: the thread, frame level, and address space
        :param ghidra.program.model.address.AddressRange range: the address range
        :param jpype.JLong or int snap: the snapshot key
        :return: the composite state
        :rtype: ghidra.trace.model.memory.TraceMemoryState
        """

    @staticmethod
    @typing.overload
    def computeState(unit: ghidra.trace.model.listing.TraceCodeUnit, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.memory.TraceMemoryState:
        """
        Compute the memory state of a given code unit
        
        :param ghidra.trace.model.listing.TraceCodeUnit unit: the code unit
        :param jpype.JLong or int snap: the snapshot key
        :return: the composite state.
        :rtype: ghidra.trace.model.memory.TraceMemoryState
        
        .. seealso::
        
            | :obj:`.computeState(Trace, AddressSpace, AddressRange, long)`
        """

    @staticmethod
    def htmlFg(color: generic.theme.GColor, text: typing.Union[java.lang.String, str]) -> str:
        """
        Escape and style the given text in the given color
        
        :param generic.theme.GColor color: the color
        :param java.lang.String or str text: the text
        :return: the HTML-styled string
        :rtype: str
        """

    def key(self) -> VariableValueRow.RowKey:
        """
        Get the key for this row type
        
        :return: the key
        :rtype: VariableValueRow.RowKey
        """

    def keyToHtml(self) -> str:
        """
        Render the key for display in the table
        
        :return: the key as an HTML string
        :rtype: str
        """

    def keyToSimpleString(self) -> str:
        """
        Render the key for display in diagnostics
        
        :return: the key as a string
        :rtype: str
        """

    def reportDetails(self):
        ...

    @staticmethod
    def styleSimple(obj: java.lang.Object) -> str:
        """
        Perform the simplest styling of the object
         
         
        
        This merely invokes the object's :meth:`Object.toString() <Object.toString>` method and escapes its. If it's
        null, it will render "None" is the error color.
        
        :param java.lang.Object obj: the object, possibly null
        :return: the HTML-styled string
        :rtype: str
        """

    @staticmethod
    def styleState(state: ghidra.trace.model.memory.TraceMemoryState, str: typing.Union[java.lang.String, str]) -> str:
        """
        Style a given string according to the given memory state
         
         
        
        This renders stale (:obj:`TraceMemoryState.UNKNOWN`) values in the stale color, usually
        gray.
        
        :param ghidra.trace.model.memory.TraceMemoryState state: the state
        :param java.lang.String or str str: the HTML string
        :return: the HTML-styled string
        :rtype: str
        """

    def toHtml(self) -> str:
        """
        Render this complete row for display in the table
        
        :return: the row as an HTMl string
        :rtype: str
        """

    def toSimpleString(self) -> str:
        """
        Render this complete row for display in diagnostics
        
        :return: the row as a string
        :rtype: str
        """

    def valueToHtml(self) -> str:
        """
        Render the value for display in the table
        
        :return: the value as an HTML string
        :rtype: str
        """

    def valueToSimpleString(self) -> str:
        """
        Render the value for display in diagnostics
        
        :return: the value as a string
        :rtype: str
        """



__all__ = ["VariableValueUtils", "VariableValueHoverPlugin", "VariableValueTable", "VariableValueHoverService", "VariableValueRow"]
