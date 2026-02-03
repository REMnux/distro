from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.debug.api.tracemgr
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.graph
import ghidra.pcode.eval
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.block
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.trace.model.data
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


T = typing.TypeVar("T")
U = typing.TypeVar("U")


class AnalysisUnwoundFrame(AbstractUnwoundFrame[T], typing.Generic[T]):
    """
    A frame recovered from analysis of a thread's register bank and stack segment
     
     
    
    The typical pattern for invoking analysis to unwind an entire stack is to use
    :meth:`StackUnwinder.start(DebuggerCoordinates, TaskMonitor) <StackUnwinder.start>` or similar, followed by
    :meth:`unwindNext(TaskMonitor) <.unwindNext>` in a chain until the stack is exhausted or analysis fails to
    unwind a frame. It may be more convenient to use
    :meth:`StackUnwinder.frames(DebuggerCoordinates, TaskMonitor) <StackUnwinder.frames>`. Its iterator implements that
    pattern. Because unwinding can be expensive, it is recommended to cache the unwound stack when
    possible. A centralized service for stack unwinding may be added later.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyToListing(self, prevParamSize: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> ghidra.trace.model.listing.TraceData:
        """
        Apply this unwound frame to the trace's listing
         
         
        
        This performs the following, establishing some conventions for trace stack analysis:
         
        * Places a bookmark at the frame start indicating any warnings encountered while analyzing
        it.
        * Places a structure at (or near) the derived stack pointer whose fields denote the various
        stack entries: local variables, saved registers, return address, parameters. The structure
        may be placed a little after the derived stack pointer to accommodate the parameters of an
        inner stack frame. The structure data type will have the category path
        :obj:`StackUnwinder.FRAMES_PATH`. This allows follow-on analysis to identify data units
        representing unwound frames. See:meth:`isFrame(TraceData) <.isFrame>`.
        * Places a comment at the start of the frame. This is meant for human consumption, so
        follow-on analysis should not attempt to parse or otherwise interpret it. It will indicate
        the frame level (0 being the innermost), the function name, the program counter, the stack
        pointer, and the frame base pointer.
        * Places a :obj:`RefType.DATA` reference from the frame start to its own base address.
        This permits follow-on analysis to derive variable values stored on the stack. See
        :meth:`getBase(TraceData) <.getBase>` and :meth:`getValue(TraceData, VariableStorage) <.getValue>`.
        * Places a :obj:`RefType.DATA` reference from the program counter to the frame start. This
        allows follow-on analysis to determine the function for the frame. See
        :meth:`getProgramCounter(TraceData) <.getProgramCounter>` and
        :meth:`getFunction(TraceData, DebuggerStaticMappingService) <.getFunction>`.
        
         
         
        
        The resulting data unit can be retrieved from the trace database and later used to construct
        a :obj:`ListingUnwoundFrame`. If the frame structure would have length 0 it is not applied.
        
        :param jpype.JInt or int prevParamSize: the number of bytes occupied by the parameters for the next frame down.
                    See :meth:`resolveStructure(int) <.resolveStructure>`.
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the data unit for the frame structure applied, or null
        :rtype: ghidra.trace.model.listing.TraceData
        :raises CancelledException: if the monitor is cancelled
        """

    def getStackPointer(self) -> ghidra.program.model.address.Address:
        ...

    def getUnwindInfo(self) -> UnwindInfo:
        """
        Get the unwind information from the analysis used to unwind this frame
        
        :return: the information
        :rtype: UnwindInfo
        """

    def resolveStructure(self, prevParamSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.Structure:
        """
        Create or resolve the structure data type representing this frame
         
         
        
        The structure composes a variety of information: 1) The stack variables (locals and
        parameters) of the function that allocated the frame. Note that some variables may be omitted
        if the function has not allocated them or has already freed them relative to the frame's
        program counter. 2) Saved registers. Callee-saved registers will typically appear closer to
        the next frame up. Caller-saved registers, assuming Ghidra hasn't already assigned the stack
        offset to a local variable, will typically appear close to the next frame down. 3) The return
        address, if on the stack.
        
        :param jpype.JInt or int prevParamSize: the number of bytes occupied by the parameters for the next frame down.
                    Parameters are pushed by the caller, and so appear to be allocated by the caller;
                    however, the really belong to the callee, so this specifies the number of bytes to
                    "donate" to the callee's frame.
        :return: the structure, to be placed ``prevParamSize`` bytes after the frame's stack
                pointer.
        :rtype: ghidra.program.model.data.Structure
        """

    def unwindNext(self, monitor: ghidra.util.task.TaskMonitor) -> AnalysisUnwoundFrame[T]:
        """
        Unwind the next frame up
         
         
        
        Unwind the frame that would become current if the function that allocated this frame were to
        return. For example, if this frame is at level 3, ``unwindNext`` will attempt to unwind
        the frame at level 4.
         
         
        
        The program counter and stack pointer for the next frame are computed using the state
        originally given in
        :meth:`StackUnwinder.start(DebuggerCoordinates, PcodeExecutorState, TaskMonitor) <StackUnwinder.start>` and this
        frame's unwind information. The state is usually the watch-value state bound to the starting
        coordinates. The program counter is evaluated like any other variable. The stack pointer is
        computed by removing the depth of this frame. Then registers are restored and unwinding
        proceeds the same as the starting frame.
        
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the next frame up
        :rtype: AnalysisUnwoundFrame[T]
        :raises CancelledException: if the monitor is cancelled
        :raises UnwindException: if unwinding fails
        """

    @property
    def unwindInfo(self) -> UnwindInfo:
        ...

    @property
    def stackPointer(self) -> ghidra.program.model.address.Address:
        ...


class SymStateSpace(java.lang.Object):
    """
    The portion of a :obj:`SymPcodeExecutorState` associated with a specific :obj:`AddressSpace`.
    """

    @typing.type_check_only
    class SymEntry(java.lang.Record):
        """
        A symbolic entry in the state
         
         
        
        It's possible the entry becomes truncated if another entry set later would overlap. Thus, it
        is necessary to remember the original range and the effective range as well as the symbol.
        """

        class_: typing.ClassVar[java.lang.Class]

        def entRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def sym(self) -> Sym:
            ...

        def symRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        @typing.overload
        def toString(self, language: ghidra.program.model.lang.Language) -> str:
            """
            Render a human-friendly string, substituting register names for ranges where appropriate
            
            :param ghidra.program.model.lang.Language language: optional language. If omitted, no register names are substituted
            :return: the string
            :rtype: str
            """

        @typing.overload
        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ExprMapSetter(ghidra.trace.database.DBTraceUtils.AddressRangeMapSetter[java.util.Map.Entry[ghidra.program.model.address.Address, SymStateSpace.SymEntry], SymStateSpace.SymEntry]):
        """
        A setter that knows how to remove or truncate overlapping entries
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Construct a new empty space
        """

    def clear(self):
        """
        Reset this state
         
         
        
        Clears the state as if it were new. That is, it will generate fresh symbols for reads without
        existing entries.
        """

    def dump(self, prefix: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language):
        ...

    def fork(self) -> SymStateSpace:
        """
        Copy this state
        
        :return: the new state
        :rtype: SymStateSpace
        """

    def get(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], arithmetic: SymPcodeArithmetic, language: ghidra.program.model.lang.Language) -> Sym:
        """
        Get a value from this space
        
        :param ghidra.program.model.address.Address address: the address of the value
        :param jpype.JInt or int size: the size of the value
        :param SymPcodeArithmetic arithmetic: the arithmetic, in case truncation is necessary
        :param ghidra.program.model.lang.Language language: the language, for generating symbols
        :return: the symbol
        :rtype: Sym
        """

    def set(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], sym: Sym):
        """
        Set a value in this space
        
        :param ghidra.program.model.address.Address address: the address of the entry
        :param jpype.JInt or int size: the size of the entry
        :param Sym sym: the symbol
        """

    def toString(self, indent: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.Language) -> str:
        """
        Render a human-friendly string showing this state space
        
        :param java.lang.String or str indent: the indentation
        :param ghidra.program.model.lang.Language language: the language, optional, for register substitution
        :return: the string
        :rtype: str
        """


class SymPcodeExecutorState(ghidra.pcode.exec_.PcodeExecutorState[Sym]):
    """
    A symbolic state for stack unwind analysis
     
     
    
    This state can store symbols in stack, register, and unique spaces. It ignores physical memory,
    since that is not typically used as temporary storage when moving values between registers and
    stack. When an address is read that does not have an entry, the state will generate a fresh
    symbol representing that address, if applicable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct a new state for the given program
        
        :param ghidra.program.model.listing.Program program: the program under analysis
        """

    def computeAddressOfReturn(self) -> ghidra.program.model.address.Address:
        """
        Examine this state's PC for the location of the return address
         
         
        
        There are two cases:
         
        * ``PC:Register => location is PC.reg.address``
        * ``PC:Deref => location is [Stack]:PC.offset``
        
        
        :return: the address (stack offset or register) of the return address
        :rtype: ghidra.program.model.address.Address
        """

    def computeMapUsingRegisters(self) -> java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]:
        """
        Compute the map of (restored) registers
         
         
        
        Any entry of the form (reg, v:Deref) is collected as (reg, [Stack]:v.offset). Note that the
        size of the stack entry is implied by the size of the register.
        
        :return: the map from register to stack address
        :rtype: java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]
        """

    def computeMapUsingStack(self) -> java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]:
        """
        Compute a map of (saved) registers
         
         
        
        Any entry of the form (addr, v:Register) is collected as (v.register, addr). Note that the
        size of the stack entry is implied by the size of the register.
        
        :return: the map from register to address
        :rtype: java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]
        """

    def computeMaskOfReturn(self) -> int:
        """
        Examine this state's PC to determine how the return address is masked
         
         
        
        This is only applicable in cases where :meth:`computeAddressOfReturn() <.computeAddressOfReturn>` returns a non-null
        address. This is to handle architectures where the low bits indicate an ISA mode, and the
        higher bits form the actual address. Often, the sleigh specifications for these processors
        will mask off those low bits when setting the PC. If that has happened, and the symbolic
        expression stored in the PC is otherwise understood to come from the stack or a register,
        this will return that mask. Most often, this will return -1, indicating that all bits are
        relevant to the actual address. If the symbolic expression does not indicate the stack or a
        register, this still returns -1.
        
        :return: the mask, often -1
        :rtype: int
        """

    def computeStackDepth(self) -> int:
        """
        Examine this state's SP for the overall change in stack depth
         
         
        
        There are two cases:
         
        * SP:Register(reg==SP) => depth is 0
        * SP:Offset => depth is SP.offset
        
         
         
        
        If SP has any other form, the depth is unknown
        
        :return: the depth, or null if not known
        :rtype: int
        """

    def dump(self):
        ...

    def forkRegs(self) -> SymPcodeExecutorState:
        """
        Create a new state whose registers are forked from those of this state
        
        :return: this fork
        :rtype: SymPcodeExecutorState
        """


class DynamicMappingException(EvaluationException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class UnwindStackCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.Trace]):
    """
    A command to unwind as much of the stack as possible and annotate the resulting frame in the
    dynamic listing
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, where: ghidra.debug.api.tracemgr.DebuggerCoordinates):
        ...


class UnwoundFrame(java.lang.Object, typing.Generic[T]):
    """
    A frame that has been unwound through analysis or annotated in the listing
     
     
    
    An unwound frame can be obtained via :obj:`StackUnwinder` or :obj:`ListingUnwoundFrame`. The
    former is used when stack unwind analysis has not yet been applied to the current trace snapshot.
    It actually returns a :obj:`AnalysisUnwoundFrame`, which can apply the resulting analysis to the
    snapshot. The latter is used when those annotations are already present.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def evaluate(self, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, symbolStorage: ghidra.program.model.address.AddressSetView) -> T:
        """
        Evaluate the given storage, following defining p-code ops until symbol storage is reached
         
         
        
        This behaves similarly to :meth:`getValue(Program, VariableStorage) <.getValue>`, except this one will
        ascend recursively to each varnode's defining p-code op. The recursion terminates when a
        varnode is contained in the given symbol storage. The symbol storage is usually collected by
        examining the tokens on the same line, searching for ones that represent "high symbols." This
        ensures that any temporary storage used by the original program in the evaluation of, e.g., a
        field access, are not read from the current state but re-evaluated in terms of the symbols'
        current values.
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.listing.VariableStorage storage: the storage to evaluate
        :param ghidra.program.model.address.AddressSetView symbolStorage: the terminal storage, usually that of symbols
        :return: the value
        :rtype: T
        
        .. seealso::
        
            | :obj:`VariableValueUtils.collectSymbolStorage(ClangLine)`
        """

    @typing.overload
    def evaluate(self, program: ghidra.program.model.listing.Program, varnode: ghidra.program.model.pcode.Varnode, symbolStorage: ghidra.program.model.address.AddressSetView) -> T:
        """
        Evaluate the given varnode, following defining p-code ops until symbol storage is reached
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.listing.Program program: the program containing the varnode
        :param ghidra.program.model.pcode.Varnode varnode: the varnode
        :param ghidra.program.model.address.AddressSetView symbolStorage: the terminal storage, usually that of symbols
        :return: the value
        :rtype: T
        """

    @typing.overload
    def evaluate(self, program: ghidra.program.model.listing.Program, op: ghidra.program.model.pcode.PcodeOp, symbolStorage: ghidra.program.model.address.AddressSetView) -> T:
        """
        Evaluate the output for the given p-code op, ascending until symbol storage is reached
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.listing.Program program: the program containing the op
        :param ghidra.program.model.pcode.PcodeOp op: the op
        :param ghidra.program.model.address.AddressSetView symbolStorage: the terminal storage, usually that of symbols
        :return: the value
        :rtype: T
        
        .. seealso::
        
            | :obj:`.evaluate(Program, VariableStorage, AddressSetView)`
        """

    def getBasePointer(self) -> ghidra.program.model.address.Address:
        """
        Get the base pointer for this frame
         
         
        
        This is the value of the stack pointer at entry of the allocating function. Note while
        related, this is a separate thing from the "base pointer" register. Not all architectures
        offer one, and even on those that do, not all functions use it. Furthermore, a function that
        does use it may place a different value in the than we define as the base pointer. The value
        here is that recovered from an examination of stack operations from the function's entry to
        the program counter. It is designed such that varnodes with stack offsets can be located in
        this frame by adding the offset to this base pointer.
        
        :return: the frame's base pointer
        :rtype: ghidra.program.model.address.Address
        """

    def getDescription(self) -> str:
        """
        Get a description of this frame, for display purposes
        
        :return: the description
        :rtype: str
        """

    def getError(self) -> java.lang.Exception:
        """
        If the unwind is in error or incomplete, get the error explaining why.
         
         
        
        When analysis is incomplete, the frame may still be partially unwound, meaning only certain
        variables can be evaluated, and the return address may not be available. Typically, a
        partially unwound frame is the last frame that can be recovered in the stack. If the base
        pointer could not be recovered, then only register variables and static variables can be
        evaluated.
        
        :return: the error
        :rtype: java.lang.Exception
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Get the function that allocated this frame
         
         
        
        This is the function whose body contains the program counter
        
        :return: the frame's allocating function
        :rtype: ghidra.program.model.listing.Function
        """

    def getLevel(self) -> int:
        """
        Get the level of this frame, 0 being the innermost
        
        :return: the level
        :rtype: int
        """

    def getProgramCounter(self) -> ghidra.program.model.address.Address:
        """
        Get the frame's program counter
         
         
        
        If this is the innermost frame, this is the next instruction to be executed. Otherwise, this
        is the return address of the next inner frame, i.e., the instruction to be executed after
        control is returned to the function that allocated this frame.
        
        :return: the frame's program counter
        :rtype: ghidra.program.model.address.Address
        """

    def getReturnAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the frame's return address
         
         
        
        The address of the return address is determined by an examination of stack and register
        operations from the program counter to a return of the function allocating this frame. Three
        cases are known:
         
        1. The return address is on the stack. This happens for architectures where the caller must
        push the return address to the stack. It can also happen on architectures with a link
        register if the callee saves that register to the stack.
        2. The return address is in a register. This happens for architectures with a link register
        assuming the callee has not saved that register to the stack.
        3. The return address cannot be recovered. This happens when the function appears to be non
        returning, or the analysis otherwise fails to recover the return address. In this case, this
        method will throw an exception.
        
        
        :return: the return address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getValue(self, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage) -> T:
        """
        Get the value of the storage from the frame
         
         
        
        Each varnode in the storage is retrieved and concatenated together. The lower-indexed
        varnodes have higher significance -- like big endian. A varnode is retrieved from the state,
        with register accesses potentially redirected to a location where its value has been saved to
        the stack.
         
         
        
        Each varnode's value is simply retrieved from the state, in contrast to
        :meth:`evaluate(Program, VariableStorage, AddressSetView) <.evaluate>`, which ascends to varnodes'
        defining p-code ops.
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.listing.VariableStorage storage: the storage
        :return: the value
        :rtype: T
        """

    @typing.overload
    def getValue(self, variable: ghidra.program.model.listing.Variable) -> T:
        """
        Get the value of the variable from the frame
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.listing.Variable variable: the variable
        :return: the value
        :rtype: T
        
        .. seealso::
        
            | :obj:`.getValue(Program, VariableStorage)`
        """

    @typing.overload
    def getValue(self, register: ghidra.program.model.lang.Register) -> T:
        """
        Get the value of the register, possible saved elsewhere on the stack, relative to this frame
         
         
        
        **WARNING:** Never invoke this method from the Swing thread. The state could be associated
        with a live session, and this may block to retrieve live state.
        
        :param ghidra.program.model.lang.Register register: the register
        :return: the value
        :rtype: T
        """

    def getWarnings(self) -> StackUnwindWarningSet:
        """
        Get the warnings generated during analysis
        
        :return: the warnings
        :rtype: StackUnwindWarningSet
        """

    def isFake(self) -> bool:
        """
        Check if this is an actual frame
        
        :return: true if fake
        :rtype: bool
        
        .. seealso::
        
            | :obj:`FakeUnwoundFrame`
        """

    def setReturnAddress(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, address: ghidra.program.model.address.Address) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Set the return address of this frame
         
         
        
        This is typically used to set up a mechanism in pure emulation that traps execution when the
        entry function has returned. For example, to emulate a target function in isolation, a script
        could load or map the target program into a trace, initialize a thread at the target
        function's entry, allocate a stack, and "unwind" that stack. Then, it can initialize the
        function's parameters and return address. The return address is usually a fake but
        recognizable address, such as ``0xdeadbeef``. The script would then place a breakpoint at
        that address and allow the emulator to run. Once it breaks at ``0xdeadbeef``, the script
        can read the return value, if applicable.
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor for setting values
        :param ghidra.program.model.address.Address address: the desired return address
        :return: a future which completes when the necessary commands have all completed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def setValue(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, value: java.math.BigInteger) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Set the value of the given storage
         
         
        
        Register accesses may be redirected to the location where its current value is saved to the
        stack.
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor for setting values
        :param ghidra.program.model.listing.Program program: the program containing the variable storage
        :param ghidra.program.model.listing.VariableStorage storage: the storage to modify
        :param java.math.BigInteger value: the desired value
        :return: a future which completes when the necessary commands have all completed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """

    @typing.overload
    def setValue(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, variable: ghidra.program.model.listing.Variable, value: java.math.BigInteger) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Set the value of the given variable
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor for setting values
        :param ghidra.program.model.listing.Variable variable: the variable to modify
        :param java.math.BigInteger value: the desired value
        :return: a future which completes when the necessary commands have all completed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        
        .. seealso::
        
            | :obj:`.setValue(StateEditor, Program, VariableStorage, BigInteger)`
        """

    def zext(self, value: T, length: typing.Union[jpype.JInt, int]) -> T:
        """
        Match length by zero extension or truncation
         
         
        
        This is to cope with a small imperfection in field expression evaluation: Fields are
        evaluated using the high p-code from the decompiled function that yielded the expression.
        That code is likely loading the value into a register, which is likely a machine word in
        size, even if the field being accessed is smaller. Thus, the type of a token's high variable
        may disagree in size with the output varnode of the token's associated high p-code op. To
        rectify this discrepancy during evaluation, the type's size is assumed correct, and the
        output value is resized to match.
        
        :param T value: the value
        :param jpype.JInt or int length: the desired length
        :return: the extended or truncated value
        :rtype: T
        """

    @property
    def basePointer(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def level(self) -> jpype.JInt:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def warnings(self) -> StackUnwindWarningSet:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def fake(self) -> jpype.JBoolean:
        ...

    @property
    def error(self) -> java.lang.Exception:
        ...

    @property
    def value(self) -> T:
        ...

    @property
    def returnAddress(self) -> ghidra.program.model.address.Address:
        ...


class UnwindException(java.lang.RuntimeException):
    """
    An exception to indicate failed or incomplete stack uwinding
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Exception):
        ...


class StackUnwindWarningSet(java.util.Collection[StackUnwindWarning]):
    """
    A bucket of warnings
     
     
    
    This collects stack unwind warnings and then culls, and combines them for display.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Create a new empty set
        """

    @typing.overload
    def __init__(self, *warnings: StackUnwindWarning):
        """
        Create a new set with the given initial warnings
        
        :param jpype.JArray[StackUnwindWarning] warnings: the warnings
        """

    @typing.overload
    def __init__(self, warnings: collections.abc.Sequence):
        """
        Copy the given set
        
        :param collections.abc.Sequence warnings: the other set
        """

    @staticmethod
    def custom(message: typing.Union[java.lang.String, str]) -> StackUnwindWarningSet:
        ...

    def reportDetails(self):
        ...

    def summarize(self) -> java.util.List[java.lang.String]:
        ...


class FakeUnwoundFrame(AbstractUnwoundFrame[T], typing.Generic[T]):
    """
    A fake frame which can be used to evaluate variables for which an actual frame is not necessary
    or not available.
    
     
    
    This "frame" can only evaluate static / global variables. Neither register variables nor stack
    variables can be evaluated. The reason for excluding registers is because some register values
    may be saved to the stack, so the values in the bank may not be the correct value in the context
    of a given stack frame. Based on an inspection of a variable's storage, it may not be necessary
    to attempt a stack unwind to evaluate it. If that is the case, this "frame" may be used to
    evaluate it where a frame interface is expected or convenient.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, state: ghidra.pcode.exec_.PcodeExecutorState[T]):
        """
        Construct a fake "frame"
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool requesting interpretation of the frame, which provides context for
                    mapped static programs.
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates (trace, thread, snap, etc.) to examine
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the machine state, typically the watch value state for the same coordinates. It
                    is the caller's (i.e., subclass') responsibility to ensure the given state
                    corresponds to the given coordinates.
        """


@typing.type_check_only
class Sym(java.lang.Object):
    """
    A symbolic value tailored for stack unwind analysis
     
     
    
    The goals of stack unwind analysis are 1) to figure the stack depth at a particular instruction,
    2) to figure the locations of saved registers on the stack, 3) to figure the location of the
    return address, whether in a register or on the stack, and 4) to figure the change in stack depth
    from calling the function. Not surprisingly, these are the fields of :obj:`UnwindInfo`. To these
    ends, symbols may have only one of the following forms:
     
     
    * An opaque value: :obj:`OpaqueSym`, to represent expressions too complex.
    * A constant: :obj:`ConstSym`, to fold constants and use as offsets.
    * A register: :obj:`RegisterSym`, to detect saved registers and to generate stack offsets
    * A stack offset, i.e., SP + c: :obj:`StackOffsetSym`, to fold offsets, detect stack depth,
    and to generate stack dereferences
    * A dereference of a stack offset, i.e., *(SP + c): :obj:`StackDerefSym`, to detect restored
    registers and return address location
    
     
     
    
    The rules are fairly straightforward:
     
     
    * a:Opaque + b:Any => Opaque()
    * a:Const + b:Const => Const(val=a.val + b.val)
    * a:Const + b:Register(reg==SP) => Offset(offset=a.val)
    * a:Offset: + b:Const => Offset(offset=a.offset + b.val)
    * *a:Offset => Deref(offset=a.offset)
    * *a:Register(reg==SP) => Deref(offset=0)
    
     
     
    
    Some minute operations are omitted for clarity. Any other operation results in Opaque(). There is
    a small fault in that Register(reg=SP) and Offset(offset=0) represent the same thing, but with
    some extra bookkeeping, it's not too terrible. By interpreting p-code and then examining the
    symbolic machine state, simple movement of data between registers and the stack can be
    summarized.
    """

    class OpaqueSym(java.lang.Enum[Sym.OpaqueSym], Sym):
        """
        The singleton opaque symbol
        """

        class_: typing.ClassVar[java.lang.Class]
        OPAQUE: typing.Final[Sym.OpaqueSym]
        """
        Singleton instance
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Sym.OpaqueSym:
            ...

        @staticmethod
        def values() -> jpype.JArray[Sym.OpaqueSym]:
            ...


    class ConstSym(java.lang.Record, Sym):
        """
        A constant symbol
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> int:
            ...


    class RegisterSym(java.lang.Record, Sym):
        """
        A register symbol
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, register: ghidra.program.model.lang.Register, mask: typing.Union[jpype.JLong, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def mask(self) -> int:
            ...

        def register(self) -> ghidra.program.model.lang.Register:
            ...

        def toString(self) -> str:
            ...

        def withAppliedMask(self, mask: typing.Union[jpype.JLong, int]) -> Sym.RegisterSym:
            ...


    class StackOffsetSym(java.lang.Record, Sym):
        """
        A stack offset symbol
         
         
        
        This represents a value in the form SP + c, where SP is the stack pointer register and c is a
        constant.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offset: typing.Union[jpype.JLong, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def offset(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class StackDerefSym(java.lang.Record, Sym):
        """
        A stack dereference symbol
         
         
        
        This represents a dereferenced :obj:`StackOffsetSym` (or the dereferenced stack pointer
        register, in which is treated as a stack offset of 0).
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offset: typing.Union[jpype.JLong, int], mask: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def mask(self) -> int:
            ...

        def offset(self) -> int:
            ...

        def size(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def withAppliedMask(self, mask: typing.Union[jpype.JLong, int]) -> Sym.StackDerefSym:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def add(self, cSpec: ghidra.program.model.lang.CompilerSpec, in2: Sym) -> Sym:
        """
        Add this and another symbol with the given compiler for context
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        :param Sym in2: the second symbol
        :return: the resulting symbol
        :rtype: Sym
        """

    def addressIn(self, space: ghidra.program.model.address.AddressSpace, cSpec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.address.Address:
        """
        When this symbol is used as the offset in a given address space, translate it to the address
        if possible
         
         
        
        The address will be used by the state to retrieve the appropriate (symbolic) value, possibly
        generating a fresh symbol. If the address is :obj:`Address.NO_ADDRESS`, then the state will
        yield the opaque symbol. For sets, the state will store the given symbolic value at the
        address. If it is :obj:`Address.NO_ADDRESS`, then the value is ignored.
        
        :param ghidra.program.model.address.AddressSpace space: the space being dereferenced
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        :return: the address, or :obj:`Address.NO_ADDRESS`
        :rtype: ghidra.program.model.address.Address
        """

    def and_(self, cSpec: ghidra.program.model.lang.CompilerSpec, in2: Sym) -> Sym:
        """
        Logical bitwise and this and another symbol with the given compiler context
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        :param Sym in2: the second symbol
        :return: the resulting symbol
        :rtype: Sym
        """

    @staticmethod
    def constant(value: typing.Union[jpype.JLong, int]) -> Sym:
        """
        Get a constant symbol
        
        :param jpype.JLong or int value: the value
        :return: the constant (with size 8 bytes)
        :rtype: Sym
        """

    @staticmethod
    def opaque() -> Sym:
        """
        Get the opaque symbol
        
        :return: the symbol
        :rtype: Sym
        """

    def sizeOf(self, cSpec: ghidra.program.model.lang.CompilerSpec) -> int:
        """
        Get the size of this symbol with the given compiler for context
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        :return: the size in bytes
        :rtype: int
        """

    def sub(self, cSpec: ghidra.program.model.lang.CompilerSpec, in2: Sym) -> Sym:
        """
        Subtract another symbol from this with the given compiler for context
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        :param Sym in2: the second symbol
        :return: the resulting symbol
        :rtype: Sym
        """

    def twosComp(self) -> Sym:
        """
        Negate this symbol
        
        :return: the resulting symbol
        :rtype: Sym
        """


class SymPcodeExecutor(ghidra.pcode.exec_.PcodeExecutor[Sym]):
    """
    The interpreter of p-code ops in the domain of :obj:`Sym`
     
     
    
    This is used for static analysis by executing specific basic blocks. As such, it should never be
    expected to interpret a conditional jump. (TODO: This rule might be violated if a fall-through
    instruction has internal conditional branches.... To fix would require breaking the p-code down
    into basic blocks.) We also do not want it to descend into subroutines. Thus, we must treat calls
    differently. Most of the implementation of this class is to attend to function calls, especially,
    indirect calls. For direct calls, it attempts to find the function in the same program (possibly
    in its import table) and derive the resulting stack effects from the database. Failing that, it
    issues warnings and makes reasonable assumptions. For indirect calls, it attempts to decompile
    the caller and examines the call site. If the target's type is known (presumably a function
    pointer), then the stack effects are derived from the signature and its calling convention. If
    not, then it examines the inputs and output (if applicable) to derive a signature and then
    figures the stack effects. In many cases, the stack adjustment is defined solely by the compiler,
    but for the ``__stdcall`` convention prominent in 32-bit x86 binaries for Windows, the input
    parameters must also be examined.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, cSpec: ghidra.program.model.lang.CompilerSpec, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, arithmetic: SymPcodeArithmetic, state: SymPcodeExecutorState, reason: ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason, monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    @typing.overload
    def computeStackChange(function: ghidra.program.model.listing.Function, warnings: java.util.Set[StackUnwindWarning]) -> int:
        """
        Attempt to figure the stack depth change for a given function
        
        :param ghidra.program.model.listing.Function function: the function whose depth change to compute
        :param java.util.Set[StackUnwindWarning] warnings: a place to emit warnings
        :return: the depth change, i.e., change to SP
        :rtype: int
        """

    @typing.overload
    def computeStackChange(self, callee: ghidra.program.model.listing.Function) -> int:
        """
        Attempt to figure the stack depth change for a given function
        
        :param ghidra.program.model.listing.Function callee: the function being called
        :return: the depth change, i.e., change to SP
        :rtype: int
        """

    @staticmethod
    def forProgram(program: ghidra.program.model.listing.Program, state: SymPcodeExecutorState, reason: ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason, monitor: ghidra.util.task.TaskMonitor) -> SymPcodeExecutor:
        """
        Construct an executor for performing stack unwind analysis of a given program
        
        :param ghidra.program.model.listing.Program program: the program to analyze
        :param SymPcodeExecutorState state: the symbolic state
        :param ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason reason: a reason to give when reading state
        :param warnings: a place to emit warnings:param ghidra.util.task.TaskMonitor monitor: a monitor for analysis, usually decompilation
        :return: the executor
        :rtype: SymPcodeExecutor
        """


class ListingUnwoundFrame(AbstractUnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]):
    """
    A frame restored from annotations applied to the trace listing
     
     
    
    This frame operates on :obj:`WatchValue`s, which are more than sufficient for most GUI elements.
    The unwinding and display of abstract values introduced by custom emulators is yet to be
    complete.
     
     
    
    This class may become deprecated. It allowed the GUI to use existing analysis that had been
    annotated in this listing. Certainly, that feature will remain, since the annotations are human
    consumable and help make sense of the stack segment. However, when other features need stack
    frames, they may or may not pull those frames from the listing. The trouble comes when a frame
    has 0 length. This can happen when a function has not pushed anything to the stack. On
    architectures without link registers, it should only happen in contingent cases, e.g., the
    analyzer can't find an exit path from the function, and so the return address location is not
    known. However, an invocation of a leaf function on an architecture with a link register may in
    fact have a 0-length frame for its entire life. Ghidra does not cope well with 0-length
    structures, and for good reason. Thus, in most cases, it is recommended to unwind, using
    :obj:`StackUnwinder`, and cache frames for later re-use. That pattern may be encapsulated in a
    centralized service later.
    
    
    .. seealso::
    
        | :obj:`AnalysisUnwoundFrame.applyToListing(int, TaskMonitor)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, frame: ghidra.trace.model.listing.TraceData):
        """
        Recover a frame from annotations already in the trace listing
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool requesting interpretation of the frame, which provides context for
                    mapped static programs.
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates (trace, thread, snap, etc.) to examine
        :param ghidra.trace.model.listing.TraceData frame: the data unit representing the frame
        """

    def getComponentContaining(self, address: ghidra.program.model.address.Address) -> ghidra.trace.model.listing.TraceData:
        """
        Get the stack entry containing the given address
        
        :param ghidra.program.model.address.Address address: the address, must already have base applied
        :return: the component, or null
        :rtype: ghidra.trace.model.listing.TraceData
        """

    def getData(self) -> ghidra.trace.model.listing.TraceData:
        """
        Get the data unit representing this frame
        
        :return: the data unit
        :rtype: ghidra.trace.model.listing.TraceData
        """

    @staticmethod
    def isFrame(data: ghidra.trace.model.listing.TraceData) -> bool:
        """
        Check if the given data unit conventionally represents a frame
         
         
        
        This is a simple conventional check, but it should rule out accidents. It checks that the
        unit's data type belongs to the :obj:`StackUnwinder.FRAMES_PATH` category. If the user or
        something else puts data types in that category, it's likely data units using those types may
        be mistaken for frames....
        
        :param ghidra.trace.model.listing.TraceData data: the candidate frame
        :return: true if it is likely a frame
        :rtype: bool
        """

    @property
    def componentContaining(self) -> ghidra.trace.model.listing.TraceData:
        ...

    @property
    def data(self) -> ghidra.trace.model.listing.TraceData:
        ...


class EvaluationException(java.lang.RuntimeException):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...


class UnwindInfo(java.lang.Record):
    """
    Information for interpreting the current stack frame and unwinding to the next
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, depth: typing.Union[java.lang.Long, int], adjust: typing.Union[java.lang.Long, int], ofReturn: ghidra.program.model.address.Address, maskOfReturn: typing.Union[jpype.JLong, int], saved: collections.abc.Mapping, warnings: StackUnwindWarningSet, error: java.lang.Exception):
        ...

    def adjust(self) -> int:
        """
        The adjustment to the stack pointer, at function entry, to return from this function
         
         
        
        This is used to unwind the stack pointer value for the next frame.
        
        :return: the adjustment
        :rtype: int
        """

    def computeBase(self, spVal: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Compute the current frame's base address given the current (or unwound) stack pointer.
         
         
        
        This is used to retrieve variable values for the current frame.
        
        :param ghidra.program.model.address.Address spVal: the stack pointer
        :return: the base address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def computeNextPc(self, base: ghidra.program.model.address.Address, state: ghidra.pcode.exec_.PcodeExecutorState[T], pc: ghidra.program.model.lang.Register) -> T:
        """
        Compute the return address of the current frame, giving the unwound program counter of the
        next frame
         
         
        
        This is used as part of unwinding the next frame.
        
        :param T: the type of values in the state:param ghidra.program.model.address.Address base: the current frame's base pointer, as in :meth:`computeBase(Address) <.computeBase>`
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state of the next frame, whose program counter this method is computing
        :param ghidra.program.model.lang.Register pc: the program counter register, used for its size
        :return: the value of the program counter for the next frame
        :rtype: T
        
        .. seealso::
        
            | :obj:`AnalysisUnwoundFrame.unwindNext(TaskMonitor)`
        """

    @typing.overload
    def computeNextPc(self, base: ghidra.program.model.address.Address, state: ghidra.pcode.exec_.PcodeExecutorState[T], codeSpace: ghidra.program.model.address.AddressSpace, pc: ghidra.program.model.lang.Register) -> ghidra.program.model.address.Address:
        """
        Compute the return address of the current frame, giving the unwound program counter (as a
        code address) of the next frame.
         
         
        
        This is used as part of unwinding the next frame.
        
        :param T: the type of values in the state:param ghidra.program.model.address.Address base: the current frame's base pointer, as in :meth:`computeBase(Address) <.computeBase>`
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state of the next frame, whose program counter this method is computing
        :param ghidra.program.model.address.AddressSpace codeSpace: the address space where the program counter points
        :param ghidra.program.model.lang.Register pc: the program counter register, used for its size
        :return: the address of the next instruction for the next frame
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`AnalysisUnwoundFrame.unwindNext(TaskMonitor)`
        """

    def computeNextSp(self, base: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Compute the unwound stack pointer for the next frame
         
         
        
        This is used as part of unwinding the next frame.
        
        :param ghidra.program.model.address.Address base: the current frame's based pointer, as in :meth:`computeBase(Address) <.computeBase>`
        :return: the stack pointer for the next frame
        :rtype: ghidra.program.model.address.Address
        
        .. seealso::
        
            | :obj:`AnalysisUnwoundFrame.unwindNext(TaskMonitor)`
        """

    def computeParamSize(self) -> int:
        """
        Get the number of bytes in the parameter portion of the frame
         
         
        
        These are the entries on the opposite side of the base pointer from the rest of the frame. In
        fact, these are pushed onto the stack by the caller, so these slots should be "stolen" from
        the caller's frame and given to the callee's frame.
        
        :return: the total parameter size in bytes
        :rtype: int
        """

    def depth(self) -> int:
        """
        The change in the stack pointer from function entry to the given program counter
         
         
        
        This is necessary to retrieve stack variables from the current frame. By subtracting this
        from the current stack pointer, the frame's base address is computed. See
        :meth:`computeBase(Address) <.computeBase>`. The offsets of stack variables are all relative to that base
        address. See :meth:`AnalysisUnwoundFrame.getValue(Variable) <AnalysisUnwoundFrame.getValue>`.
        
        :return: the depth
        :rtype: int
        """

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def error(self) -> java.lang.Exception:
        ...

    @staticmethod
    def errorOnly(error: java.lang.Exception) -> UnwindInfo:
        """
        Construct an error-only info
        
        :param java.lang.Exception error: the error
        :return: the info containing only the error
        :rtype: UnwindInfo
        """

    def function(self) -> ghidra.program.model.listing.Function:
        """
        The function that was analyzed
        
        :return: the function
        :rtype: ghidra.program.model.listing.Function
        """

    def hashCode(self) -> int:
        ...

    def mapSavedRegisters(self, base: ghidra.program.model.address.Address, map: SavedRegisterMap):
        """
        Add register map entries for the saved registers in this frame
        
        :param ghidra.program.model.address.Address base: the current frame's base pointer, as in :meth:`computeBase(Address) <.computeBase>`
        :param SavedRegisterMap map: the register map of the stack to this point, to be modified
        """

    def maskOfReturn(self) -> int:
        """
        The mask applied to the return address
         
         
        
        This is to handle ISAs that use the low bits of addresses in jumps to indicate an ISA switch.
        Often, the code that returns from a function will apply a mask. If that is the case, this
        returns that mask. In most cases, this returns -1, which when applied as a mask has no
        effect.
         
         
        
        **NOTE**: There is currently no tracking of the ISA mode by the stack unwinder. First, the
        conventions for tracking that in the Sleigh specification varies from processor to processor.
        There is often custom-made handling of that bit programmed in Java for the emulator, but it's
        not generally accessible for static analysis. Second, for stack unwinding purposes, we use
        the statically disassembled code at the return address, anyway. That should already be of the
        correct ISA; if not, then we are already lost.
        
        :return: the mask, often -1
        :rtype: int
        """

    @typing.overload
    def ofReturn(self) -> ghidra.program.model.address.Address:
        """
        The *address of* the return address
         
         
        
        The address may be a register or a stack offset, relative to the stack pointer at function
        entry.
        
        :return: the address of the return address
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def ofReturn(self, base: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        The *address of* the return address, given a stack base
         
         
        
        The address may be a register or a stack offset, relative to the stack pointer at function
        entry, i.e., base. If it's the latter, then this will resolve it with respect to the given
        base. The result can be used to retrieve the return address from a state. See
        :meth:`computeNextPc(Address, PcodeExecutorState, Register) <.computeNextPc>`.
        
        :param ghidra.program.model.address.Address base: the stack pointer at function entry
        :return: the address of the return address
        :rtype: ghidra.program.model.address.Address
        """

    def restoreRegisters(self, base: ghidra.program.model.address.Address, state: ghidra.pcode.exec_.PcodeExecutorState[T]):
        """
        Restore saved registers in the given state
         
         
        
        This is used as part of unwinding the next frame.
        
        :param T: the type of values in the state:param ghidra.program.model.address.Address base: the current frame's base pointer, as in :meth:`computeBase(Address) <.computeBase>`.
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state to modify, usually forked from the current frame's state
        
        .. seealso::
        
            | :obj:`AnalysisUnwoundFrame.unwindNext(TaskMonitor)`
        """

    def saved(self) -> java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]:
        """
        The map of registers to stack offsets for saved registers
         
         
        
        This is not necessary until its time to unwind the next frame. The saved registers should be
        restored, then the next PC and SP computed, then the next frame unwound. See
        :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>`.
        
        :return: the map of registers to stack addresses
        :rtype: java.util.Map[ghidra.program.model.lang.Register, ghidra.program.model.address.Address]
        """

    def toString(self) -> str:
        ...

    def warnings(self) -> StackUnwindWarningSet:
        """
        The list of warnings issues during analysis
        
        :return: the warnings
        :rtype: StackUnwindWarningSet
        """


class StackUnwindWarning(java.lang.Object):
    """
    A warning issued while unwinding a stack
     
     
    
    This is designed to avoid the untamed bucket of messages that a warning set usually turns into.
    In essence, it's still a bucket of messages; however, each type is curated and has some logic for
    how it interacts with other messages and additional instances of itself.
    """

    class Combinable(java.lang.Object, typing.Generic[T]):
        """
        A warning that can be combined with other instances of itself
        """

        class_: typing.ClassVar[java.lang.Class]

        def summarize(self, all: collections.abc.Sequence) -> str:
            ...


    class NoReturnPathStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        The unwind analyzer could not find an exit path from the frame's program counter.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pc: ghidra.program.model.address.Address):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def pc(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    class OpaqueReturnPathStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        The unwind analyzer discovered at last one exit path, but none could be analyzed.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pc: ghidra.program.model.address.Address, last: java.lang.Exception):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def last(self) -> java.lang.Exception:
            ...

        def pc(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    class UnknownPurgeStackUnwindWarning(java.lang.Record, StackUnwindWarning, StackUnwindWarning.Combinable[StackUnwindWarning.UnknownPurgeStackUnwindWarning]):
        """
        While analyzing instructions, the unwind analyzer encountered a call to a function whose
        effect on the stack is unknown.
         
         
        
        The analyzer does not descend into calls or otherwise implement inter-procedural analysis.
        Instead, it relies on analysis already performed by Ghidra's other analyzers and/or the human
        user. The analyzer will assume a reasonable default.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, function: ghidra.program.model.listing.Function):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def function(self) -> ghidra.program.model.listing.Function:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class UnspecifiedConventionStackUnwindWarning(java.lang.Record, StackUnwindWarning, StackUnwindWarning.Combinable[StackUnwindWarning.UnspecifiedConventionStackUnwindWarning]):
        """
        While analyzing instructions, the unwind analyzer encountered a call to a function whose
        convention is not known.
         
         
        
        The analyzer will assume the default convention for the program's compiler.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, function: ghidra.program.model.listing.Function):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def function(self) -> ghidra.program.model.listing.Function:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class MultipleHighCallsStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        While analyzing an indirect call, using the decompiler, the unwind analyzer obtained multiple
        high :obj:`PcodeOp.CALL` or :obj:`PcodeOp.CALLIND` p-code ops.
         
         
        
        Perhaps this should be replaced by an assertion, but failing fast may not be a good approach
        for this case.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, found: java.util.List[ghidra.program.model.pcode.PcodeOpAST]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def found(self) -> java.util.List[ghidra.program.model.pcode.PcodeOpAST]:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    class NoHighCallsStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        Similar to :obj:`MultipleHighCallsStackUnwindWarning`, except no high call p-code ops.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, op: ghidra.program.model.pcode.PcodeOp):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def op(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        def toString(self) -> str:
            ...


    class UnexpectedTargetTypeStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        While analyzing an indirect call, the target's type was not a function pointer.
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


    class NoHighVariableFromTargetPointerTypeUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        While analyzing an indirect call, couldn't get the function signature because its input
        doesn't have a high variable.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, vn: ghidra.program.model.pcode.VarnodeAST):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def vn(self) -> ghidra.program.model.pcode.VarnodeAST:
            ...


    class CouldNotRecoverSignatureStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        While analyzing an indirect call, the signature could not be derived from call-site context.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, op: ghidra.program.model.pcode.PcodeOpAST):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def op(self) -> ghidra.program.model.pcode.PcodeOpAST:
            ...

        def toString(self) -> str:
            ...


    class CustomStackUnwindWarning(java.lang.Record, StackUnwindWarning):
        """
        A custom warning, either because a specific type is too onerous, or because the message was
        deserialized and the specific type and info cannot be recovered.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def message(self) -> str:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getMessage(self) -> str:
        """
        Get the message for display
        
        :return: the message
        :rtype: str
        """

    def moots(self, other: StackUnwindWarning) -> bool:
        """
        Check if the given warning can be omitted on account of this warning
         
         
        
        Usually, the unwinder should be careful not to emit unnecessary warnings, but at times that
        can be difficult, and its proper implementation may complicate the actual unwind logic. This
        allows the unnecessary warning to be removed afterward.
        
        :param StackUnwindWarning other: the other warning
        :return: true if this warning deems the other unnecessary
        :rtype: bool
        """

    def reportDetails(self):
        """
        For diagnostics, report any error details indicated by this warning, usually via :obj:`Msg`.
        """

    @property
    def message(self) -> java.lang.String:
        ...


@typing.type_check_only
class FrameStructureBuilder(java.lang.Object):
    """
    The implementation of :meth:`AnalysisUnwoundFrame.generateStructure(int) <AnalysisUnwoundFrame.generateStructure>`
    """

    @typing.type_check_only
    class FrameField(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def address(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def length(self) -> int:
            ...

        def name(self) -> str:
            ...

        def scopeStart(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> ghidra.program.model.data.DataType:
            ...


    class_: typing.ClassVar[java.lang.Class]
    RETURN_ADDRESS_FIELD_NAME: typing.Final = "return_address"
    SAVED_REGISTER_FIELD_PREFIX: typing.Final = "saved_"

    def build(self, path: ghidra.program.model.data.CategoryPath, name: typing.Union[java.lang.String, str], dtm: ghidra.trace.model.data.TraceBasedDataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Build the resulting structure
        
        :param ghidra.program.model.data.CategoryPath path: the category path for the new structure
        :param java.lang.String or str name: the name of the new structure
        :param ghidra.trace.model.data.TraceBasedDataTypeManager dtm: the data type manager for the structure
        :return: the new structure
        :rtype: ghidra.program.model.data.Structure
        """


class AbstractUnwoundFrame(UnwoundFrame[T], typing.Generic[T]):
    """
    An abstract implementation of :obj:`UnwoundFrame`
    
     
    
    This generally contains all the methods for interpreting and retrieving higher-level variables
    once the frame context is known. It doesn't contain the mechanisms for creating or reading
    annotations.
    """

    @typing.type_check_only
    class ArithmeticFrameVarnodeEvaluator(ghidra.pcode.eval.ArithmeticVarnodeEvaluator[U], typing.Generic[U]):
        """
        A class which can evaluate high p-code varnodes in the context of a stack frame using a
        p-code arithmetic
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[U]):
            ...


    @typing.type_check_only
    class AbstractFrameVarnodeEvaluator(ghidra.pcode.eval.AbstractVarnodeEvaluator[U], typing.Generic[U]):
        """
        A class which can evaluate high p-code varnodes in the context of a stack frame
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FrameVarnodeEvaluator(AbstractUnwoundFrame.ArithmeticFrameVarnodeEvaluator[U], typing.Generic[U]):
        """
        A frame evaluator which descends to symbol storage
         
         
        
        This ensure that if a register is used as a temporary value in an varnode AST, that
        evaluation proceeds all the way to the "source" symbols.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[U], symbolStorage: ghidra.program.model.address.AddressSetView):
            """
            Construct an evaluator with the given arithmetic and symbol storage
             
             
            
            Varnodes contained completely in symbol storage are presumed to be the inputs of the
            evaluation. All other varnodes are evaluated by examining their defining p-code op. It is
            an error to include any unique space in symbol storage.
            
            :param ghidra.pcode.exec_.PcodeArithmetic[U] arithmetic: the arithmetic for evaluating p-code ops
            :param ghidra.program.model.address.AddressSetView symbolStorage: the address ranges to regard as input, i.e., the leaves of evalution
            """


    @typing.type_check_only
    class FrameVarnodeValueGetter(AbstractUnwoundFrame.ArithmeticFrameVarnodeEvaluator[U], typing.Generic[U]):
        """
        A frame "evaluator" which merely gets values
        
         
        
        This evaluator never descends to defining p-code ops. It is an error to ask it for the value
        of unique varnodes. With some creativity, this can also be used as a varnode visitor to set
        values.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, arithmetic: ghidra.pcode.exec_.PcodeArithmetic[U]):
            ...


    @typing.type_check_only
    class FrameVarnodeValueSetter(AbstractUnwoundFrame.AbstractFrameVarnodeEvaluator[U], typing.Generic[U]):
        """
        A frame "evaluator" which actually sets values
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, state: ghidra.pcode.exec_.PcodeExecutorState[T]):
        """
        Construct an unwound frame
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool requesting interpretation of the frame, which provides context for
                    mapped static programs.
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the coordinates (trace, thread, snap, etc.) to examine
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the machine state, typically the watch value state for the same coordinates. It
                    is the caller's (i.e., subclass') responsibility to ensure the given state
                    corresponds to the given coordinates.
        """


@typing.type_check_only
class SymPcodeArithmetic(ghidra.pcode.exec_.PcodeArithmetic[Sym]):
    """
    The interpretation of arithmetic p-code ops in the domain of :obj:`Sym` for a specific compiler
    specification
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cSpec: ghidra.program.model.lang.CompilerSpec):
        """
        Construct the arithmetic
        
        :param ghidra.program.model.lang.CompilerSpec cSpec: the compiler specification
        """


class UnwindAnalysis(java.lang.Object):
    """
    A class for analyzing a given program's functions as a means of unwinding their stack frames in
    traces, possibly for live debug sessions.
    
    
    .. seealso::
    
        | :obj:`StackUnwinder`
    """

    @typing.type_check_only
    class BlockGraph(ghidra.graph.GImplicitDirectedGraph[UnwindAnalysis.BlockVertex, UnwindAnalysis.BlockEdge]):
        """
        A graph used for finding execution paths from function entry through the program counter to a
        return.
         
         
        
        This just wraps :obj:`UnwindAnalysis.blockModel` in a :obj:`GImplicitDirectedGraph`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, monitor: ghidra.util.task.TaskMonitor):
            ...


    @typing.type_check_only
    class BlockVertex(java.lang.Record):
        """
        Wrap a :obj:`CodeBlock`
        """

        class_: typing.ClassVar[java.lang.Class]

        def block(self) -> ghidra.program.model.block.CodeBlock:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class BlockEdge(java.lang.Record, ghidra.graph.GEdge[UnwindAnalysis.BlockVertex]):
        """
        Wrap a :obj:`CodeBlockReference`
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def ref(self) -> ghidra.program.model.block.CodeBlockReference:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class AnalysisForPC(java.lang.Object):
        """
        The analysis surrounding a single frame for a given program counter, i.e., instruction
        address
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, pc: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
            """
            Begin analysis for unwinding a frame, knowing only the program counter for that frame
             
             
            
            This will look up the function containing the program counter. If there's isn't one, then
            this analysis cannot proceed.
            
            :param ghidra.program.model.address.Address pc: the program counter
            :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
            :raises CancelledException: if the monitor cancels the analysis
            """

        def computeUnwindInfo(self) -> UnwindInfo:
            """
            Compute the unwinding information for a frame presumably produced by executing the
            current function up to but excluding the program counter
             
             
            
            The goal is to compute a base pointer for the current frame so that the values of stack
            variables can be retrieved from a dynamic trace, as well as enough information to unwind
            and achieve the same for the next frame up on the stack. That is, the frame of the
            function that called the current function. We'll also need to figure out what registers
            were saved where on the stack so that the values of register variables can be retrieved
            from a dynamic trace. For architectures with a link register, register restoration is
            necessary to unwind the next frame, since that register holds its program counter.
            Ideally, this unwinding can be applied iteratively, until we reach the process' entry
            point.
             
             
            
            The analytic strategy is fairly straightforward and generalized, though not universally
            applicable. It employs a somewhat rudimentary symbolic interpretation. A symbol can be a
            constant, a register's initial value at function entry, a stack offset relative to the
            stack pointer at function entry, a dereferenced stack offset, or an opaque value. See
            :obj:`Sym`.
             
             
            1. Interpret the instructions along the shortest path from function entry to the program
            counter.
            2. Examine the symbol in the stack pointer register. It should be a stack offset. That
            offset is the "stack depth." See:meth:`UnwindInfo.depth() <UnwindInfo.depth>`,
            :meth:`UnwindInfo.computeBase(Address) <UnwindInfo.computeBase>`, and
            :meth:`SymPcodeExecutorState.computeStackDepth() <SymPcodeExecutorState.computeStackDepth>`.
            3. Search the stack for register symbols, creating an offset-register map. A subset of
            these are the saved registers on the stack. See:obj:`UnwindInfo.saved` and
            :meth:`SymPcodeExecutorState.computeMapUsingStack() <SymPcodeExecutorState.computeMapUsingStack>`.
            4. Reset the stack state. (This implies stack dereferences from further interpretation
            refer to their values at the program counter rather than function entry.) See
            :meth:`SymPcodeExecutorState.forkRegs() <SymPcodeExecutorState.forkRegs>`.
            5. Interpret the instructions along the shortest path from the program counter to a
            function return.
            6. Examine the symbol in the program counter register. This gives the location (register
            or stack offset) of the return address. This strategy should work whether or not a link
            register is involved. See:meth:`SymPcodeExecutorState.computeAddressOfReturn() <SymPcodeExecutorState.computeAddressOfReturn>`.
            7. Examine the symbol in the stack pointer register, again. It should be a stack offset.
            That offset is the "stack adjustment." See:meth:`UnwindInfo.adjust() <UnwindInfo.adjust>`,
            :meth:`UnwindInfo.computeNextSp(Address) <UnwindInfo.computeNextSp>`, and
            :meth:`SymPcodeExecutorState.computeStackDepth() <SymPcodeExecutorState.computeStackDepth>`.
            8. Search the registers for stack dereference symbols, creating an offset-register map.
            This intersected with the same from entry to program counter is the saved registers map.
            See:meth:`UnwindInfo.saved() <UnwindInfo.saved>`,
            :meth:`UnwindInfo.mapSavedRegisters(Address, SavedRegisterMap) <UnwindInfo.mapSavedRegisters>`, and
            :meth:`SymPcodeExecutorState.computeMapUsingRegisters() <SymPcodeExecutorState.computeMapUsingRegisters>`.
            
             
             
            
            This strategy does make some assumptions:
             
            * The function returns.
            * For every edge in the basic block graph, the stack depth at the end of its source
            block is equal to the stack depth at the start of its destination block.
            * The function follows a "sane" convention. While it doesn't have to be any particular
            convention, it does need to restore its saved registers, and those registers should be
            saved to the stack in a straightforward manner.
            
            
            :return: the unwind information
            :rtype: UnwindInfo
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executeBlock(self, exec_: SymPcodeExecutor, block: ghidra.program.model.block.CodeBlock):
            """
            Execute the instructions in the given block
            
            :param SymPcodeExecutor exec: the executor
            :param ghidra.program.model.block.CodeBlock block: the block whose instructions to execute
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executeBlockFrom(self, exec_: SymPcodeExecutor, block: ghidra.program.model.block.CodeBlock, from_: ghidra.program.model.address.Address):
            """
            Execute the instructions in the given block starting at the given address
             
             
            
            Instructions preceding the given address are omitted.
            
            :param SymPcodeExecutor exec: the executor
            :param ghidra.program.model.block.CodeBlock block: the block whose instructions to execute
            :param ghidra.program.model.address.Address from: the starting address, usually the program counter
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executeBlockTo(self, exec_: SymPcodeExecutor, block: ghidra.program.model.block.CodeBlock, to: ghidra.program.model.address.Address):
            """
            Execute the instructions in the given block preceding the given address
             
             
            
            The instruction at ``to`` is omitted.
            
            :param SymPcodeExecutor exec: the executor
            :param ghidra.program.model.block.CodeBlock block: the block whose instructions to execute
            :param ghidra.program.model.address.Address to: the ending address, usually the program counter
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executeFromPc(self, state: SymPcodeExecutorState, from_: java.util.Deque[UnwindAnalysis.BlockEdge]) -> SymPcodeExecutorState:
            """
            Finish execution from the program counter to a function return, using the given path
             
             
            
            This returns the same (but mutated) state as passed to it. The state should be forked
            from the result of :meth:`executeToPc(Deque) <.executeToPc>`, but resetting the stack portion.
            
            :param SymPcodeExecutorState state: the state, whose registers are forked from the result of
                        :meth:`executeToPc(Deque) <.executeToPc>`.
            :param java.util.Deque[UnwindAnalysis.BlockEdge] from: the path from the program counter to a return
            :return: the resulting state
            :rtype: SymPcodeExecutorState
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executePathFrom(self, exec_: SymPcodeExecutor, from_: java.util.Deque[UnwindAnalysis.BlockEdge]):
            """
            Execute the instructions along the given path from a source block, omitting the initial
            source block.
             
             
            
            The given path us usually from the block containing the program counter to a function
            return. The initial source is omitted, since it should only be partially executed, i.e.,
            using :meth:`executeBlockFrom(SymPcodeExecutor, CodeBlock, Address) <.executeBlockFrom>`.
            
            :param SymPcodeExecutor exec: the executor
            :param java.util.Deque[UnwindAnalysis.BlockEdge] from: the path from the program counter
            :raises CancelledException: if the monitor cancels the analysis
            
            .. seealso::
            
                | :obj:`.executeFromPc(SymPcodeExecutorState, Deque)`
            """

        def executePathTo(self, exec_: SymPcodeExecutor, to: java.util.Deque[UnwindAnalysis.BlockEdge]):
            """
            Execute the instructions along the given path to a destination block, omitting the final
            destination block.
             
             
            
            The given path is usually from the function entry to the block containing the program
            counter. The final block is omitted, since it should only be partially executed, i.e.,
            using :meth:`executeBlockTo(SymPcodeExecutor, CodeBlock, Address) <.executeBlockTo>`.
            
            :param SymPcodeExecutor exec: the executor
            :param java.util.Deque[UnwindAnalysis.BlockEdge] to: the path to the program counter
            :raises CancelledException: if the monitor cancels the analysis
            
            .. seealso::
            
                | :obj:`.executeToPc(Deque)`
            """

        def executeSet(self, exec_: SymPcodeExecutor, set: ghidra.program.model.address.AddressSetView):
            """
            Execute the instructions, ordered by address, in the given address set
            
            :param SymPcodeExecutor exec: the executor
            :param ghidra.program.model.address.AddressSetView set: the address set indicating the instructions to execute
            :raises CancelledException: if the monitor cancels the analysis
            """

        def executeToPc(self, to: java.util.Deque[UnwindAnalysis.BlockEdge]) -> SymPcodeExecutorState:
            """
            Execute the instructions from entry to the program counter, using the given path
             
             
            
            This constructs a new symbolic state for stack analysis, performs the execution, and
            returns the state. The state can then be analyzed before finishing execution to a
            function return and analyzing it again.
            
            :param java.util.Deque[UnwindAnalysis.BlockEdge] to: the path from entry to the program counter
            :return: the resulting state
            :rtype: SymPcodeExecutorState
            :raises CancelledException: if the monitor cancels the analysis
            """

        def getEntryPaths(self) -> java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]:
            """
            Compute the shortest path(s) from function entry to the program counter
            
            :return: the paths. There's usually only one
            :rtype: java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]
            :raises CancelledException: if the monitor cancels the analysis
            """

        def getExitsPaths(self) -> java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]:
            """
            Compute the shortest path(s) from the program counter to a function return
             
             
            
            Because the shortest-path API does not readily permit the searching for the shortest path
            from one vertex to many vertices, we instead search for the shortest path from the
            program counter to each of the found function returns, collect all the resulting paths,
            and sort. Still, usually only the first (shortest of all) is needed.
            
            :return: the paths sorted shortest first
            :rtype: java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]
            :raises CancelledException: if the monitor cancels the analysis
            """

        def getReturnBlocks(self) -> java.util.Collection[UnwindAnalysis.BlockVertex]:
            """
            Find terminating blocks that return from the function
             
             
            
            If there are none, then the function is presumed non-returning. Analysis will not be
            complete.
             
             
            
            For non-returning functions, we can still use the entry path. From limited
            experimentation, it seems the extra saved-register entries are not problematic. One case
            is register parameters that the function saves to the stack for its own sake. While
            restoring those would technically be incorrect, it doesn't seem problematic to do so.
            This doesn't help us compute :obj:`UnwindInfo.adjust`, but that might just be
            :meth:`PrototypeModel.getExtrapop() <PrototypeModel.getExtrapop>`....
            
            :return: the blocks
            :rtype: java.util.Collection[UnwindAnalysis.BlockVertex]
            :raises CancelledException: if the monitor cancels the analysis
            """

        @property
        def entryPaths(self) -> java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]:
            ...

        @property
        def exitsPaths(self) -> java.util.Collection[java.util.Deque[UnwindAnalysis.BlockEdge]]:
            ...

        @property
        def returnBlocks(self) -> java.util.Collection[UnwindAnalysis.BlockVertex]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Prepare analysis on the given program
        
        :param ghidra.program.model.listing.Program program: the program
        """

    def computeUnwindInfo(self, pc: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> UnwindInfo:
        """
        Compute the unwind information for the given program counter
        
        :param ghidra.program.model.address.Address pc: the program counter
        :param ghidra.util.task.TaskMonitor monitor: a monitor for progress and cancellation
        :return: the unwind information
        :rtype: UnwindInfo
        :raises CancelledException: if the monitor cancels the analysis
        """


class StackUnwinder(java.lang.Object):
    """
    A mechanism for unwinding the stack or parts of it
     
     
    
    It can start at any frame for which the program counter and stack pointer are known. The choice
    of starting frame is informed by some tradeoffs. For making sense of a specific frame, it might
    be best to start at the nearest frame with confidently recorded PC and SP values. This will
    ensure there is little room for error unwinding from the known frame to the desired frame. For
    retrieving variable values, esp. variables stored in registers, it might be best to start at the
    innermost frame, unless all registers in a nearer frame are confidently recorded. The registers
    in frame 0 are typically recorded with highest confidence. This will ensure that all saved
    register values are properly restored from the stack into the desired frame.
     
     
    
    The usage pattern is typically:
     
    ``StackUnwinder unwinder = new StackUnwinder(tool, coordinates.getPlatform());for (AnalysisUnwoundFrame<WatchValue> frame : unwinder.frames(coordinates.frame(0), monitor)) {    // check and/or cache the frame}``
     
     
    
    Typically, a frame is sought either by its level or by its function. Once found, several
    operations can be performed with it, including applying annotations to the listing for the stack
    segment (see :meth:`AnalysisUnwoundFrame.applyToListing(int, TaskMonitor) <AnalysisUnwoundFrame.applyToListing>`) and computing values
    of variables (see :obj:`UnwoundFrame`.) The iterator unwinds each frame lazily. If the iterator
    stops sooner than expected, consider using :meth:`start(DebuggerCoordinates, TaskMonitor) <.start>` and
    :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>` directly to get better diagnostics.
    """

    @typing.type_check_only
    class StaticAndUnwind(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def info(self) -> UnwindInfo:
            ...

        def staticPc(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    FRAMES_PATH: typing.Final[ghidra.program.model.data.CategoryPath]
    PC_OP_INDEX: typing.Final = -1
    BASE_OP_INDEX: typing.Final = 0

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, platform: ghidra.trace.model.guest.TracePlatform):
        """
        Construct an unwinder
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool with applicable modules opened as programs
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform (for registers, spaces, and stack conventions)
        """

    def computeUnwindInfo(self, snap: typing.Union[jpype.JLong, int], level: typing.Union[jpype.JInt, int], pcVal: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> StackUnwinder.StaticAndUnwind:
        """
        Compute the unwind information for the given program counter and context
         
         
        
        For the most part, this just translates the dynamic program counter to a static program
        address and then invokes :meth:`UnwindAnalysis.computeUnwindInfo(Address, TaskMonitor) <UnwindAnalysis.computeUnwindInfo>`.
        
        :param jpype.JLong or int snap: the snapshot key (used for mapping the program counter to a program database)
        :param jpype.JInt or int level: the frame level, used only for error messages
        :param ghidra.program.model.address.Address pcVal: the program counter (dynamic)
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the unwind info, possibly incomplete
        :rtype: StackUnwinder.StaticAndUnwind
        :raises CancelledException: if the monitor is cancelled
        """

    @typing.overload
    def frames(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, state: ghidra.pcode.exec_.PcodeExecutorState[T], monitor: ghidra.util.task.TaskMonitor) -> java.lang.Iterable[AnalysisUnwoundFrame[T]]:
        """
        An iterable wrapper for :meth:`start(DebuggerCoordinates, PcodeExecutorState, TaskMonitor) <.start>`
        and :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>`
        
        :param T: the type of values in the state:param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the starting coordinates
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :return: the iterable over unwound frames
        :rtype: java.lang.Iterable[AnalysisUnwoundFrame[T]]
        """

    @typing.overload
    def frames(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, monitor: ghidra.util.task.TaskMonitor) -> java.lang.Iterable[AnalysisUnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]]:
        """
        An iterable wrapper for :meth:`start(DebuggerCoordinates, TaskMonitor) <.start>` and
        :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>`
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the starting coordinates
        :param ghidra.util.task.TaskMonitor monitor: the monitor
        :return: the iterable over unwound frames
        :rtype: java.lang.Iterable[AnalysisUnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]]
        """

    @typing.overload
    def start(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, monitor: ghidra.util.task.TaskMonitor) -> AnalysisUnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]:
        """
        Begin unwinding frames that can evaluate variables as :obj:`WatchValue`s
         
         
        
        While the returned frame is not technically "unwound," it is necessary to derive its base
        pointer in order to evaluate any of its variables and unwind subsequent frames. The returned
        frame has the :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>` method.
        
        :param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the starting coordinates, particularly the frame level
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the frame for the given level
        :rtype: AnalysisUnwoundFrame[ghidra.pcode.exec_.DebuggerPcodeUtils.WatchValue]
        :raises CancelledException: if the monitor is cancelled
        """

    @typing.overload
    def start(self, coordinates: ghidra.debug.api.tracemgr.DebuggerCoordinates, state: ghidra.pcode.exec_.PcodeExecutorState[T], monitor: ghidra.util.task.TaskMonitor) -> AnalysisUnwoundFrame[T]:
        """
        Begin unwinding frames that can evaluate variables from the given state
         
         
        
        If is the caller's responsibility to ensure that the given state corresponds to the given
        coordinates. If they do not, the result is undefined.
         
         
        
        The starting frame's program counter and stack pointer are derived from the trace (in
        coordinates), not the state. The program counter will be retrieved from the
        :obj:`TraceStackFrame` if available. Otherwise, it will use the value in the register bank
        for the starting frame level. If it is not known, the unwind fails. The static (module)
        mappings are used to find the function containing the program counter, and that function is
        analyzed for its unwind info, wrt. the mapped program counter. See
        :meth:`UnwindAnalysis.computeUnwindInfo(Address, TaskMonitor) <UnwindAnalysis.computeUnwindInfo>`. Depending on the complexity
        of the function, that analysis may be expensive. If the function cannot be found, the unwind
        fails. If analysis fails, the resulting frame may be incomplete, or the unwind may fail.
        Subsequent frames are handled similarly. See
        :meth:`AnalysisUnwoundFrame.unwindNext(TaskMonitor) <AnalysisUnwoundFrame.unwindNext>`.
        
        :param T: the type of values in the state, and the result of variable evaluations:param ghidra.debug.api.tracemgr.DebuggerCoordinates coordinates: the starting coordinates, particularly the frame level
        :param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state, which must correspond to the given coordinates
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the frame for the given level
        :rtype: AnalysisUnwoundFrame[T]
        :raises CancelledException: if the monitor is cancelled
        """


class SavedRegisterMap(java.lang.Object):
    """
    A map from registers to physical stack addresses
    
     
    
    This is used by an unwound frame to ensure that register reads are translated to stack reads when
    the register's value was saved to the stack by some inner frame. If a register is not saved to
    the stack by such a frame, then its value is read from the register bank.
    """

    @typing.type_check_only
    class SavedEntry(java.lang.Record):
        """
        An entry in the map
        """

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def from_(self) -> ghidra.program.model.address.AddressRange:
            """
            The range in register space to be redirected to the stack
            
            :return: the "from" range
            :rtype: ghidra.program.model.address.AddressRange
            """

        def hashCode(self) -> int:
            ...

        def intersect(self, range: ghidra.program.model.address.AddressRange) -> SavedRegisterMap.SavedEntry:
            """
            Produce the same or equivalent entry that redirects at most the given "from" range
            
            :param ghidra.program.model.address.AddressRange range: the "from" range to intersect
            :return: the same or truncated entry
            :rtype: SavedRegisterMap.SavedEntry
            """

        def size(self) -> int:
            """
            The length of the mapped ranges
            
            :return: the length
            :rtype: int
            """

        def to(self) -> ghidra.program.model.address.Address:
            """
            The physical address in the stack segment to which the register is redirected
             
             
            
            The length of the "to" range is given by the length of the "from" range
            
            :return: the "to" address
            :rtype: ghidra.program.model.address.Address
            """

        def toString(self) -> str:
            ...

        def truncate(self, range: ghidra.program.model.address.AddressRange) -> SavedRegisterMap.SavedEntry:
            """
            Produce an equivalent entry that redirects only the given new "from" range
            
            :param ghidra.program.model.address.AddressRange range: the new "from" range, which must be enclosed by the current "from" range
            :return: the same or truncated entry
            :rtype: SavedRegisterMap.SavedEntry
            """

        def truncateMax(self, max: ghidra.program.model.address.Address) -> SavedRegisterMap.SavedEntry:
            """
            Produce an equivalent entry which excludes any "from" address beyond the given max
            
            :param ghidra.program.model.address.Address max: the max "from" address
            :return: the same or truncated entry
            :rtype: SavedRegisterMap.SavedEntry
            """

        def truncateMin(self, min: ghidra.program.model.address.Address) -> SavedRegisterMap.SavedEntry:
            """
            Produce an equivalent entry which exclude any "from" address before the given min
            
            :param ghidra.program.model.address.Address min: the min "from" address
            :return: the same or truncated entry
            :rtype: SavedRegisterMap.SavedEntry
            """


    @typing.type_check_only
    class SavedEntrySetter(ghidra.trace.database.DBTraceUtils.AddressRangeMapSetter[java.util.Map.Entry[ghidra.program.model.address.Address, SavedRegisterMap.SavedEntry], SavedRegisterMap.SavedEntry]):
        """
        A class which can set values over a range, ensuring no overlapping entries
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PieceVisitor(java.lang.Object, typing.Generic[U]):

        class_: typing.ClassVar[java.lang.Class]

        def visitVarnode(self, address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], user: U) -> U:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct an empty (identity) register map
        """

    @typing.overload
    def __init__(self, saved: java.util.TreeMap[ghidra.program.model.address.Address, SavedRegisterMap.SavedEntry]):
        """
        Copy a given register map
        
        :param java.util.TreeMap[ghidra.program.model.address.Address, SavedRegisterMap.SavedEntry] saved: the map to copy
        """

    def fork(self) -> SavedRegisterMap:
        """
        Copy this register map
        
        :return: the copy
        :rtype: SavedRegisterMap
        """

    def getVar(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], reason: ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason) -> T:
        """
        Get a variable from the given state wrt. this mapping
         
         
        
        Register reads are redirected to the mapped addresses when applicable.
        
        :param T: the type of values in the state:param ghidra.pcode.exec_.PcodeExecutorState[T] state: the state to access
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JInt or int size: the size of the variable
        :param ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason reason: a reason for reading the variable
        :return: the variable's value
        :rtype: T
        """

    @typing.overload
    def put(self, from_: ghidra.program.model.lang.Register, stackVar: ghidra.program.model.pcode.Varnode):
        """
        Map a register to a stack varnode
        
        :param ghidra.program.model.lang.Register from: the register
        :param ghidra.program.model.pcode.Varnode stackVar: the stack varnode
        """

    @typing.overload
    def put(self, from_: ghidra.program.model.address.AddressRange, to: ghidra.program.model.address.AddressRange):
        """
        Map the given ranges, which must have equal lengths
        
        :param ghidra.program.model.address.AddressRange from: the range in register space
        :param ghidra.program.model.address.AddressRange to: the range in the stack segment
        """

    @typing.overload
    def put(self, from_: ghidra.program.model.address.AddressRange, to: ghidra.program.model.address.Address):
        """
        Map the given range to the given address
        
        :param ghidra.program.model.address.AddressRange from: the range in register space
        :param ghidra.program.model.address.Address to: the address in the stack segment
        """

    def setVar(self, editor: ghidra.app.services.DebuggerControlService.StateEditor, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
        """
        Set a variable using the given editor wrt. this mapping
        
        :param ghidra.app.services.DebuggerControlService.StateEditor editor: the editor
        :param ghidra.program.model.address.Address address: the address of the variable
        :param jpype.JArray[jpype.JByte] bytes: the bytes (in language-dependent endianness) giving the variable's value
        :return: a future that completes when all editing commands have completed
        :rtype: java.util.concurrent.CompletableFuture[java.lang.Void]
        """



__all__ = ["AnalysisUnwoundFrame", "SymStateSpace", "SymPcodeExecutorState", "DynamicMappingException", "UnwindStackCommand", "UnwoundFrame", "UnwindException", "StackUnwindWarningSet", "FakeUnwoundFrame", "Sym", "SymPcodeExecutor", "ListingUnwoundFrame", "EvaluationException", "UnwindInfo", "StackUnwindWarning", "FrameStructureBuilder", "AbstractUnwoundFrame", "SymPcodeArithmetic", "UnwindAnalysis", "StackUnwinder", "SavedRegisterMap"]
