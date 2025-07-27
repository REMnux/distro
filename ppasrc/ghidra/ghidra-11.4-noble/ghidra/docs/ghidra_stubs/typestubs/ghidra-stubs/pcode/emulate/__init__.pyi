from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.pcode.emulate.callother
import ghidra.pcode.error
import ghidra.pcode.memstate
import ghidra.pcode.pcoderaw
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class InstructionDecodeException(ghidra.pcode.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reason: typing.Union[java.lang.String, str], pc: ghidra.program.model.address.Address):
        ...

    def getProgramCounter(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programCounter(self) -> ghidra.program.model.address.Address:
        ...


class Emulate(java.lang.Object):
    """
    A SLEIGH based implementation of the Emulate interface
     
    
    This implementation uses a Translate object to translate machine instructions into
    pcode and caches pcode ops for later use by the emulator.  The pcode is cached as soon
    as the execution address is set, either explicitly, or via branches and fallthrus.  There
    are additional methods for inspecting the pcode ops in the current instruction as a sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, s: ghidra.pcode.memstate.MemoryState, b: BreakTable):
        """
        Creates a new :obj:`Emulate` object
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: is the SLEIGH language
        :param ghidra.pcode.memstate.MemoryState s: is the MemoryState the emulator should manipulate
        :param BreakTable b: is the table of breakpoints the emulator should invoke
        """

    def dispose(self):
        ...

    def executeBranch(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        Since the full instruction is cached, we can do relative branches properly
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular branch op being executed
        """

    def executeBranchind(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This routine performs a standard pcode branch indirect operation on the memory state
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular branchind op being executed
        """

    def executeCall(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This routine performs a standard pcode call operation on the memory state
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular call op being executed
        """

    def executeCallind(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This routine performs a standard pcode call indirect operation on the memory state
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular  callind op being executed
        """

    def executeCallother(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        Give instuctionStateModifier first shot at executing custom pcodeop,
        if not supported look for a breakpoint for the given user-defined op and invoke it.
        If it doesn't exist, or doesn't replace the action, throw an exception
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular user-defined op being executed
        :raises UnimplementedCallOtherException:
        """

    def executeConditionalBranch(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        ...

    def executeIndirect(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This kind of pcode op should not come up in ordinary emulation, so this routine
        throws an exception.
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular indirect op being executed
        """

    def executeInstruction(self, stopAtBreakpoint: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        This routine executes an entire machine instruction at once, as a conventional debugger step
        function would do.  If execution is at the start of an instruction, the breakpoints are checked
        and invoked as needed for the current address.  If this routine is invoked while execution is
        in the middle of a machine instruction, execution is continued until the current instruction
        completes.
        
        :param jpype.JBoolean or bool stopAtBreakpoint: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException: 
        :raises LowlevelError: 
        :raises InstructionDecodeException:
        """

    def executeLoad(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This routine performs a standard pcode load operation on the memory state
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular load op being executed
        """

    def executeMultiequal(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This kind of pcode op should not come up in ordinary emulation, so this routine
        throws an exception.
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular multiequal op being executed
        """

    def executeStore(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw):
        """
        This routine performs a standard pcode store operation on the memory state
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular store op being executed
        """

    def fallthruOp(self):
        """
        Update the iterator into the current pcode cache, and if necessary, generate
        the pcode for the fallthru instruction and reset the iterator.
        """

    def getContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the current context register value.  The context value returned reflects
        its state when the previously executed instruction was 
        parsed/executed.  The context value returned will feed into the next 
        instruction to be parsed with its non-flowing bits cleared and
        any future context state merged in.  If no instruction has been executed,
        the explicitly set context will be returned.  A null value is returned
        if no context register is defined by the language or initial context has 
        not been set.
        """

    def getExecuteAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the currently executing machine address
        :rtype: ghidra.program.model.address.Address
        """

    def getExecutionState(self) -> EmulateExecutionState:
        """
        :return: the current emulator execution state
        :rtype: EmulateExecutionState
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getLastExecuteAddress(self) -> ghidra.program.model.address.Address:
        """
        :return: the last address
        :rtype: ghidra.program.model.address.Address
        """

    def getMemoryState(self) -> ghidra.pcode.memstate.MemoryState:
        """
        :return: the memory state object which this emulator uses
        :rtype: ghidra.pcode.memstate.MemoryState
        """

    def getNewDisassemblerContext(self) -> EmulateDisassemblerContext:
        ...

    def isInstructionStart(self) -> bool:
        """
        Since the emulator can single step through individual pcode operations, the machine state
        may be halted in the middle of a single machine instruction, unlike conventional debuggers.
        This routine can be used to determine if execution is actually at the beginning of a machine
        instruction.
        
        :return: true if the next pcode operation is at the start of the instruction translation
        :rtype: bool
        """

    def setContextRegisterValue(self, regValue: ghidra.program.model.lang.RegisterValue):
        """
        Sets the context register value at the current execute address.
        The Emulator should not be running when this method is invoked.
        Only flowing context bits should be set, as non-flowing bits
        will be cleared prior to parsing on instruction.  In addition,
        any future context state set by the pcode emitter will
        take precedence over context set using this method.  This method
        is primarily intended to be used to establish the initial 
        context state.
        
        :param ghidra.program.model.lang.RegisterValue regValue:
        """

    def setExecuteAddress(self, addr: ghidra.program.model.address.Address):
        """
        Set the current execution address and cache the pcode translation of the machine instruction
        at that address
        
        :param ghidra.program.model.address.Address addr: is the address where execution should continue
        """

    @property
    def executeAddress(self) -> ghidra.program.model.address.Address:
        ...

    @executeAddress.setter
    def executeAddress(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def instructionStart(self) -> jpype.JBoolean:
        ...

    @property
    def newDisassemblerContext(self) -> EmulateDisassemblerContext:
        ...

    @property
    def memoryState(self) -> ghidra.pcode.memstate.MemoryState:
        ...

    @property
    def executionState(self) -> EmulateExecutionState:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def lastExecuteAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def contextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @contextRegisterValue.setter
    def contextRegisterValue(self, value: ghidra.program.model.lang.RegisterValue):
        ...


class EmulateDisassemblerContext(ghidra.program.model.lang.DisassemblerContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, initialContextValue: ghidra.program.model.lang.RegisterValue):
        ...

    def getCurrentContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    def setCurrentAddress(self, addr: ghidra.program.model.address.Address):
        ...

    @property
    def currentContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...


class UnimplementedCallOtherException(ghidra.pcode.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw, opName: typing.Union[java.lang.String, str]):
        ...

    def getCallOtherOp(self) -> ghidra.pcode.pcoderaw.PcodeOpRaw:
        ...

    def getCallOtherOpName(self) -> str:
        ...

    @property
    def callOtherOpName(self) -> java.lang.String:
        ...

    @property
    def callOtherOp(self) -> ghidra.pcode.pcoderaw.PcodeOpRaw:
        ...


class EmulateMemoryStateBuffer(ghidra.program.model.mem.MemBuffer):
    """
    ``MemoryStateBuffer`` provides a MemBuffer for instruction parsing use
    which wraps an emulator MemoryState.  This implementation wraps all specified 
    memory offsets within the associated address space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memState: ghidra.pcode.memstate.MemoryState, addr: ghidra.program.model.address.Address):
        ...

    def setAddress(self, addr: ghidra.program.model.address.Address):
        ...


class EmulateExecutionState(java.lang.Enum[EmulateExecutionState]):

    class_: typing.ClassVar[java.lang.Class]
    STOPPED: typing.Final[EmulateExecutionState]
    """
    Currently stopped
    """

    BREAKPOINT: typing.Final[EmulateExecutionState]
    """
    Currently stopped at a breakpoint
    """

    INSTRUCTION_DECODE: typing.Final[EmulateExecutionState]
    """
    Currently decoding instruction (i.e., generating pcode ops)
    """

    EXECUTE: typing.Final[EmulateExecutionState]
    """
    Currently executing instruction pcode
    """

    FAULT: typing.Final[EmulateExecutionState]
    """
    Execution stopped due to a fault/error
    """


    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> EmulateExecutionState:
        ...

    @staticmethod
    def values() -> jpype.JArray[EmulateExecutionState]:
        ...


class UnimplementedInstructionException(ghidra.pcode.error.LowlevelError):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address):
        ...

    def getInstructionAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def instructionAddress(self) -> ghidra.program.model.address.Address:
        ...


class BreakTable(java.lang.Object):
    """
    A collection of breakpoints for the emulator
     
    
    A BreakTable keeps track of an arbitrary number of breakpoints for an emulator.
    Breakpoints are either associated with a particular user-defined pcode op,
    or with a specific machine address (as in a standard debugger). Through the BreakTable
    object, an emulator can invoke breakpoints through the two methods
     
    * doPcodeOpBreak()
    * doAddressBreak()
    
    
    depending on the type of breakpoint they currently want to invoke
    """

    class_: typing.ClassVar[java.lang.Class]

    def doAddressBreak(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Invoke any breakpoints associated with this machine address
         
        
        Within the table, the first breakpoint which is designed to work with at this address
        is invoked.  If there was a breakpoint, and if it was designed to replace
        the action of the machine instruction, then true is returned.
        
        :param ghidra.program.model.address.Address addr: is address to test for breakpoints
        :return: true is the machine instruction has been replaced by a breakpoint
        :rtype: bool
        """

    def doPcodeOpBreak(self, curop: ghidra.pcode.pcoderaw.PcodeOpRaw) -> bool:
        """
        Invoke any breakpoints associated with this particular pcodeop
         
        
        Within the table, the first breakpoint which is designed to work with this particular
        kind of pcode operation is invoked.  If there was a breakpoint and it was designed
        to replace the action of the pcode op, then true is returned.
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw curop: is the instance of a pcode op to test for breakpoints
        :return: true if the action of the pcode op is performed by the breakpoint
        :rtype: bool
        """

    def setEmulate(self, emu: Emulate):
        """
        Associate a particular emulator with breakpoints in this table
         
        
        Breakpoints may need access to the context in which they are invoked. This
        routine provides the context for all breakpoints in the table.
        
        :param Emulate emu: is the Emulate context
        """


class BreakTableCallBack(BreakTable):
    """
    A basic instantiation of a breakpoint table
     
    
    This object allows breakpoints to registered in the table via either
     
    * registerPcodeCallback()
    * registerAddressCallback()
    
    
    Breakpoints are stored in map containers, and the core BreakTable methods
    are implemented to search in these containers
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_NAME: typing.Final = "*"

    def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        """
        The break table needs a translator object so user-defined pcode ops can be registered against
        by name.
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage language: the language
        """

    def doAddressBreak(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        This routine examines the address based container for any breakpoints associated with the
        given address. If one is found, its addressCallback method is invoked.
        
        :param ghidra.program.model.address.Address addr: is the address being checked for breakpoints
        :return: true if the breakpoint exists and returns true, otherwise return false
        :rtype: bool
        """

    def doPcodeOpBreak(self, curop: ghidra.pcode.pcoderaw.PcodeOpRaw) -> bool:
        """
        This routine examines the pcode-op based container for any breakpoints associated with the
        given op.  If one is found, its pcodeCallback method is invoked.
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw curop: is pcode op being checked for breakpoints
        :return: true if the breakpoint exists and returns true, otherwise return false
        :rtype: bool
        """

    def registerAddressCallback(self, addr: ghidra.program.model.address.Address, func: BreakCallBack):
        """
        Any time the emulator is about to execute (the pcode translation of) a particular machine
        instruction at this address, the indicated breakpoint is invoked first. The break table
        does not assume responsibility for freeing the breakpoint object.
        
        :param ghidra.program.model.address.Address addr: is the address associated with the breakpoint
        :param BreakCallBack func: is the breakpoint being registered
        """

    def registerPcodeCallback(self, name: typing.Union[java.lang.String, str], func: BreakCallBack):
        """
        Any time the emulator is about to execute a user-defined pcode op with the given name,
        the indicated breakpoint is invoked first. The break table does not assume responsibility
        for freeing the breakpoint object.
        
        :param java.lang.String or str name: is the name of the user-defined pcode op
        :param BreakCallBack func: is the breakpoint object to associate with the pcode op
        """

    def setEmulate(self, emu: Emulate):
        """
        This routine invokes the setEmulate method on each breakpoint currently in the table
        
        :param Emulate emu: is the emulator to be associated with the breakpoints
        """

    def unregisterAddressCallback(self, addr: ghidra.program.model.address.Address):
        ...

    def unregisterPcodeCallback(self, name: typing.Union[java.lang.String, str]):
        """
        Unregister the currently registered PcodeCallback handler for the
        specified name
        
        :param java.lang.String or str name: is the name of the user-defined pcode op
        """


class EmulateInstructionStateModifier(java.lang.Object):
    """
    ``EmulateInstructionStateModifier`` defines a language specific handler to assist
    emulation with adjusting the current execution state, providing support for custom pcodeop's
    (i.e., CALLOTHER). The implementation of this interface must provide a public constructor which
    takes a single Emulate argument.
    """

    class_: typing.ClassVar[java.lang.Class]

    def executeCallOther(self, op: ghidra.program.model.pcode.PcodeOp) -> bool:
        """
        Execute a CALLOTHER op
        
        :param ghidra.program.model.pcode.PcodeOp op: 
        :return: true if corresponding pcodeop was registered and emulation support is performed, or
                false if corresponding pcodeop is not supported by this class.
        :rtype: bool
        :raises LowlevelError:
        """

    def getPcodeOpMap(self) -> java.util.Map[java.lang.Integer, ghidra.pcode.emulate.callother.OpBehaviorOther]:
        """
        Get the map of registered pcode userop behaviors
        
        :return: the map, by userop index.
        :rtype: java.util.Map[java.lang.Integer, ghidra.pcode.emulate.callother.OpBehaviorOther]
        """

    def initialExecuteCallback(self, emulate: Emulate, current_address: ghidra.program.model.address.Address, contextRegisterValue: ghidra.program.model.lang.RegisterValue):
        """
        Emulation callback immediately before the first instruction is executed. This callback
        permits any language specific initializations to be performed.
        
        :param Emulate emulate: 
        :param ghidra.program.model.address.Address current_address: intial execute address
        :param ghidra.program.model.lang.RegisterValue contextRegisterValue: initial context value or null if not applicable or unknown
        :raises LowlevelError:
        """

    def postExecuteCallback(self, emulate: Emulate, lastExecuteAddress: ghidra.program.model.address.Address, lastExecutePcode: jpype.JArray[ghidra.program.model.pcode.PcodeOp], lastPcodeIndex: typing.Union[jpype.JInt, int], currentAddress: ghidra.program.model.address.Address):
        """
        Emulation callback immediately following execution of the lastExecuteAddress. One use of this
        callback is to modify the flowing/future context state.
        
        :param Emulate emulate: 
        :param ghidra.program.model.address.Address lastExecuteAddress: 
        :param jpype.JArray[ghidra.program.model.pcode.PcodeOp] lastExecutePcode: 
        :param jpype.JInt or int lastPcodeIndex: pcode index of last op or -1 if no pcode or fall-through occurred.
        :param ghidra.program.model.address.Address currentAddress: 
        :raises LowlevelError:
        """

    @property
    def pcodeOpMap(self) -> java.util.Map[java.lang.Integer, ghidra.pcode.emulate.callother.OpBehaviorOther]:
        ...


class BreakCallBack(java.lang.Object):
    """
    A breakpoint object
     
    
    This is a base class for breakpoint objects in an emulator.  The breakpoints are implemented
    as callback method, which is overridden for the particular behavior needed by the emulator.
    Each derived class must override either
     
    * pcodeCallback()
    * addressCallback()
    
    
    depending on whether the breakpoint is tailored for a particular pcode op or for
    a machine address.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addressCallback(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        This routine is invoked during emulation, if this breakpoint has somehow been associated with
        this address.  The callback can perform any operation on the emulator context it wants. It then
        returns true if these actions are intended to replace the action of the entire machine
        instruction at this address. Or it returns false if the machine instruction should still be
        executed normally.
        
        :param ghidra.program.model.address.Address addr: is the address where the break has occurred
        :return: true if the machine instruction should not be executed
        :rtype: bool
        """

    def pcodeCallback(self, op: ghidra.pcode.pcoderaw.PcodeOpRaw) -> bool:
        """
        This routine is invoked during emulation, if this breakpoint has somehow been associated with
        this kind of pcode op.  The callback can perform any operation on the emulator context it wants.
        It then returns \b true if these actions are intended to replace the action of the pcode op itself.
        Or it returns \b false if the pcode op should still have its normal effect on the emulator context.
        
        :param ghidra.pcode.pcoderaw.PcodeOpRaw op: is the particular pcode operation where the break occurs.
        :return: \b true if the normal pcode op action should not occur
        :rtype: bool
        """

    def setEmulate(self, emu: Emulate):
        ...



__all__ = ["InstructionDecodeException", "Emulate", "EmulateDisassemblerContext", "UnimplementedCallOtherException", "EmulateMemoryStateBuffer", "EmulateExecutionState", "UnimplementedInstructionException", "BreakTable", "BreakTableCallBack", "EmulateInstructionStateModifier", "BreakCallBack"]
