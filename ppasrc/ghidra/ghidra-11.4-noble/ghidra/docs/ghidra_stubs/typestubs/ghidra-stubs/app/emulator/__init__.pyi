from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.emulator.memory
import ghidra.app.emulator.state
import ghidra.app.plugin.processors.sleigh
import ghidra.pcode.emu
import ghidra.pcode.emulate
import ghidra.pcode.exec_
import ghidra.pcode.memstate
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class EmulatorConfiguration(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getLoadData(self) -> ghidra.app.emulator.memory.EmulatorLoadData:
        ...

    def getMemoryFaultHandler(self) -> ghidra.pcode.memstate.MemoryFaultHandler:
        ...

    def getPreferredMemoryPageSize(self) -> int:
        ...

    def getProgramCounterName(self) -> str:
        ...

    def isWriteBackEnabled(self) -> bool:
        ...

    @property
    def memoryFaultHandler(self) -> ghidra.pcode.memstate.MemoryFaultHandler:
        ...

    @property
    def loadData(self) -> ghidra.app.emulator.memory.EmulatorLoadData:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def writeBackEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def preferredMemoryPageSize(self) -> jpype.JInt:
        ...

    @property
    def programCounterName(self) -> java.lang.String:
        ...


class Emulator(java.lang.Object):
    """
    The emulator interface
     
     
    
    This interface may soon be deprecated. It was extracted from what has now been renamed
    :obj:`DefaultEmulator`. Please consider using :obj:`PcodeEmulator` instead.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addMemoryAccessFilter(self, filter: MemoryAccessFilter):
        """
        Add a filter on memory access
        
        :param MemoryAccessFilter filter: the filter
        """

    def dispose(self):
        """
        Clean up resources used by the emulator
        """

    def executeInstruction(self, stopAtBreakpoint: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Execute instruction at current address
        
        :param jpype.JBoolean or bool stopAtBreakpoint: if true and breakpoint hits at current execution address execution
                    will halt without executing instruction.
        :raises CancelledException: if execution was cancelled
        """

    def getBreakTable(self) -> ghidra.pcode.emulate.BreakTableCallBack:
        """
        Get the breakpoint table
        
        :return: the breakpoint table
        :rtype: ghidra.pcode.emulate.BreakTableCallBack
        """

    def getContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the current context register value.
         
         
        
        The context value returned reflects its state when the previously executed instruction was
        parsed/executed. The context value returned will feed into the next instruction to be parsed
        with its non-flowing bits cleared and any future context state merged in.
        
        :return: context as a RegisterValue object
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getEmulateExecutionState(self) -> ghidra.pcode.emulate.EmulateExecutionState:
        """
        Get the low-level execution state
         
         
        
        This can be useful within a memory fault handler to determine if a memory read was associated
        with instruction parsing (i.e., :obj:`EmulateExecutionState.INSTRUCTION_DECODE`) or an
        actual emulated read (i.e., :obj:`EmulateExecutionState.EXECUTE`).
        
        :return: emulator execution state.
        :rtype: ghidra.pcode.emulate.EmulateExecutionState
        """

    def getExecuteAddress(self) -> ghidra.program.model.address.Address:
        """
        Get current execution address (or the address of the next instruction to be executed)
        
        :return: current execution address
        :rtype: ghidra.program.model.address.Address
        """

    def getFilteredMemState(self) -> FilteredMemoryState:
        """
        Get the memory state, modified by all installed access filters
        
        :return: the state
        :rtype: FilteredMemoryState
        """

    def getHalt(self) -> bool:
        """
        Check if the emulator has been halted
        
        :return: true if halted
        :rtype: bool
        """

    def getLastExecuteAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the last instruction executed (or the instructed currently being executed)
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getMemState(self) -> ghidra.pcode.memstate.MemoryState:
        """
        Get the memory state
        
        :return: the state
        :rtype: ghidra.pcode.memstate.MemoryState
        """

    def getPC(self) -> int:
        """
        Get the value of the program counter
        
        :return: the value, i.e., offset in code space
        :rtype: int
        """

    def getPCRegisterName(self) -> str:
        """
        Get the name of the program counter register
        
        :return: the name
        :rtype: str
        """

    def isAtBreakpoint(self) -> bool:
        """
        
        
        :return: true if halted at a breakpoint
        :rtype: bool
        """

    def isExecuting(self) -> bool:
        """
        
        
        :return: true if emulator is busy executing an instruction
        :rtype: bool
        """

    def setContextRegisterValue(self, regValue: ghidra.program.model.lang.RegisterValue):
        """
        Sets the context register value at the current execute address.
         
         
        
        The Emulator should not be running when this method is invoked. Only flowing context bits
        should be set, as non-flowing bits will be cleared prior to parsing on instruction. In
        addition, any future context state set by the pcode emitter will take precedence over context
        set using this method. This method is primarily intended to be used to establish the initial
        context state.
        
        :param ghidra.program.model.lang.RegisterValue regValue: is the value to set context to
        """

    def setExecuteAddress(self, addressableWordOffset: typing.Union[jpype.JLong, int]):
        """
        Set the value of the program counter
        
        :param jpype.JLong or int addressableWordOffset: the *word* offset of the instruction to execute next.
        """

    def setHalt(self, halt: typing.Union[jpype.JBoolean, bool]):
        """
        Halt or un-halt the emulator
        
        :param jpype.JBoolean or bool halt: true to halt
        """

    @property
    def pCRegisterName(self) -> java.lang.String:
        ...

    @property
    def memState(self) -> ghidra.pcode.memstate.MemoryState:
        ...

    @property
    def halt(self) -> jpype.JBoolean:
        ...

    @halt.setter
    def halt(self, value: jpype.JBoolean):
        ...

    @property
    def breakTable(self) -> ghidra.pcode.emulate.BreakTableCallBack:
        ...

    @property
    def pC(self) -> jpype.JLong:
        ...

    @property
    def executeAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def filteredMemState(self) -> FilteredMemoryState:
        ...

    @property
    def atBreakpoint(self) -> jpype.JBoolean:
        ...

    @property
    def emulateExecutionState(self) -> ghidra.pcode.emulate.EmulateExecutionState:
        ...

    @property
    def executing(self) -> jpype.JBoolean:
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


class AdaptedMemoryState(ghidra.pcode.memstate.AbstractMemoryState, typing.Generic[T]):
    """
    An implementation of :obj:`MemoryState` which wraps a newer :obj:`PcodeExecutorState`.
     
     
    
    This is a transitional component used internally by the :obj:`AdaptedEmulator`. It is also used
    in the :obj:`ModifiedPcodeThread`, which is part of the newer :obj:`PcodeEmulator` system, as a
    means of incorporating :obj:`EmulateInstructionStateModifier`, which is part of the older
    :obj:`EmulatorHelper` system. This class will be removed once both conditions are met:
     
     
    1. An equivalent state modification system is developed for the :obj:`PcodeEmulator` system,
    and each:obj:`EmulateInstructionStateModifier` is ported to it.
    2. The :obj:`AdaptedEmulator` class is removed.
    
     
     
    
    Guidance for the use of this class is the same as :obj:`AdaptedEmulator`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, state: ghidra.pcode.exec_.PcodeExecutorState[T], reason: ghidra.pcode.exec_.PcodeExecutorStatePiece.Reason):
        ...


class DefaultEmulator(Emulator):
    """
    The default implementation of :obj:`Emulator`.
    
     
    
    This class used to be named ``Emulator``, until it was replaced by an interface extracted
    from this class. There is now a second implementation named :obj:`AdaptedEmulator`, which wraps
    the newer :obj:`PcodeEmulator` system. If you are developing a new use case based on p-code
    emulation, please consider using :obj:`PcodeEmulator` directly. There are several example
    scripts in the ``SystemEmulation`` module. If you are maintaining an existing use case
    currently based on :obj:`Emulator`, you will at least need to change ``new Emulator(...)``
    to ``new DefaultEmulator(...)``. It is highly recommended to port to the newer
    :obj:`PcodeEmulator`. You may find the :obj:`AdaptedEmulator` useful during the transition, but
    that class is only transitional.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cfg: EmulatorConfiguration):
        ...

    def addProvider(self, provider: ghidra.app.emulator.memory.MemoryLoadImage, view: ghidra.program.model.address.AddressSetView):
        """
        Add memory load image provider
        
        :param ghidra.app.emulator.memory.MemoryLoadImage provider: memory load image provider
        :param ghidra.program.model.address.AddressSetView view: memory region which corresponds to provider
        """

    def cloneMemory(self) -> ghidra.pcode.memstate.MemoryState:
        ...

    def disassemble(self, count: typing.Union[java.lang.Integer, int]) -> java.util.List[java.lang.String]:
        """
        Disassemble from the current execute address
        
        :param java.lang.Integer or int count: number of contiguous instructions to disassemble
        :return: list of instructions
        :rtype: java.util.List[java.lang.String]
        """

    def genAddress(self, addr: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        ...

    def getDefaultContext(self) -> java.util.Set[java.lang.String]:
        ...

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...

    def getMemoryBank(self, space: ghidra.program.model.address.AddressSpace, ps: typing.Union[jpype.JInt, int]) -> ghidra.app.emulator.state.FilteredMemoryPageOverlay:
        ...

    def getTickCount(self) -> int:
        ...

    @property
    def tickCount(self) -> jpype.JInt:
        ...

    @property
    def defaultContext(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...


class EmulatorHelper(ghidra.pcode.memstate.MemoryFaultHandler, EmulatorConfiguration):
    """
    This is the primary "entry point" for using an :obj:`Emulator`.
    
     
    
    This is part of the older p-code emulation system. For information about the newer p-code
    emulation system, see :obj:`PcodeEmulator`. There are several example scripts in the
    ``SystemEmulation`` module.
    
    
    .. seealso::
    
        | :obj:`PcodeEmulator`
    
        | :obj:`Emulator`
    """

    @typing.type_check_only
    class MemoryWriteTracker(MemoryAccessFilter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def clearBreakpoint(self, addr: ghidra.program.model.address.Address):
        """
        Clear breakpoint
        
        :param ghidra.program.model.address.Address addr: memory address for breakpoint to be cleared
        """

    def createMemoryBlockFromMemoryState(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], overlay: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.mem.MemoryBlock:
        """
        Create a new initialized memory block using the current emulator memory state
        
        :param java.lang.String or str name: block name
        :param ghidra.program.model.address.Address start: start address of the block
        :param jpype.JInt or int length: the size of the block
        :param jpype.JBoolean or bool overlay: if true, the block will be created as an OVERLAY which means that a new
                    overlay address space will be created and the block will have a starting address
                    at the same offset as the given start address parameter, but in the new address
                    space.
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: new memory block
        :rtype: ghidra.program.model.mem.MemoryBlock
        :raises LockException: if exclusive lock not in place (see haveLock())
        :raises MemoryConflictException: if the new block overlaps with a previous block
        :raises AddressOverflowException: if the start is beyond the address space
        :raises CancelledException: user cancelled operation
        :raises DuplicateNameException:
        """

    def dispose(self):
        ...

    def enableMemoryWriteTracking(self, enable: typing.Union[jpype.JBoolean, bool]):
        """
        Enable/Disable tracking of memory writes in the form of an address set.
        
        :param jpype.JBoolean or bool enable:
        """

    def getContextRegister(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the current context register value
        
        :return: context register value or null if not set or unknown
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getEmulateExecutionState(self) -> ghidra.pcode.emulate.EmulateExecutionState:
        """
        
        
        :return: the low-level emulator execution state
        :rtype: ghidra.pcode.emulate.EmulateExecutionState
        """

    def getEmulator(self) -> Emulator:
        ...

    def getExecutionAddress(self) -> ghidra.program.model.address.Address:
        """
        Get current execution address
        
        :return: current execution address
        :rtype: ghidra.program.model.address.Address
        """

    def getLastError(self) -> str:
        """
        
        
        :return: last error message associated with execution failure
        :rtype: str
        """

    def getPCRegister(self) -> ghidra.program.model.lang.Register:
        """
        Get Program Counter (PC) register defined by applicable processor specification
        
        :return: Program Counter register
        :rtype: ghidra.program.model.lang.Register
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getStackPointerRegister(self) -> ghidra.program.model.lang.Register:
        """
        Get Stack Pointer register defined by applicable compiler specification
        
        :return: Stack Pointer register
        :rtype: ghidra.program.model.lang.Register
        """

    def getTrackedMemoryWriteSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        :return: address set of memory locations written by the emulator if memory write tracking is
                enabled, otherwise null is returned. The address set returned will continue to be
                updated unless memory write tracking becomes disabled.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def readMemory(self, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        ...

    def readMemoryByte(self, addr: ghidra.program.model.address.Address) -> int:
        ...

    def readNullTerminatedString(self, addr: ghidra.program.model.address.Address, maxLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Read string from memory state.
        
        :param ghidra.program.model.address.Address addr: memory address
        :param jpype.JInt or int maxLength: limit string read to this length. If return string is truncated, "..." will
                    be appended.
        :return: string read from memory state
        :rtype: str
        """

    @typing.overload
    def readRegister(self, reg: ghidra.program.model.lang.Register) -> java.math.BigInteger:
        ...

    @typing.overload
    def readRegister(self, regName: typing.Union[java.lang.String, str]) -> java.math.BigInteger:
        ...

    def readStackValue(self, relativeOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], signed: typing.Union[jpype.JBoolean, bool]) -> java.math.BigInteger:
        """
        Read a stack value from the memory state.
        
        :param jpype.JInt or int relativeOffset: offset relative to current stack pointer
        :param jpype.JInt or int size: data size in bytes
        :param jpype.JBoolean or bool signed: true if value read is signed, false if unsigned
        :return: value
        :rtype: java.math.BigInteger
        :raises java.lang.Exception: error occurs reading stack pointer
        """

    def registerCallOtherCallback(self, pcodeOpName: typing.Union[java.lang.String, str], callback: ghidra.pcode.emulate.BreakCallBack):
        """
        Register callback for language defined pcodeop (call other). WARNING! Using this method may
        circumvent the default CALLOTHER emulation support when supplied by the Processor module.
        
        :param java.lang.String or str pcodeOpName: the name of the pcode op
        :param ghidra.pcode.emulate.BreakCallBack callback: the callback to register
        """

    def registerDefaultCallOtherCallback(self, callback: ghidra.pcode.emulate.BreakCallBack):
        """
        Register default callback for language defined pcodeops (call other). WARNING! Using this
        method may circumvent the default CALLOTHER emulation support when supplied by the Processor
        module.
        
        :param ghidra.pcode.emulate.BreakCallBack callback: the default callback to register
        """

    @typing.overload
    def run(self, addr: ghidra.program.model.address.Address, context: ghidra.program.model.lang.ProcessorContext, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Start execution at the specified address using the initial context specified. Method will
        block until execution stops. This method will initialize context register based upon the
        program stored context if not already done. In addition, both general register value and the
        context register may be further modified via the context parameter if specified.
        
        :param ghidra.program.model.address.Address addr: initial program address
        :param ghidra.program.model.lang.ProcessorContext context: optional context settings which override current program context
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: true if execution completes without error (i.e., is at breakpoint)
        :rtype: bool
        :raises CancelledException: if execution cancelled via monitor
        """

    @typing.overload
    def run(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Continue execution from the current execution address. No adjustment will be made to the
        context beyond the normal context flow behavior defined by the language. Method will block
        until execution stops.
        
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: true if execution completes without error (i.e., is at breakpoint)
        :rtype: bool
        :raises CancelledException: if execution cancelled via monitor
        """

    def setBreakpoint(self, addr: ghidra.program.model.address.Address):
        """
        Establish breakpoint
        
        :param ghidra.program.model.address.Address addr: memory address for new breakpoint
        """

    @typing.overload
    def setContextRegister(self, ctxRegValue: ghidra.program.model.lang.RegisterValue):
        """
        Set current context register value. Keep in mind that any non-flowing context values will be
        stripped.
        
        :param ghidra.program.model.lang.RegisterValue ctxRegValue:
        """

    @typing.overload
    def setContextRegister(self, ctxReg: ghidra.program.model.lang.Register, value: java.math.BigInteger):
        """
        Set current context register value. Keep in mind that any non-flowing context values will be
        stripped.
        
        :param ghidra.program.model.lang.Register ctxReg: context register
        :param java.math.BigInteger value: context value
        """

    def setMemoryFaultHandler(self, handler: ghidra.pcode.memstate.MemoryFaultHandler):
        """
        Provides ability to install a low-level memory fault handler. The handler methods should
        generally return 'false' to allow the default handler to generate the appropriate target
        error. Within the fault handler, the EmulateExecutionState can be used to distinguish the
        pcode-emit state and the actual execution state since an attempt to execute an instruction at
        an uninitialized memory location will cause an uninitializedRead during the PCODE_EMIT state.
        
        :param ghidra.pcode.memstate.MemoryFaultHandler handler: memory fault handler.
        """

    def step(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Step execution one instruction which may consist of multiple pcode operations. No adjustment
        will be made to the context beyond the normal context flow behavior defined by the language.
        Method will block until execution stops.
        
        :return: true if execution completes without error
        :rtype: bool
        :raises CancelledException: if execution cancelled via monitor
        """

    def unregisterCallOtherCallback(self, pcodeOpName: typing.Union[java.lang.String, str]):
        """
        Unregister callback for language defined pcodeop (call other).
        
        :param java.lang.String or str pcodeOpName: the name of the pcode op
        """

    def unregisterDefaultCallOtherCallback(self):
        """
        Unregister default callback for language defined pcodeops (call other). WARNING! Using this
        method may circumvent the default CALLOTHER emulation support when supplied by the Processor
        module.
        """

    def writeMemory(self, addr: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]):
        ...

    def writeMemoryValue(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def writeRegister(self, reg: ghidra.program.model.lang.Register, value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def writeRegister(self, regName: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def writeRegister(self, reg: ghidra.program.model.lang.Register, value: java.math.BigInteger):
        ...

    @typing.overload
    def writeRegister(self, regName: typing.Union[java.lang.String, str], value: java.math.BigInteger):
        ...

    @typing.overload
    def writeStackValue(self, relativeOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Write a value onto the stack
        
        :param jpype.JInt or int relativeOffset: offset relative to current stack pointer
        :param jpype.JInt or int size: data size in bytes
        :param jpype.JLong or int value: 
        :raises java.lang.Exception: error occurs reading stack pointer
        """

    @typing.overload
    def writeStackValue(self, relativeOffset: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int], value: java.math.BigInteger):
        """
        Write a value onto the stack
        
        :param jpype.JInt or int relativeOffset: offset relative to current stack pointer
        :param jpype.JInt or int size: data size in bytes
        :param java.math.BigInteger value: 
        :raises java.lang.Exception: error occurs reading stack pointer
        """

    @property
    def emulator(self) -> Emulator:
        ...

    @property
    def contextRegister(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @contextRegister.setter
    def contextRegister(self, value: ghidra.program.model.lang.RegisterValue):
        ...

    @property
    def lastError(self) -> java.lang.String:
        ...

    @property
    def trackedMemoryWriteSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def emulateExecutionState(self) -> ghidra.pcode.emulate.EmulateExecutionState:
        ...

    @property
    def stackPointerRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def pCRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def executionAddress(self) -> ghidra.program.model.address.Address:
        ...


@typing.type_check_only
class FilteredMemoryState(ghidra.pcode.memstate.DefaultMemoryState):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AdaptedEmulator(Emulator):
    """
    An implementation of :obj:`Emulator` that wraps the newer :obj:`PcodeEmulator`
     
     
    
    This is a transitional utility only. It is currently used only by the pcode tests until that is
    ported to use the new :obj:`PcodeEmulator` directly. New use cases based on p-code emulation
    should use the :obj:`PcodeEmulator` directly. Older use cases still being actively maintained
    should begin work porting to :obj:`PcodeEmulator`. Old use cases without active maintenance may
    try this wrapper, but may have to remain using :obj:`DefaultEmulator`. At a minimum, to update
    such old use cases, `new Emulator(...)` must be replaced by `new DefaultEmulator(...)`.
    """

    @typing.type_check_only
    class AdaptedPcodeEmulator(ghidra.pcode.emu.PcodeEmulator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, loadImage: ghidra.app.emulator.memory.MemoryLoadImage, faultHandler: ghidra.pcode.memstate.MemoryFaultHandler):
            ...


    class AdaptedPcodeUseropLibrary(ghidra.pcode.exec_.AnnotatedPcodeUseropLibrary[jpype.JArray[jpype.JByte]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def __addr_cb(self):
            ...


    @typing.type_check_only
    class AdaptedPcodeThread(ghidra.pcode.emu.BytesPcodeThread):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], machine: ghidra.pcode.emu.AbstractPcodeMachine[jpype.JArray[jpype.JByte]]):
            ...


    @typing.type_check_only
    class StateBacking(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def faultHandler(self) -> ghidra.pcode.memstate.MemoryFaultHandler:
            ...

        def hashCode(self) -> int:
            ...

        def loadImage(self) -> ghidra.app.emulator.memory.MemoryLoadImage:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class AdaptedBytesPcodeExecutorState(ghidra.pcode.exec_.BytesPcodeExecutorState):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, backing: AdaptedEmulator.StateBacking):
            ...


    @typing.type_check_only
    class AdaptedBytesPcodeExecutorStatePiece(ghidra.pcode.exec_.AbstractBytesPcodeExecutorStatePiece[AdaptedEmulator.AdaptedBytesPcodeExecutorStateSpace]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, backing: AdaptedEmulator.StateBacking):
            ...


    @typing.type_check_only
    class AdaptedBytesPcodeExecutorStateSpace(ghidra.pcode.exec_.BytesPcodeExecutorStateSpace[AdaptedEmulator.StateBacking]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, space: ghidra.program.model.address.AddressSpace, backing: AdaptedEmulator.StateBacking):
            ...


    @typing.type_check_only
    class AdaptedBreakTableCallback(ghidra.pcode.emulate.BreakTableCallBack):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class AdaptedFilteredMemoryState(FilteredMemoryState):
        """
        An adapter to keep track of the filter chain
         
         
        
        We don't actually invoke this adapter's set/getChunk methods. Instead, we just use it to
        track what filters are installed. The :obj:`AdaptedBytesPcodeExecutorState` will invoke the
        filter chain and then perform the read or write itself.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, config: EmulatorConfiguration):
        ...


class MemoryAccessFilter(java.lang.Object):
    """
    A means of intercepting and/or modifying the emulator's memory access.
     
     
    
    Several of these filters may be chained together, each being invoked in the reverse of the order
    added. In this way, the first added gets the "final say," but it also is farthest from the
    original request.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispose(self):
        """
        Dispose this filter which will cause it to be removed from the memory state.
         
         
        
        If overriden, be sure to invoke ``super.dispose()``.
        """

    def filterOnExecutionOnly(self) -> bool:
        ...

    def setFilterOnExecutionOnly(self, filterOnExecutionOnly: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["EmulatorConfiguration", "Emulator", "AdaptedMemoryState", "DefaultEmulator", "EmulatorHelper", "FilteredMemoryState", "AdaptedEmulator", "MemoryAccessFilter"]
