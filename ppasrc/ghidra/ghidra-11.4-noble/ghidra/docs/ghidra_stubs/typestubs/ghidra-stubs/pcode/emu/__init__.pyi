from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh
import ghidra.app.util
import ghidra.pcode.emulate
import ghidra.pcode.emulate.callother
import ghidra.pcode.exec_
import ghidra.pcode.memstate
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")
V = typing.TypeVar("V")


class ThreadPcodeExecutorState(ghidra.pcode.exec_.PcodeExecutorState[T], typing.Generic[T]):
    """
    A p-code executor state that multiplexes shared and thread-local states for use in a machine that
    models multi-threading
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sharedState: ghidra.pcode.exec_.PcodeExecutorState[T], localState: ghidra.pcode.exec_.PcodeExecutorState[T]):
        """
        Create a multiplexed state
        
        :param ghidra.pcode.exec_.PcodeExecutorState[T] sharedState: the shared part of the state
        :param ghidra.pcode.exec_.PcodeExecutorState[T] localState: the thread-local part of the state
        
        .. seealso::
        
            | :obj:`DefaultPcodeThread.DefaultPcodeThread(String, AbstractPcodeMachine)`
        """

    def getLocalState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        """
        Get the thread-local state
        
        :return: the thread-local state
        :rtype: ghidra.pcode.exec_.PcodeExecutorState[T]
        """

    def getSharedState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        """
        Get the shared state
        
        :return: the shared state
        :rtype: ghidra.pcode.exec_.PcodeExecutorState[T]
        """

    @property
    def sharedState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        ...

    @property
    def localState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        ...


class PcodeThread(java.lang.Object, typing.Generic[T]):
    """
    An emulated thread of execution
    """

    class_: typing.ClassVar[java.lang.Class]

    def assignContext(self, context: ghidra.program.model.lang.RegisterValue):
        """
        Adjust the thread's decoding context without writing to its executor state
         
         
        
        As in :meth:`RegisterValue.assign(Register, RegisterValue) <RegisterValue.assign>`, only those bits having a value
        in the given context are applied to the current context.
        
        :param ghidra.program.model.lang.RegisterValue context: the new context
        
        .. seealso::
        
            | :obj:`.overrideContext(RegisterValue)`
        """

    def clearAllInjects(self):
        """
        Remove all per-thread injects from this thread
         
         
        
        All machine-level injects are still effective after this call.
        """

    def clearInject(self, address: ghidra.program.model.address.Address):
        """
        Remove the per-thread inject, if present, at the given address
         
         
        
        This has no effect on machine-level injects. If there is one present, it will still override
        this thread's p-code if execution reaches the address.
        
        :param ghidra.program.model.address.Address address: the address to clear
        """

    def dropInstruction(self):
        """
        If there is a current instruction, drop its frame of execution
         
         
        
        **WARNING:** This does not revert any state changes caused by a partially-executed
        instruction. It is up to the client to revert the underlying machine state if desired. Note
        the thread's program counter will not be advanced. Likely, the next call to
        :meth:`stepInstruction() <.stepInstruction>` will re-start the same instruction. If there is no current
        instruction, this method has no effect.
        """

    def executeInstruction(self):
        """
        Execute the next instruction, ignoring injects
         
         
        
        **WARNING:** This method should likely only be used internally. It steps the current
        instruction, but without any consideration for user injects, e.g., breakpoints. Most clients
        should call :meth:`stepInstruction() <.stepInstruction>` instead.
        
        :raises IllegalStateException: if the emulator is still in the middle of an instruction. That
                    can happen if the machine is interrupted, or if the client has called
                    :meth:`stepPcodeOp() <.stepPcodeOp>`.
        """

    def finishInstruction(self):
        """
        Finish execution of the current instruction or inject
         
         
        
        In general, this method is only used after an interrupt or fault in order to complete the
        p-code of the faulting instruction. Depending on the nature of the interrupt, this behavior
        may not be desired.
        
        :raises IllegalStateException: if there is no current instruction, i.e., the emulator has not
                    started executing the next instruction, yet.
        """

    def getArithmetic(self) -> ghidra.pcode.exec_.PcodeArithmetic[T]:
        """
        Get the thread's p-code arithmetic
        
        :return: the arithmetic
        :rtype: ghidra.pcode.exec_.PcodeArithmetic[T]
        """

    def getContext(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the thread's decoding context
        
        :return: the context
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getCounter(self) -> ghidra.program.model.address.Address:
        """
        Get the value of the program counter of this thread
        
        :return: the value
        :rtype: ghidra.program.model.address.Address
        """

    def getExecutor(self) -> ghidra.pcode.exec_.PcodeExecutor[T]:
        """
        Get the thread's p-code executor
         
         
        
        This can be used to execute injected p-code, e.g., as part of implementing a userop, or as
        part of testing, outside the thread's usual control flow. Any new frame generated by the
        executor is ignored by the thread. It retains the instruction frame, if any. Note that
        suspension is implemented by the executor, so if this p-code thread is suspended, the
        executor cannot execute any code.
        
        :return: the executor
        :rtype: ghidra.pcode.exec_.PcodeExecutor[T]
        """

    def getFrame(self) -> ghidra.pcode.exec_.PcodeFrame:
        """
        Get the current frame, if present
         
         
        
        If the client only calls :meth:`stepInstruction() <.stepInstruction>` and execution completes normally, this
        method will always return ``null``. If interrupted, the frame marks where execution of an
        instruction or inject should resume. Depending on the case, the frame may need to be stepped
        back in order to retry the failed p-code operation. If this frame is present, it means that
        the instruction has not been executed completed. Even if the frame
        :meth:`PcodeFrame.isFinished() <PcodeFrame.isFinished>`,
        
        :return: the current frame
        :rtype: ghidra.pcode.exec_.PcodeFrame
        """

    def getInstruction(self) -> ghidra.program.model.listing.Instruction:
        """
        Get the current decoded instruction, if applicable
        
        :return: the instruction
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        """
        Get the thread's Sleigh language (processor model)
        
        :return: the language
        :rtype: ghidra.app.plugin.processors.sleigh.SleighLanguage
        """

    def getMachine(self) -> PcodeMachine[T]:
        """
        Get the machine within which this thread executes
        
        :return: the containing machine
        :rtype: PcodeMachine[T]
        """

    def getName(self) -> str:
        """
        Get the name of this thread
        
        :return: the name
        :rtype: str
        """

    def getState(self) -> ThreadPcodeExecutorState[T]:
        """
        Get the thread's memory and register state
         
         
        
        The memory part of this state is shared among all threads in the same machine. See
        :meth:`PcodeMachine.getSharedState() <PcodeMachine.getSharedState>`.
        
        :return: the state
        :rtype: ThreadPcodeExecutorState[T]
        """

    def getUseropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        """
        Get the complete userop library for this thread
        
        :return: the library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[T]
        """

    def inject(self, address: ghidra.program.model.address.Address, source: typing.Union[java.lang.String, str]):
        """
        Override the p-code at the given address with the given Sleigh source for only this thread
         
         
        
        This works the same :meth:`PcodeMachine.inject(Address, String) <PcodeMachine.inject>` but on a per-thread basis.
        Where there is both a machine-level and thread-level inject the thread inject takes
        precedence. Furthermore, the machine-level inject cannot be accessed by the thread-level
        inject.
        
        :param ghidra.program.model.address.Address address: the address to inject at
        :param java.lang.String or str source: the Sleigh source to compile and inject
        """

    def isSuspended(self) -> bool:
        """
        Check the suspension state of the thread's executor
        
        :return: true if suspended
        :rtype: bool
        """

    def overrideContext(self, context: ghidra.program.model.lang.RegisterValue):
        """
        Adjust the thread's decoding context and write the contextreg of its executor state
        
        :param ghidra.program.model.lang.RegisterValue context: the new context
        
        .. seealso::
        
            | :obj:`.assignContext(RegisterValue)`
        """

    def overrideContextWithDefault(self):
        """
        Set the context at the current counter to the default given by the language
         
         
        
        This also writes the context to the thread's state. For languages without context, this call
        does nothing.
        """

    def overrideCounter(self, counter: ghidra.program.model.address.Address):
        """
        Set the thread's program counter and write the pc register of its executor state
         
         
        
        **Warning:** Setting the counter into the middle of group constructs, e.g., parallel
        instructions or delay-slotted instructions, may cause undefined behavior.
        
        :param ghidra.program.model.address.Address counter: the new target address
        
        .. seealso::
        
            | :obj:`.setCounter(Address)`
        """

    def reInitialize(self):
        """
        Re-sync the decode context and counter address from the machine state
        """

    def run(self):
        """
        Emulate indefinitely
         
         
        
        This begins or resumes execution of the emulator. If there is a current instruction, that
        instruction is finished. By calling this method, you are "donating" the current Java thread
        to the emulator. This method will not likely return, but instead only terminates via
        exception, e.g., hitting a user breakpoint or becoming suspended. Depending on the use case,
        this method might be invoked from a Java thread dedicated to this emulated thread.
        """

    def setCounter(self, counter: ghidra.program.model.address.Address):
        """
        Set the thread's program counter without writing to its executor state
        
        :param ghidra.program.model.address.Address counter: the new target address
        
        .. seealso::
        
            | :obj:`.overrideCounter(Address)`
        """

    def setSuspended(self, suspended: typing.Union[jpype.JBoolean, bool]):
        """
        Set the suspension state of the thread's executor
         
         
        
        When :meth:`run() <.run>` is invoked by a dedicated thread, suspending the pcode thread is the most
        reliable way to halt execution. Note the emulator may halt mid instruction. If this is not
        desired, then upon catching the exception, un-suspend the p-code thread and call
        :meth:`finishInstruction() <.finishInstruction>` or :meth:`dropInstruction() <.dropInstruction>`.
        
        :param jpype.JBoolean or bool suspended: true to suspend the machine, false to let it run
        
        .. seealso::
        
            | :obj:`PcodeMachine.setSuspended(boolean)`
        """

    def skipInstruction(self):
        """
        Decode, but skip the next instruction
        """

    def skipPcodeOp(self):
        """
        Skip emulation of a single p-code operation
         
         
        
        If there is no current frame, this behaves as in :meth:`stepPcodeOp() <.stepPcodeOp>`. Otherwise, this
        skips the current pcode op, advancing as if a fall-through op. If no ops remain in the frame,
        this behaves as in :meth:`stepPcodeOp() <.stepPcodeOp>`. Please note to skip an extranal branch, the op
        itself must be skipped. "Skipping" the following op, which disposes the frame, cannot prevent
        the branch.
        """

    @typing.overload
    def stepInstruction(self):
        """
        Step emulation a single instruction
         
         
        
        Note because of the way Ghidra and Sleigh handle delay slots, the execution of an instruction
        with delay slots cannot be separated from the instructions filling those slots. It and its
        slotted instructions are executed in a single "step." However, stepping the individual p-code
        ops is still possible using :meth:`stepPcodeOp() <.stepPcodeOp>`.
        """

    @typing.overload
    def stepInstruction(self, count: typing.Union[jpype.JLong, int]):
        """
        Repeat :meth:`stepInstruction() <.stepInstruction>` count times
        
        :param jpype.JLong or int count: the number of instructions to step
        """

    def stepPatch(self, sleigh: typing.Union[java.lang.String, str]):
        """
        Apply a patch to the emulator
        
        :param java.lang.String or str sleigh: a line of sleigh semantic source to execute (excluding the final semicolon)
        """

    @typing.overload
    def stepPcodeOp(self):
        """
        Step emulation a single p-code operation
         
         
        
        Execution of the current instruction begins if there is no current frame: A new frame is
        constructed and its counter is initialized. If a frame is present, and it has not been
        completed, its next operation is executed and its counter is stepped. If the current frame is
        completed, the machine's program counter is advanced and the current frame is removed.
         
         
        
        Consider the case of a fall-through instruction: The first p-code step decodes the
        instruction and sets up the p-code frame. The second p-code step executes the first p-code op
        of the frame. Each subsequent p-code step executes the next p-code op until no ops remain.
        The final p-code step detects the fall-through result, advances the counter, and disposes the
        frame. The next p-code step is actually the first p-code step of the next instruction.
         
         
        
        Consider the case of a branching instruction: The first p-code step decodes the instruction
        and sets up the p-code frame. The second p-code step executes the first p-code op of the
        frame. Each subsequent p-code step executes the next p-code op until an (external) branch is
        executed. That branch itself sets the program counter appropriately. The final p-code step
        detects the branch result and simply disposes the frame. The next p-code step is actually the
        first p-code step of the next instruction.
         
         
        
        The decode step in both examples is subject to p-code injections. In order to provide the
        most flexibility, there is no enforcement of various emulation state on this method. Expect
        strange behavior for strange call sequences.
         
         
        
        While this method heeds injects, such injects will obscure the p-code of the instruction
        itself. If the inject executes the instruction, the entire instruction will be executed when
        stepping the :meth:`PcodeEmulationLibrary.emu_exec_decoded() <PcodeEmulationLibrary.emu_exec_decoded>` userop, since there is not
        (currently) any way to "step into" a userop.
        """

    @typing.overload
    def stepPcodeOp(self, count: typing.Union[jpype.JLong, int]):
        """
        Repeat :meth:`stepPcodeOp() <.stepPcodeOp>` count times
        
        :param jpype.JLong or int count: the number of p-code operations to step
        """

    @property
    def useropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        ...

    @property
    def machine(self) -> PcodeMachine[T]:
        ...

    @property
    def instruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def executor(self) -> ghidra.pcode.exec_.PcodeExecutor[T]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def context(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def arithmetic(self) -> ghidra.pcode.exec_.PcodeArithmetic[T]:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...

    @property
    def state(self) -> ThreadPcodeExecutorState[T]:
        ...

    @property
    def counter(self) -> ghidra.program.model.address.Address:
        ...

    @counter.setter
    def counter(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def suspended(self) -> jpype.JBoolean:
        ...

    @suspended.setter
    def suspended(self, value: jpype.JBoolean):
        ...

    @property
    def frame(self) -> ghidra.pcode.exec_.PcodeFrame:
        ...


class BytesPcodeThread(ModifiedPcodeThread[jpype.JArray[jpype.JByte]]):
    """
    A simple p-code thread that operates on concrete bytes
    
     
    
    For a complete example of a p-code emulator, see :obj:`PcodeEmulator`. This is the default
    thread for that emulator.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], machine: AbstractPcodeMachine[jpype.JArray[jpype.JByte]]):
        """
        Construct a new thread
        
        :param java.lang.String or str name: the thread's name
        :param AbstractPcodeMachine[jpype.JArray[jpype.JByte]] machine: the machine to which the thread belongs
        
        .. seealso::
        
            | :obj:`PcodeMachine.newThread(String)`
        """


class InstructionDecoder(java.lang.Object):
    """
    A means of decoding machine instructions from the bytes contained in the machine state
    """

    class_: typing.ClassVar[java.lang.Class]

    def branched(self, address: ghidra.program.model.address.Address):
        """
        Inform the decoder that the emulator thread just branched
        
        :param ghidra.program.model.address.Address address:
        """

    def decodeInstruction(self, address: ghidra.program.model.address.Address, context: ghidra.program.model.lang.RegisterValue) -> ghidra.app.util.PseudoInstruction:
        """
        Decode the instruction starting at the given address using the given context
         
         
        
        This method cannot return null. If a decode error occurs, it must throw an exception.
        
        :param ghidra.program.model.address.Address address: the address to start decoding
        :param ghidra.program.model.lang.RegisterValue context: the disassembler/decode context
        :return: the instruction
        :rtype: ghidra.app.util.PseudoInstruction
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language for this decoder
        
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """

    def getLastInstruction(self) -> ghidra.program.model.listing.Instruction:
        """
        Get the last instruction decoded
        
        :return: the instruction
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getLastLengthWithDelays(self) -> int:
        """
        Get the length of the last decoded instruction, including delay slots
        
        :return: the length
        :rtype: int
        """

    @property
    def lastLengthWithDelays(self) -> jpype.JInt:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def lastInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...


class AbstractPcodeMachine(PcodeMachine[T], typing.Generic[T]):
    """
    An abstract implementation of :obj:`PcodeMachine` suitable as a base for most implementations
     
     
    
    A note regarding terminology: A p-code "machine" refers to any p-code-based machine simulator,
    whether or not it operates on abstract or concrete values. The term "emulator" is reserved for
    machines whose values always include a concrete piece. That piece doesn't necessarily have to be
    a (derivative of) :obj:`BytesPcodeExecutorStatePiece`, but it usually is. To be called an
    "emulator" implies that :meth:`PcodeArithmetic.toConcrete(Object, Purpose) <PcodeArithmetic.toConcrete>` never throws
    :obj:`ConcretionError` for any value in its state.
     
     
    
    For a complete example of a p-code emulator, see :obj:`PcodeEmulator`. For an alternative
    implementation incorporating an abstract piece, see the Taint Analyzer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a p-code machine with the given language and arithmetic
        
        :param ghidra.program.model.lang.Language language: the processor language to be emulated
        """


class PcodeEmulator(AbstractPcodeMachine[jpype.JArray[jpype.JByte]]):
    """
    A p-code machine which executes on concrete bytes and incorporates per-architecture state
    modifiers
     
     
    
    This is a simple concrete bytes emulator suitable for unit testing and scripting. More complex
    use cases likely benefit by extending this or one of its super types. Likewise, the factory
    methods will likely instantiate classes which extend the default or one of its super types. When
    creating such an extension, it helps to refer to this default implementation to understand the
    overall architecture of an emulator. The emulator was designed using hierarchies of abstract
    classes each extension incorporating more complexity (and restrictions) finally culminating here.
    Every class should be extensible and have overridable factory methods so that those extensions
    can be incorporated into even more capable emulators. Furthermore, many components, e.g.,
    :obj:`PcodeExecutorState` were designed with composition in mind. Referring to examples, it is
    straightforward to extend the emulator via composition. Consider using :obj:`AuxPcodeEmulator`
    or one of its derivatives to create a concrete-plus-auxiliary style emulator.
     
     
    emulator      : :obj:`PcodeMachine```<T>``
    - language     : :obj:`SleighLanguage`
    - arithmetic   : :obj:`PcodeArithmetic```<T>``
    - sharedState  : :obj:`PcodeExecutorState```<T>``
    - library      : :obj:`PcodeUseropLibrary```<T>``
    - injects      : ``Map<Address,``:obj:`PcodeProgram```>``
    - threads      : ``List<``:obj:`PcodeThread```<T>>``
        - [0]          : :obj:`PcodeThread```<T>``
        - decoder      : :obj:`InstructionDecoder`
        - executor     : :obj:`PcodeExecutor```<T>``
        - frame        : :obj:`PcodeFrame`
        - localState   : :obj:`PcodeExecutorState```<T>``
        - library      : :obj:`PcodeUseropLibrary```<T>``
        - injects      : ``Map<Address,``:obj:`PcodeProgram```>``
        - [1] ...
     
     
     
    
    The root object of an emulator is the :obj:`PcodeEmulator`, usually ascribed the type
    :obj:`PcodeMachine`. At the very least, it must know the language of the processor it emulates.
    It then derives appropriate arithmetic definitions, a shared (memory) state, and a shared userop
    library. Initially, the machine has no threads. For many use cases creating a single
    :obj:`PcodeThread` suffices; however, this default implementation models multi-threaded
    execution "out of the box." Upon creation, each thread is assigned a local (register) state, and
    a userop library for controlling that particular thread. The thread's full state and userop
    library are composed from the machine's shared components and that thread's particular
    components. For state, the composition directs memory accesses to the machine's state and
    register accesses to the thread's state. (Accesses to the "unique" space are also directed to the
    thread's state.) This properly emulates the thread semantics of most platforms. For the userop
    library, composition is achieved via :meth:`PcodeUseropLibrary.compose(PcodeUseropLibrary) <PcodeUseropLibrary.compose>`.
    Thus, each invocation is directed to the library that exports the invoked userop.
     
     
    
    Each thread creates an :obj:`InstructionDecoder` and a :obj:`PcodeExecutor`, providing the
    kernel of p-code emulation for that thread. That executor is bound to the thread's composed
    state, and to the machine's arithmetic. Together, the state and the arithmetic "define" all the
    p-code ops that the executor can invoke. Unsurprisingly, arithmetic operations are delegated to
    the :obj:`PcodeArithmetic`, and state operations (including memory operations and temporary
    variable access) are delegated to the :obj:`PcodeExecutorState`. The core execution loop easily
    follows: 1) decode the current instruction, 2) generate that instruction's p-code, 3) feed the
    code to the executor, 4) resolve the outcome and advance the program counter, then 5) repeat. So
    long as the arithmetic and state objects agree in type, a p-code machine can be readily
    implemented to manipulate values of that type.
     
     
    
    This concrete emulator chooses a :obj:`BytesPcodeArithmetic` based on the endianness of the
    target language. Its threads are :obj:`BytesPcodeThread`. The shared and thread-local states are
    all :obj:`BytesPcodeExecutorState`. That pieces of that state can be extended to read through to
    some other backing object. For example, the memory state could read through to an imported
    program image, which allows the emulator's memory to be loaded lazily.
     
     
    
    The default userop library is empty. For many use cases, it will be necessary to override
    :meth:`createUseropLibrary() <.createUseropLibrary>` if only to implement the language-defined userops. If needed,
    simulation of the host operating system is typically achieved by implementing the ``syscall``
    userop. The fidelity of that simulation depends on the use case. See the SystemEmulation module
    to see what simulators are available "out of the box."
     
     
    
    Alternatively, if the target program never invokes system calls directly, but rather via
    system-provided APIs, then it may suffice to stub out those imports. Typically, Ghidra will place
    a "thunk" at each import address with the name of the import. Stubbing an import is accomplished
    by injecting p-code at the import address. See :meth:`PcodeMachine.inject(Address, String) <PcodeMachine.inject>`. The
    inject will need to replicate the semantics of that call to the desired fidelity.
    **IMPORTANT:** The inject must also return control to the calling function, usually by
    replicating the conventions of the target platform.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a new concrete emulator
         
         
        
        Yes, it is customary to invoke this constructor directly.
        
        :param ghidra.program.model.lang.Language language: the language of the target processor
        """


class SleighInstructionDecoder(InstructionDecoder):
    """
    The default instruction decoder, based on Sleigh
     
     
    
    This simply uses a :obj:`Disassembler` on the machine's memory state.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, state: ghidra.pcode.exec_.PcodeExecutorState[typing.Any]):
        """
        Construct a Sleigh instruction decoder
        
        :param ghidra.program.model.lang.Language language: the language to decoder
        :param ghidra.pcode.exec_.PcodeExecutorState[typing.Any] state: the state containing the target program, probably the shared state of the p-code
                    machine. It must be possible to obtain concrete buffers on this state.
        
        .. seealso::
        
            | :obj:`DefaultPcodeThread.createInstructionDecoder(PcodeExecutorState)`
        
            | :obj:`DefaultPcodeThread.createInstructionDecoder(PcodeExecutorState)`
        """


class ModifiedPcodeThread(DefaultPcodeThread[T], typing.Generic[T]):
    """
    A p-code thread which incorporates per-architecture state modifiers
     
     
    
    All machines that include a concrete state piece, i.e., all emulators, should use threads derived
    from this class. This implementation assumes that the modified state can be concretized. This
    doesn't necessarily require the machine to be a concrete emulator, but an abstract machine must
    avoid or handle :obj:`ConcretionError`s arising from state modifiers.
     
     
    
    For a complete example of a p-code emulator, see :obj:`PcodeEmulator`.
     
     
    
    TODO: "State modifiers" are a feature of the older :obj:`Emulator`. They are crudely
    incorporated into threads extended from this abstract class, so that they do not yet need to be
    ported to this emulator.
    """

    @typing.type_check_only
    class GlueEmulate(ghidra.pcode.emulate.Emulate):
        """
        Glue for incorporating state modifiers
         
         
        
        This allows the modifiers to change the context and counter of the thread.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, s: ghidra.pcode.memstate.MemoryState, b: ghidra.pcode.emulate.BreakTable):
            ...


    @typing.type_check_only
    class ModifierUseropLibrary(ghidra.pcode.exec_.PcodeUseropLibrary[T]):
        """
        For incorporating the state modifier's userop behaviors
        """

        @typing.type_check_only
        class ModifierUseropDefinition(ghidra.pcode.exec_.PcodeUseropLibrary.PcodeUseropDefinition[T]):
            """
            A wrapper around :obj:`OpBehaviorOther`
            """

            class_: typing.ClassVar[java.lang.Class]

            def __init__(self, name: typing.Union[java.lang.String, str], behavior: ghidra.pcode.emulate.callother.OpBehaviorOther):
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], machine: AbstractPcodeMachine[T]):
        """
        Construct a new thread with the given name belonging to the given machine
        
        :param java.lang.String or str name: the name of the new thread
        :param AbstractPcodeMachine[T] machine: the machine to which the new thread belongs
        
        .. seealso::
        
            | :obj:`PcodeMachine.newThread(String)`
        """


class SparseAddressRangeMap(java.lang.Object, typing.Generic[V]):

    @typing.type_check_only
    class Space(java.lang.Object, typing.Generic[V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Page(java.lang.Object, typing.Generic[V]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    PAGE_BITS: typing.Final = 12
    PAGE_MASK: typing.Final = -4096
    OFF_MASK: typing.Final = 4095

    def __init__(self):
        ...

    def clear(self):
        ...

    def hasEntry(self, address: ghidra.program.model.address.Address, predicate: java.util.function.Predicate[V]) -> bool:
        ...

    def isEmpty(self) -> bool:
        ...

    def put(self, range: ghidra.program.model.address.AddressRange, value: V) -> java.util.Map.Entry[ghidra.program.model.address.AddressRange, V]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class PcodeStateInitializer(ghidra.util.classfinder.ExtensionPoint):
    """
    An extension for preparing execution state for sleigh emulation
     
     
    
    As much as possible, it's highly-recommended to use Sleigh execution to perform any
    modifications. This will help it remain agnostic to various state types.
     
     
    
    TODO: Implement annotation-based :meth:`isApplicable(Language) <.isApplicable>`?
    """

    class_: typing.ClassVar[java.lang.Class]

    def initializeMachine(self, machine: PcodeMachine[T]):
        """
        The machine's memory state has just been initialized, and additional initialization is needed
        for Sleigh execution
         
         
        
        There's probably not much preparation of memory
        
        :param T: the type of values in the machine state:param PcodeMachine[T] machine: the newly-initialized machine
        """

    def initializeThread(self, thread: PcodeThread[T]):
        """
        The thread's register state has just been initialized, and additional initialization is
        needed for Sleigh execution
         
         
        
        Initialization generally consists of setting "virtual" registers using data from the real
        ones. Virtual registers are those specified in the Sleigh, but which don't actually exist on
        the target processor. Often, they exist to simplify static analysis, but unfortunately cause
        a minor headache for dynamic execution.
        
        :param T: the type of values in the machine state:param PcodeThread[T] thread: the newly-initialized thread
        """

    def isApplicable(self, language: ghidra.program.model.lang.Language) -> bool:
        """
        Check if this initializer applies to the given language
        
        :param ghidra.program.model.lang.Language language: the language to check
        :return: true if it applies, false otherwise
        :rtype: bool
        """

    @property
    def applicable(self) -> jpype.JBoolean:
        ...


class PcodeMachine(java.lang.Object, typing.Generic[T]):
    """
    A machine which execute p-code on state of an abstract type
    """

    class SwiMode(java.lang.Enum[PcodeMachine.SwiMode]):
        """
        Specifies whether or not to interrupt on p-code breakpoints
        """

        class_: typing.ClassVar[java.lang.Class]
        ACTIVE: typing.Final[PcodeMachine.SwiMode]
        """
        Heed :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>` calls
        """

        IGNORE_ALL: typing.Final[PcodeMachine.SwiMode]
        """
        Ignore all :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>` calls
        """

        IGNORE_STEP: typing.Final[PcodeMachine.SwiMode]
        """
        Ignore :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>` calls for one p-code step
         
         
        
        The mode is reset to :obj:`.ACTIVE` after one p-code step, whether or not that step
        causes an SWI.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PcodeMachine.SwiMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[PcodeMachine.SwiMode]:
            ...


    class AccessKind(java.lang.Enum[PcodeMachine.AccessKind]):
        """
        The kind of access breakpoint
        """

        class_: typing.ClassVar[java.lang.Class]
        R: typing.Final[PcodeMachine.AccessKind]
        """
        A read access breakpoint
        """

        W: typing.Final[PcodeMachine.AccessKind]
        """
        A write access breakpoint
        """

        RW: typing.Final[PcodeMachine.AccessKind]
        """
        A read/write access breakpoint
        """


        def trapsRead(self) -> bool:
            """
            Check if this kind of breakpoint should trap a read, i.e., :obj:`PcodeOp.LOAD`
            
            :return: true to interrupt
            :rtype: bool
            """

        def trapsWrite(self) -> bool:
            """
            Check if this kind of breakpoint should trap a write, i.e., :obj:`PcodeOp.STORE`
            
            :return: true to interrupt
            :rtype: bool
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PcodeMachine.AccessKind:
            ...

        @staticmethod
        def values() -> jpype.JArray[PcodeMachine.AccessKind]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addAccessBreakpoint(self, range: ghidra.program.model.address.AddressRange, kind: PcodeMachine.AccessKind):
        """
        Add an access breakpoint over the given range
         
         
        
        Access breakpoints are implemented out of band, without modification to the emulated image.
        The breakpoints are only effective for p-code :obj:`PcodeOp.LOAD` and :obj:`PcodeOp.STORE`
        operations with concrete offsets. Thus, an operation that refers directly to a memory
        address, e.g., a memory-mapped register, will not be trapped. Similarly, access breakpoints
        on registers or unique variables will not work. Access to an abstract offset that cannot be
        made concrete, i.e., via :meth:`PcodeArithmetic.toConcrete(Object, Purpose) <PcodeArithmetic.toConcrete>` cannot be
        trapped. To interrupt on direct and/or abstract accesses, consider wrapping the relevant
        state and/or overriding :meth:`PcodeExecutorStatePiece.getVar(Varnode, Reason) <PcodeExecutorStatePiece.getVar>` and related.
        For accesses to abstract offsets, consider overriding
        :meth:`AbstractPcodeMachine.checkLoad(AddressSpace, Object, int) <AbstractPcodeMachine.checkLoad>` and/or
        :meth:`AbstractPcodeMachine.checkStore(AddressSpace, Object, int) <AbstractPcodeMachine.checkStore>` instead.
         
         
        
        A breakpoint's range cannot cross more than one page boundary. Pages are 4096 bytes each.
        This allows implementations to optimize checking for breakpoints. If a breakpoint does not
        follow this rule, the behavior is undefined. Breakpoints may overlap, but currently no
        indication is given as to which breakpoint interrupted emulation.
         
         
        
        No synchronization is provided on the internal breakpoint storage. Clients should ensure the
        machine is not executing when adding breakpoints. Additionally, the client must ensure only
        one thread is adding breakpoints to the machine at a time.
        
        :param ghidra.program.model.address.AddressRange range: the address range to trap
        :param PcodeMachine.AccessKind kind: the kind of access to trap
        """

    def addBreakpoint(self, address: ghidra.program.model.address.Address, sleighCondition: typing.Union[java.lang.String, str]):
        """
        Add a conditional execution breakpoint at the given address
         
         
        
        Breakpoints are implemented at the p-code level using an inject, without modification to the
        emulated image. As such, it cannot coexist with another inject. A client needing to break
        during an inject must use :meth:`PcodeEmulationLibrary.emu_swi() <PcodeEmulationLibrary.emu_swi>` in the injected Sleigh.
         
         
        
        No synchronization is provided on the internal breakpoint storage. Clients should ensure the
        machine is not executing when adding breakpoints. Additionally, the client must ensure only
        one thread is adding breakpoints to the machine at a time.
        
        :param ghidra.program.model.address.Address address: the address at which to break
        :param java.lang.String or str sleighCondition: a Sleigh expression which controls the breakpoint
        """

    def clearAccessBreakpoints(self):
        """
        Remove all access breakpoints from this machine
        """

    def clearAllInjects(self):
        """
        Remove all injects from this machine
         
         
        
        This will clear execution breakpoints, but not access breakpoints. See
        :meth:`clearAccessBreakpoints() <.clearAccessBreakpoints>`.
        """

    def clearInject(self, address: ghidra.program.model.address.Address):
        """
        Remove the inject, if present, at the given address
        
        :param ghidra.program.model.address.Address address: the address to clear
        """

    def compileSleigh(self, sourceName: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str]) -> ghidra.pcode.exec_.PcodeProgram:
        """
        Compile the given Sleigh code for execution by a thread of this machine
         
         
        
        This links in the userop library given at construction time and those defining the emulation
        userops, e.g., ``emu_swi``.
        
        :param java.lang.String or str sourceName: a user-defined source name for the resulting "program"
        :param java.lang.String or str source: the Sleigh source
        :return: the compiled program
        :rtype: ghidra.pcode.exec_.PcodeProgram
        """

    def getAllThreads(self) -> java.util.Collection[PcodeThread[T]]:
        """
        Collect all threads present in the machine
        
        :return: the collection of threads
        :rtype: java.util.Collection[PcodeThread[T]]
        """

    def getArithmetic(self) -> ghidra.pcode.exec_.PcodeArithmetic[T]:
        """
        Get the arithmetic applied by the machine
        
        :return: the arithmetic
        :rtype: ghidra.pcode.exec_.PcodeArithmetic[T]
        """

    def getInject(self, address: ghidra.program.model.address.Address) -> ghidra.pcode.exec_.PcodeProgram:
        """
        Check for a p-code injection (override) at the given address
        
        :param ghidra.program.model.address.Address address: the address, usually the program counter
        :return: the injected program, most likely ``null``
        :rtype: ghidra.pcode.exec_.PcodeProgram
        """

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        """
        Get the machine's Sleigh language (processor model)
        
        :return: the language
        :rtype: ghidra.app.plugin.processors.sleigh.SleighLanguage
        """

    def getSharedState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        """
        Get the machine's shared (memory) state
         
         
        
        The returned state will may throw :obj:`IllegalArgumentException` if the client requests
        register values of it. This state is shared among all threads in this machine.
        
        :return: the memory state
        :rtype: ghidra.pcode.exec_.PcodeExecutorState[T]
        """

    def getSoftwareInterruptMode(self) -> PcodeMachine.SwiMode:
        """
        Get the current software interrupt mode
        
        :return: the mode
        :rtype: PcodeMachine.SwiMode
        """

    def getStubUseropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        """
        Get a userop library which at least declares all userops available in each thread userop
        library.
         
         
        
        Thread userop libraries may have more userops than are defined in the machine's userop
        library. However, to compile Sleigh programs linked to thread libraries, the thread's userops
        must be known to the compiler. The stub library will name all userops common among the
        threads, even if their definitions vary. **WARNING:** The stub library is not required to
        provide implementations of the userops. Often they will throw exceptions, so do not attempt
        to use the returned library in an executor.
        
        :return: the stub library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[T]
        """

    def getThread(self, name: typing.Union[java.lang.String, str], createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> PcodeThread[T]:
        """
        Get the thread, if present, with the given name
        
        :param java.lang.String or str name: the name
        :param jpype.JBoolean or bool createIfAbsent: create a new thread if the thread does not already exist
        :return: the thread, or ``null`` if absent and not created
        :rtype: PcodeThread[T]
        """

    def getUseropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        """
        Get the userop library common to all threads in the machine.
         
         
        
        Note that threads may have larger libraries, but each contains all the userops in this
        library.
        
        :return: the userop library
        :rtype: ghidra.pcode.exec_.PcodeUseropLibrary[T]
        """

    def inject(self, address: ghidra.program.model.address.Address, source: typing.Union[java.lang.String, str]):
        """
        Override the p-code at the given address with the given Sleigh source
         
         
        
        This will attempt to compile the given source against this machine's userop library and then
        inject it at the given address. The resulting p-code *replaces* that which would be
        executed by decoding the instruction at the given address. That means the machine will not
        decode, nor advance its counter, unless the Sleigh causes it. In most cases, the Sleigh will
        call :meth:`PcodeEmulationLibrary.emu_exec_decoded() <PcodeEmulationLibrary.emu_exec_decoded>` to cause the machine to decode and
        execute the overridden instruction.
         
         
        
        Each address can have at most a single inject. If there is already one present, it is
        replaced and the old inject completely forgotten. The injector does not support chaining or
        double-wrapping, etc.
         
         
        
        No synchronization is provided on the internal injection storage. Clients should ensure the
        machine is not executing when injecting p-code. Additionally, the client must ensure only one
        thread is injecting p-code to the machine at a time.
        
        :param ghidra.program.model.address.Address address: the address to inject at
        :param java.lang.String or str source: the Sleigh source to compile and inject
        """

    def isSuspended(self) -> bool:
        """
        Check the suspension state of the machine
        
        :return: true if suspended
        :rtype: bool
        
        .. seealso::
        
            | :obj:`PcodeThread.isSuspended()`
        """

    @typing.overload
    def newThread(self) -> PcodeThread[T]:
        """
        Create a new thread with a default name in this machine
        
        :return: the new thread
        :rtype: PcodeThread[T]
        """

    @typing.overload
    def newThread(self, name: typing.Union[java.lang.String, str]) -> PcodeThread[T]:
        """
        Create a new thread with the given name in this machine
        
        :param java.lang.String or str name: the name
        :return: the new thread
        :rtype: PcodeThread[T]
        """

    def setSoftwareInterruptMode(self, mode: PcodeMachine.SwiMode):
        """
        Change the efficacy of p-code breakpoints
         
         
        
        This is used to prevent breakpoints from interrupting at inappropriate times, e.g., upon
        continuing from a breakpoint.
        
        :param PcodeMachine.SwiMode mode: the new mode
        """

    def setSuspended(self, suspended: typing.Union[jpype.JBoolean, bool]):
        """
        Set the suspension state of the machine
         
         
        
        This does not simply suspend all threads, but sets a machine-wide flag. A thread is suspended
        if either the thread's flag is set, or the machine's flag is set.
        
        :param jpype.JBoolean or bool suspended: true to suspend the machine, false to let it run
        
        .. seealso::
        
            | :obj:`PcodeThread.setSuspended(boolean)`
        """

    @property
    def useropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        ...

    @property
    def stubUseropLibrary(self) -> ghidra.pcode.exec_.PcodeUseropLibrary[T]:
        ...

    @property
    def allThreads(self) -> java.util.Collection[PcodeThread[T]]:
        ...

    @property
    def softwareInterruptMode(self) -> PcodeMachine.SwiMode:
        ...

    @softwareInterruptMode.setter
    def softwareInterruptMode(self, value: PcodeMachine.SwiMode):
        ...

    @property
    def sharedState(self) -> ghidra.pcode.exec_.PcodeExecutorState[T]:
        ...

    @property
    def arithmetic(self) -> ghidra.pcode.exec_.PcodeArithmetic[T]:
        ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage:
        ...

    @property
    def suspended(self) -> jpype.JBoolean:
        ...

    @suspended.setter
    def suspended(self, value: jpype.JBoolean):
        ...


class DefaultPcodeThread(PcodeThread[T], typing.Generic[T]):
    """
    The default implementation of :obj:`PcodeThread` suitable for most applications
     
     
    
    When emulating on concrete state, consider using :obj:`ModifiedPcodeThread`, so that state
    modifiers from the older :obj:`Emulator` are incorporated. In either case, it may be worthwhile
    to examine existing state modifiers to ensure they are appropriately represented in any abstract
    state. It may be necessary to port them.
     
     
    
    This class implements the control-flow logic of the target machine, cooperating with the p-code
    program flow implemented by the :obj:`PcodeExecutor`. This implementation exists primarily in
    :meth:`beginInstructionOrInject() <.beginInstructionOrInject>` and :meth:`advanceAfterFinished() <.advanceAfterFinished>`.
    """

    class PcodeEmulationLibrary(ghidra.pcode.exec_.AnnotatedPcodeUseropLibrary[T], typing.Generic[T]):
        """
        A userop library exporting some methods for emulated thread control
        
         
        
        TODO: Since p-code userops can now receive the executor, it may be better to receive it, cast
        it, and obtain the thread, rather than binding a library to each thread.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, thread: DefaultPcodeThread[T]):
            """
            Construct a library to control the given thread
            
            :param DefaultPcodeThread[T] thread: the thread
            """

        def emu_exec_decoded(self):
            """
            Execute the actual machine instruction at the current program counter
             
             
            
            Because "injects" override the machine instruction, injects which need to defer to the
            machine instruction must invoke this userop.
            
            
            .. seealso::
            
                | :obj:`.emu_skip_decoded()`
            """

        def emu_injection_err(self):
            """
            Notify the client of a failed Sleigh inject compilation.
             
             
            
            To avoid pestering the client during emulator set-up, a service may effectively defer
            notifying the user of Sleigh compilation errors by replacing the erroneous injects with
            calls to this p-code op. Then, only if and when an erroneous inject is encountered will
            the client be notified.
            """

        def emu_skip_decoded(self):
            """
            Advance the program counter beyond the current machine instruction
             
             
            
            Because "injects" override the machine instruction, they must specify the effect on the
            program counter, lest the thread become caught in an infinite loop on the inject. To
            emulate fall-through without executing the machine instruction, the inject must invoke
            this userop.
            
            
            .. seealso::
            
                | :obj:`.emu_exec_decoded()`
            """

        def emu_swi(self):
            """
            Interrupt execution
             
             
            
            This immediately throws an :obj:`InterruptPcodeExecutionException`. To implement
            out-of-band breakpoints, inject an invocation of this userop at the desired address.
            
            
            .. seealso::
            
                | :obj:`PcodeMachine.addBreakpoint(Address, String)`
            """


    class PcodeThreadExecutor(ghidra.pcode.exec_.PcodeExecutor[T], typing.Generic[T]):
        """
        An executor for the p-code thread
         
         
        
        This executor checks for thread suspension and updates the program counter register upon
        execution of (external) branches.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, thread: DefaultPcodeThread[T]):
            """
            Construct the executor
            
            :param DefaultPcodeThread[T] thread: the thread this executor supports
            
            .. seealso::
            
                | :obj:`DefaultPcodeThread.createExecutor()`
            """

        def getThread(self) -> DefaultPcodeThread[T]:
            """
            Get the thread owning this executor
            
            :return: the thread
            :rtype: DefaultPcodeThread[T]
            """

        @property
        def thread(self) -> DefaultPcodeThread[T]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], machine: AbstractPcodeMachine[T]):
        """
        Construct a new thread
        
        :param java.lang.String or str name: the name of the thread
        :param AbstractPcodeMachine[T] machine: the machine containing the thread
        
        .. seealso::
        
            | :obj:`AbstractPcodeMachine.createThread(String)`
        """

    @staticmethod
    def getContextAfterCommits(instruction: ghidra.program.model.listing.Instruction, counter: typing.Union[jpype.JLong, int]) -> ghidra.program.model.lang.RegisterValue:
        ...



__all__ = ["ThreadPcodeExecutorState", "PcodeThread", "BytesPcodeThread", "InstructionDecoder", "AbstractPcodeMachine", "PcodeEmulator", "SleighInstructionDecoder", "ModifiedPcodeThread", "SparseAddressRangeMap", "PcodeStateInitializer", "PcodeMachine", "DefaultPcodeThread"]
