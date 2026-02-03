from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pcode.emu
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class SkipStep(AbstractStep):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, threadKey: typing.Union[jpype.JLong, int], tickCount: typing.Union[jpype.JLong, int]):
        """
        Construct a skip step for the given thread with the given tick count
        
        :param jpype.JLong or int threadKey: the key of the thread in the trace, -1 for the "last thread"
        :param jpype.JLong or int tickCount: the number of ticks to skip on the thread
        """

    @staticmethod
    def parse(threadKey: typing.Union[jpype.JLong, int], stepSpec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> SkipStep:
        ...


class TickStep(AbstractStep):
    """
    A step of a given thread in a schedule: repeating some number of ticks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, threadKey: typing.Union[jpype.JLong, int], tickCount: typing.Union[jpype.JLong, int]):
        """
        Construct a tick step for the given thread with the given tick count
        
        :param jpype.JLong or int threadKey: the key of the thread in the trace, -1 for the "last thread"
        :param jpype.JLong or int tickCount: the number of ticks to step on the thread
        """

    @staticmethod
    def parse(threadKey: typing.Union[jpype.JLong, int], stepSpec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> TickStep:
        ...


class PatchStep(Step):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, threadKey: typing.Union[jpype.JLong, int], sleigh: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def generateSleigh(language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> java.util.List[java.lang.String]:
        """
        Generate multiple lines of Sleigh, all to set a single variable
        
        :param ghidra.program.model.lang.Language language: the target language
        :param ghidra.program.model.address.Address address: the (start) address of the variable
        :param jpype.JArray[jpype.JByte] data: the bytes to write to the variable
        :return: the lines of Sleigh code
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    @typing.overload
    def generateSleighLine(language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte], length: typing.Union[jpype.JInt, int]) -> str:
        """
        Generate a single line of Sleigh
         
         
        
        Note that when length is greater than 8, this will generate constants which are too large for
        the Java implementation of Sleigh. Use :meth:`generateSleigh(Language, Address, byte[]) <.generateSleigh>`
        instead to write the variable in chunks.
        
        :param ghidra.program.model.lang.Language language: the target language
        :param ghidra.program.model.address.Address address: the (start) address of the variable
        :param jpype.JArray[jpype.JByte] data: the bytes to write to the variable
        :param jpype.JInt or int length: the length of the variable
        :return: the Sleigh code
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def generateSleighLine(language: ghidra.program.model.lang.Language, address: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]) -> str:
        """
        Generate a single line of Sleigh
        
        :param ghidra.program.model.lang.Language language: the target language
        :param ghidra.program.model.address.Address address: the (start) address of the variable
        :param jpype.JArray[jpype.JByte] data: the bytes to write to the variable
        :return: the Sleigh code
        :rtype: str
        
        .. seealso::
        
            | :obj:`.generateSleighLine(Language, Address, byte[], int)`
        """

    @staticmethod
    def parse(threadKey: typing.Union[jpype.JLong, int], stepSpec: typing.Union[java.lang.String, str]) -> PatchStep:
        ...


class CompareResult(java.lang.Enum[CompareResult]):
    """
    The result of a rich comparison of two schedules (or parts thereof)
    """

    class_: typing.ClassVar[java.lang.Class]
    UNREL_LT: typing.Final[CompareResult]
    REL_LT: typing.Final[CompareResult]
    EQUALS: typing.Final[CompareResult]
    REL_GT: typing.Final[CompareResult]
    UNREL_GT: typing.Final[CompareResult]
    compareTo: typing.Final[jpype.JInt]
    related: typing.Final[jpype.JBoolean]

    @staticmethod
    def related(compareTo: typing.Union[jpype.JInt, int]) -> CompareResult:
        """
        Enrich the result of :meth:`Comparable.compareTo(Object) <Comparable.compareTo>`, given that the two are related
        
        :param jpype.JInt or int compareTo: the return from ``compareTo``
        :return: the rich result
        :rtype: CompareResult
        """

    @staticmethod
    @typing.overload
    def unrelated(compareTo: typing.Union[jpype.JInt, int]) -> CompareResult:
        """
        Enrich the result of :meth:`Comparable.compareTo(Object) <Comparable.compareTo>`, given that the two are not
        related
        
        :param jpype.JInt or int compareTo: the return from ``compareTo``
        :return: the rich result
        :rtype: CompareResult
        """

    @staticmethod
    @typing.overload
    def unrelated(result: CompareResult) -> CompareResult:
        """
        Maintain sort order, but specify the two are not in fact related
        
        :param CompareResult result: the result of another (usually recursive) rich comparison
        :return: the modified result
        :rtype: CompareResult
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> CompareResult:
        ...

    @staticmethod
    def values() -> jpype.JArray[CompareResult]:
        ...


class Sequence(java.lang.Comparable[Sequence]):
    """
    A sequence of thread steps, each repeated some number of times
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def advance(self, step: Step):
        """
        Append the given step to this sequence
        
        :param Step step: the step to append
        """

    @typing.overload
    def advance(self, seq: Sequence):
        """
        Append the given sequence to this one
        
        :param Sequence seq: the sequence to append
        """

    @staticmethod
    def catenate(a: Sequence, b: Sequence) -> Sequence:
        """
        Construct (and normalize) a sequence formed by the steps in a followed by the steps in b
        
        :param Sequence a: the first sequence
        :param Sequence b: the second (appended) sequence
        :return: the resulting sequence
        :rtype: Sequence
        """

    def coalescePatches(self, language: ghidra.program.model.lang.Language):
        ...

    def collectThreads(self, into: java.util.Set[ghidra.trace.model.thread.TraceThread], trace: ghidra.trace.model.Trace, eventThread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        """
        Collect all the threads involved in this sequence
        
        :param java.util.Set[ghidra.trace.model.thread.TraceThread] into: a set to collect the threads
        :param ghidra.trace.model.Trace trace: the trace whose threads to collect
        :param ghidra.trace.model.thread.TraceThread eventThread: the default starting thread
        :return: the last thread named in the sequence
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def compareSeq(self, that: Sequence) -> CompareResult:
        """
        Richly compare two sequences
         
         
        
        The result indicates not only which is "less" or "greater" than the other, but also indicates
        whether the two are "related." Two sequences are considered related if one is the prefix to
        the other. More precisely, they are related if it's possible to transform one into the other
        solely by truncation (rewind) or solely by concatenation (advance). When related, the prefix
        is considered "less than" the other. Equal sequences are trivially related.
         
         
        
        Examples:
         
        * ``""`` is related to and less than ``"10"``
        * ``"10"`` is related and equal to ``"10"``
        * ``"10"`` is related to and less than ``"11"``
        * ``"t1-5"`` is related to and less than ``"t1-5;t2-4"``
        * ``"t1-5"`` is un-related to and less than ``"t1-4;t2-4"``
        
         
         
        
        The :meth:`compareTo(Sequence) <.compareTo>` implementation defers to this method. Thus, in a sorted set
        of step sequences, the floor of a given sequence is will be the longest prefix in that set to
        the given sequence, assuming such a prefix is present.
        
        :param Sequence that: the object of comparison (this being the subject)
        :return: a result describing the relationship from subject to object
        :rtype: CompareResult
        """

    def count(self) -> int:
        ...

    def differsOnlyByPatch(self, that: Sequence) -> bool:
        ...

    def dropLast(self) -> Sequence:
        """
        Drop the last step from this sequence
        
        :return: the sequence with the last step removed
        :rtype: Sequence
        """

    def execute(self, trace: ghidra.trace.model.Trace, eventThread: ghidra.trace.model.thread.TraceThread, machine: ghidra.pcode.emu.PcodeMachine[typing.Any], stepper: Stepper, monitor: ghidra.util.task.TaskMonitor) -> ghidra.trace.model.thread.TraceThread:
        """
        Execute this sequence upon the given machine
         
         
        
        Threads are retrieved from the database by key, then created in the machine (if not already
        present) named by :meth:`TraceThread.getPath() <TraceThread.getPath>`. The caller should ensure the machine's state
        is bound to the given trace.
        
        :param ghidra.trace.model.Trace trace: the trace to which the machine is bound
        :param ghidra.trace.model.thread.TraceThread eventThread: the thread for the first step, if it applies to the "last thread"
        :param ghidra.pcode.emu.PcodeMachine[typing.Any] machine: the machine to step, or null to validate the sequence
        :param Stepper stepper: the actions to step each thread
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation and progress reports
        :return: the last trace thread stepped during execution
        :rtype: ghidra.trace.model.thread.TraceThread
        :raises CancelledException: if execution is cancelled
        """

    def getLastThreadKey(self) -> int:
        """
        Get the key of the last thread stepped
        
        :return: the key, or -1 if no step in the sequence specifies a thread
        :rtype: int
        """

    def getSteps(self) -> java.util.List[Step]:
        """
        Obtain a clone of the steps
         
         
        
        Modifications to the returned steps have no effect on this sequence.
        
        :return: the cloned steps
        :rtype: java.util.List[Step]
        """

    def isNop(self) -> bool:
        """
        Check if this sequence represents any actions
        
        :return: true if the sequence is empty, false if not
        :rtype: bool
        """

    def last(self) -> Step:
        """
        :return: the last step
        :rtype: Step
        """

    @staticmethod
    @typing.overload
    def of(*steps: Step) -> Sequence:
        """
        Construct (and normalize) a sequence of the specified steps
        
        :param jpype.JArray[Step] steps: the desired steps in order
        :return: the resulting sequence
        :rtype: Sequence
        """

    @staticmethod
    @typing.overload
    def of(steps: java.util.List[Step]) -> Sequence:
        """
        Construct (and normalize) a sequence of the specified steps
        
        :param java.util.List[Step] steps: the desired steps in order
        :return: the resulting sequence
        :rtype: Sequence
        """

    @staticmethod
    def parse(seqSpec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> Sequence:
        """
        Parse (and normalize) a sequence of steps
         
         
        
        This takes a semicolon-separated list of steps in the form specified by
        :meth:`Step.parse(String, TimeRadix) <Step.parse>`. Each step may or may not specify a thread, but it's
        uncommon for any but the first step to omit the thread. The sequence is normalized as it is
        parsed, so any step after the first that omits a thread will be combined with the previous
        step. When the first step applies to the "last thread," it typically means the "event thread"
        of the source trace snapshot.
        
        :param java.lang.String or str seqSpec: the string specification of the sequence
        :param TraceSchedule.TimeRadix radix: the radix
        :return: the parsed sequence
        :rtype: Sequence
        :raises IllegalArgumentException: if the specification is of the wrong form
        """

    def relativize(self, prefix: Sequence) -> Sequence:
        """
        Compute the sequence which concatenated to the given prefix would result in this sequence
         
         
        
        The returned step sequence should not be manipulated, since it may just be this sequence.
        
        :param Sequence prefix: the prefix
        :return: the relative sequence from prefix to this
        :rtype: Sequence
        :raises IllegalArgumentException: if prefix is not a prefix of this sequence
        
        .. seealso::
        
            | :obj:`.compareSeq(Sequence)`
        """

    def rewind(self, count: typing.Union[jpype.JLong, int]) -> int:
        """
        Rewind this sequence the given step count
         
         
        
        This modifies the sequence in place, removing the given count from the end of the sequence.
        Any step whose count is reduced to 0 as a result of rewinding is removed entirely from the
        sequence. Note that each sleigh step (modification) counts as one step when rewinding.
        
        :param jpype.JLong or int count: the step count to rewind
        :return: if count exceeds the steps of this sequence, the (positive) difference remaining
        :rtype: int
        """

    def toString(self, radix: TraceSchedule.TimeRadix) -> str:
        ...

    def totalPatchCount(self) -> int:
        """
        Compute to total number of patches specified
        
        :return: the total
        :rtype: int
        """

    def totalSkipCount(self) -> int:
        ...

    def totalTickCount(self) -> int:
        """
        Compute to total number of ticks specified
        
        :return: the total
        :rtype: int
        """

    def truncate(self, count: typing.Union[jpype.JInt, int]) -> Sequence:
        """
        Truncate this sequence to the first count steps
        
        :param jpype.JInt or int count: the count
        :return: the new sequence
        :rtype: Sequence
        """

    def validate(self, trace: ghidra.trace.model.Trace, eventThread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        """
        Validate this sequence for the given trace
        
        :param ghidra.trace.model.Trace trace: the trace
        :param ghidra.trace.model.thread.TraceThread eventThread: the thread for the first step, if it applies to the "last thread"
        :return: the last trace thread that would be stepped by this sequence
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    @property
    def lastThreadKey(self) -> jpype.JLong:
        ...

    @property
    def steps(self) -> java.util.List[Step]:
        ...

    @property
    def nop(self) -> jpype.JBoolean:
        ...


class AbstractStep(Step):

    class_: typing.ClassVar[java.lang.Class]

    def advance(self, steps: typing.Union[jpype.JLong, int]):
        """
        Add to the count of this step
        
        :param jpype.JLong or int steps: the count to add
        """


class StepKind(java.lang.Enum[StepKind], Stepper):

    class_: typing.ClassVar[java.lang.Class]
    INSTRUCTION: typing.Final[StepKind]
    PCODE: typing.Final[StepKind]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> StepKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[StepKind]:
        ...


class Step(java.lang.Comparable[Step]):

    class StepType(java.lang.Enum[Step.StepType]):

        class_: typing.ClassVar[java.lang.Class]
        TICK: typing.Final[Step.StepType]
        SKIP: typing.Final[Step.StepType]
        PATCH: typing.Final[Step.StepType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> Step.StepType:
            ...

        @staticmethod
        def values() -> jpype.JArray[Step.StepType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def addTo(self, step: Step):
        ...

    def clone(self) -> Step:
        ...

    def coalescePatches(self, language: ghidra.program.model.lang.Language, steps: java.util.List[Step]) -> int:
        ...

    def compareStep(self, that: Step) -> CompareResult:
        """
        Richly compare this step to another
        
        :param Step that: the object of comparison (this being the subject)
        :return: a result describing the relationship from subject to object
        :rtype: CompareResult
        """

    def compareStepType(self, that: Step) -> CompareResult:
        ...

    @typing.overload
    def execute(self, tm: ghidra.trace.model.thread.TraceThreadManager, eventThread: ghidra.trace.model.thread.TraceThread, machine: ghidra.pcode.emu.PcodeMachine[typing.Any], stepper: Stepper, monitor: ghidra.util.task.TaskMonitor) -> ghidra.trace.model.thread.TraceThread:
        ...

    @typing.overload
    def execute(self, emuThread: ghidra.pcode.emu.PcodeThread[typing.Any], stepper: Stepper, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getPatchCount(self) -> int:
        ...

    def getSkipCount(self) -> int:
        ...

    def getThread(self, tm: ghidra.trace.model.thread.TraceThreadManager, eventThread: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.thread.TraceThread:
        ...

    def getThreadKey(self) -> int:
        ...

    def getTickCount(self) -> int:
        ...

    def getType(self) -> Step.StepType:
        ...

    def getTypeOrder(self) -> int:
        ...

    def isCompatible(self, step: Step) -> bool:
        """
        Check if the given step can be combined with this one
         
         
        
        Two steps applied to the same thread can just be summed. If the given step applies to the
        "last thread" or to the same thread as this step, then it can be combined.
        
        :param Step step: the second step
        :return: true if combinable, false otherwise.
        :rtype: bool
        """

    def isEventThread(self) -> bool:
        ...

    def isNop(self) -> bool:
        ...

    @staticmethod
    def nop() -> TickStep:
        ...

    @staticmethod
    @typing.overload
    def parse(stepSpec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> Step:
        """
        Parse a step, possibly including a thread prefix, e.g., ``"t1-..."``
         
         
        
        If the thread prefix is given, the step applies to the given thread. Otherwise, the step
        applies to the last thread or the event thread.
        
        :param java.lang.String or str stepSpec: the string specification
        :param TraceSchedule.TimeRadix radix: the radix
        :return: the parsed step
        :rtype: Step
        :raises IllegalArgumentException: if the specification is of the wrong form
        """

    @staticmethod
    @typing.overload
    def parse(threadKey: typing.Union[jpype.JLong, int], stepSpec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> Step:
        """
        Parse a step for the given thread key
         
         
        
        The form of the spec must either be numeric, indicating some number of ticks, or
        brace-enclosed Sleigh code, e.g., ``"{r0=0x1234}"``. The latter allows patching machine
        state during execution.
        
        :param jpype.JLong or int threadKey: the thread to step, or -1 for the last thread or event thread
        :param java.lang.String or str stepSpec: the string specification
        :param TraceSchedule.TimeRadix radix: the radix
        :return: the parsed step
        :rtype: Step
        :raises IllegalArgumentException: if the specification is of the wrong form
        """

    @staticmethod
    def requireThread(thread: ghidra.trace.model.thread.TraceThread, key: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.thread.TraceThread:
        ...

    def rewind(self, count: typing.Union[jpype.JLong, int]) -> int:
        """
        Subtract from the count of this step
         
         
        
        If this step has a count exceeding that given, then this method simply subtracts the given
        number from the ``tickCount`` and returns the (negative) difference. If this step has
        exactly the count given, this method sets the count to 0 and returns 0, indicating this step
        should be removed from the sequence. If the given count exceeds that of this step, this
        method sets the count to 0 and returns the (positive) difference, indicating this step should
        be removed from the sequence, and the remaining steps rewound from the preceding step.
        
        :param jpype.JLong or int count: the count to rewind
        :return: the number of steps remaining
        :rtype: int
        """

    def subtract(self, step: Step) -> Step:
        ...

    def toString(self, radix: TraceSchedule.TimeRadix) -> str:
        ...

    @property
    def compatible(self) -> jpype.JBoolean:
        ...

    @property
    def tickCount(self) -> jpype.JLong:
        ...

    @property
    def threadKey(self) -> jpype.JLong:
        ...

    @property
    def typeOrder(self) -> jpype.JInt:
        ...

    @property
    def eventThread(self) -> jpype.JBoolean:
        ...

    @property
    def patchCount(self) -> jpype.JLong:
        ...

    @property
    def type(self) -> Step.StepType:
        ...

    @property
    def skipCount(self) -> jpype.JLong:
        ...


class Scheduler(java.lang.Object):
    """
    A generator of an emulator's thread schedule
    """

    class RunResult(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def error(self) -> java.lang.Throwable:
            """
            Get the error that interrupted execution
             
             
            
            Ideally, this is a :obj:`InterruptPcodeExecutionException`, indicating a breakpoint
            trapped the emulator, but it could be a number of things:
             
             
            * An instruction decode error
            * An unimplemented instruction
            * An unimplemented p-code userop
            * An error accessing the machine state
            * A runtime error in the implementation of a p-code userop
            * A runtime error in the implementation of the emulator, in which case, a bug should be
            filed
            
            
            :return: the error
            :rtype: java.lang.Throwable
            """

        def schedule(self) -> TraceSchedule:
            """
            Get the actual schedule executed
             
             
            
            It is possible for the machine to be interrupted mid-instruction. If this is the case,
            the trace schedule will indicate the p-code steps taken.
            
            :return: the schedule
            :rtype: TraceSchedule
            """


    class RecordRunResult(java.lang.Record, Scheduler.RunResult):
        """
        The result of running a machine
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, schedule: TraceSchedule, error: java.lang.Throwable):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def error(self) -> java.lang.Throwable:
            ...

        def hashCode(self) -> int:
            ...

        def schedule(self) -> TraceSchedule:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def nextSlice(self, trace: ghidra.trace.model.Trace) -> TickStep:
        """
        Get the next step to schedule
        
        :param ghidra.trace.model.Trace trace: the trace being emulated
        :return: the thread and (instruction-level) tick count
        :rtype: TickStep
        """

    @staticmethod
    def oneThread(thread: ghidra.trace.model.thread.TraceThread) -> Scheduler:
        """
        Create a scheduler that allocates all slices to a single thread
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to schedule
        :return: the scheduler
        :rtype: Scheduler
        """

    def run(self, trace: ghidra.trace.model.Trace, eventThread: ghidra.trace.model.thread.TraceThread, machine: ghidra.pcode.emu.PcodeMachine[typing.Any], monitor: ghidra.util.task.TaskMonitor) -> Scheduler.RunResult:
        """
        Run a machine according to the given schedule until it is interrupted
         
         
        
        This method will drop p-code steps from injections, including those from execution
        breakpoints. The goal is to ensure that the returned schedule can be used to recover the same
        state on a machine without injections. Unfortunately, injections which modify the machine
        state, other than unique variables, will defeat that goal.
        
        :param ghidra.trace.model.Trace trace: the trace whose threads to schedule
        :param ghidra.trace.model.thread.TraceThread eventThread: the first thread to schedule if the scheduler doesn't specify
        :param ghidra.pcode.emu.PcodeMachine[typing.Any] machine: the machine to run
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation
        :return: the result of execution
        :rtype: Scheduler.RunResult
        """


class Stepper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def instruction() -> Stepper:
        ...

    @staticmethod
    def pcode() -> Stepper:
        ...

    def skip(self, thread: ghidra.pcode.emu.PcodeThread[typing.Any]):
        ...

    def tick(self, thread: ghidra.pcode.emu.PcodeThread[typing.Any]):
        ...


class TraceSchedule(java.lang.Comparable[TraceSchedule]):
    """
    A sequence of emulator stepping commands, essentially comprising a "point in time."
    """

    class TimeRadix(java.lang.Enum[TraceSchedule.TimeRadix]):
        """
        Format for rendering and parsing snaps and step counts
        """

        class_: typing.ClassVar[java.lang.Class]
        DEC: typing.Final[TraceSchedule.TimeRadix]
        """
        Use decimal (default)
        """

        HEX_UPPER: typing.Final[TraceSchedule.TimeRadix]
        """
        Use upper-case hexadecimal
        """

        HEX_LOWER: typing.Final[TraceSchedule.TimeRadix]
        """
        Use lower-case hexadecimal
        """

        DEFAULT: typing.Final[TraceSchedule.TimeRadix]
        """
        The default radix (decimal)
        """

        name: typing.Final[java.lang.String]
        n: typing.Final[jpype.JInt]
        fmt: typing.Final[java.lang.String]

        def decode(self, nm: typing.Union[java.lang.String, str]) -> int:
            ...

        def format(self, time: typing.Union[jpype.JLong, int]) -> str:
            ...

        @staticmethod
        def fromStr(s: typing.Union[java.lang.String, str]) -> TraceSchedule.TimeRadix:
            """
            Get the radix specified by the given string
            
            :param java.lang.String or str s: the name of the specified radix
            :return: the radix
            :rtype: TraceSchedule.TimeRadix
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceSchedule.TimeRadix:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceSchedule.TimeRadix]:
            ...


    class ScheduleForm(java.lang.Enum[TraceSchedule.ScheduleForm]):
        """
        Specifies forms of a stepping schedule.
         
         
        
        Each form defines a set of stepping schedules. It happens that each is a subset of the next.
        A :obj:`.SNAP_ONLY` schedule is also a :obj:`.SNAP_ANY_STEPS_OPS` schedule, but not
        necessarily vice versa.
        """

        class_: typing.ClassVar[java.lang.Class]
        SNAP_ONLY: typing.Final[TraceSchedule.ScheduleForm]
        """
        The schedule consists only of a snapshot. No stepping after.
        """

        SNAP_EVT_STEPS: typing.Final[TraceSchedule.ScheduleForm]
        """
        The schedule consists of a snapshot and some number of instruction steps on the event
        thread only.
        """

        SNAP_ANY_STEPS: typing.Final[TraceSchedule.ScheduleForm]
        """
        The schedule consists of a snapshot and a sequence of instruction steps on any
        threads(s).
        """

        SNAP_ANY_STEPS_OPS: typing.Final[TraceSchedule.ScheduleForm]
        """
        The schedule consists of a snapshot and a sequence of instruction steps then p-code op
        steps on any thread(s).
         
         
        
        This is the most capable form supported by :obj:`TraceSchedule`.
        """

        VALUES: typing.Final[java.util.List[TraceSchedule.ScheduleForm]]

        def contains(self, trace: ghidra.trace.model.Trace, schedule: TraceSchedule) -> bool:
            """
            Check if the given schedule conforms
            
            :param ghidra.trace.model.Trace trace: if available, a trace for determining the event thread
            :param TraceSchedule schedule: the schedule to test
            :return: true if the schedule adheres to this form
            :rtype: bool
            """

        def intersect(self, that: TraceSchedule.ScheduleForm) -> TraceSchedule.ScheduleForm:
            """
            Get the more restrictive of this and the given form
            
            :param TraceSchedule.ScheduleForm that: the other form
            :return: the more restrictive form
            :rtype: TraceSchedule.ScheduleForm
            """

        def validate(self, trace: ghidra.trace.model.Trace, schedule: TraceSchedule) -> TraceSchedule:
            """
            If the given schedule conforms, normalize the schedule to prove it does.
            
            :param ghidra.trace.model.Trace trace: if available, a trace for determining the event thread
            :param TraceSchedule schedule: the schedule to test
            :return: the non-null normalized schedule, or null if the given schedule does not conform
            :rtype: TraceSchedule
            """

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceSchedule.ScheduleForm:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceSchedule.ScheduleForm]:
            ...


    class Source(java.lang.Enum[TraceSchedule.Source]):

        class_: typing.ClassVar[java.lang.Class]
        INPUT: typing.Final[TraceSchedule.Source]
        """
        The schedule comes from the user or some source other than a recorded emulation schedule.
        """

        RECORD: typing.Final[TraceSchedule.Source]
        """
        The schedule comes from recording actual emulation.
         
         
        
        Specifically, the p-code steps must be known not to exceed one instruction.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceSchedule.Source:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceSchedule.Source]:
            ...


    class StepAndKind(java.lang.Record):
        """
        Indicates a step and which kind (instruction or p-code)
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, kind: StepKind, step: Step):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def kind(self) -> StepKind:
            ...

        def step(self) -> Step:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ZERO: typing.Final[TraceSchedule]
    """
    The initial snapshot (with no steps)
    """


    @typing.overload
    def __init__(self, snap: typing.Union[jpype.JLong, int], steps: Sequence, pSteps: Sequence, source: TraceSchedule.Source):
        """
        Construct the given schedule
        
        :param jpype.JLong or int snap: the initial trace snapshot
        :param Sequence steps: the step sequence
        :param Sequence pSteps: the p-code step sequence
        :param TraceSchedule.Source source: if the p-code steps are known not to exceed one instruction
        """

    @typing.overload
    def __init__(self, snap: typing.Union[jpype.JLong, int], steps: Sequence, pSteps: Sequence):
        """
        Construct the given schedule, but assumed abnormal
        
        :param jpype.JLong or int snap: the initial trace snapshot
        :param Sequence steps: the step sequence
        :param Sequence pSteps: the p-code step sequence
        """

    def advanced(self, next: TraceSchedule) -> TraceSchedule:
        """
        Compute the schedule resulting from this schedule advanced by the given schedule
         
         
        
        This operation cannot be used to append instruction steps after p-code steps. Thus, if this
        schedule contains any p-code steps and ``next`` has instruction steps, an error will be
        
        :param TraceSchedule next: the schedule to append. Its snap is ignored.
        :return: the complete schedule
        :rtype: TraceSchedule
        :raises IllegalArgumentException: if the result would have instruction steps following p-code
                    steps
        """

    def assumeRecorded(self) -> TraceSchedule:
        ...

    def compareSchedule(self, that: TraceSchedule) -> CompareResult:
        """
        Richly compare two schedules
         
         
        
        Schedules starting at different snapshots are never related, because there is no
        emulator/simulator stepping action which advances to the next snapshot. Though p-code steps
        may comprise a partial step, we do not consider a partial step to be a prefix of a full step,
        since we cannot know *a priori* how many p-code steps comprise a full instruction
        step. Consider, e.g., the user may specify 100 p-code steps, which could effect 20
        instruction steps.
        
        :param TraceSchedule that: the object of comparison (this being the subject)
        :return: a result describing the relationship from subject to object
        :rtype: CompareResult
        """

    def differsOnlyByPatch(self, that: TraceSchedule) -> bool:
        ...

    def dropLastStep(self) -> TraceSchedule:
        """
        Drop the last step
         
         
        
        If there are p-code steps, this drops the last step there. Otherwise, this drops the last
        step from the instruction steps. A step includes all ticks in the step, e.g.,
        ``0:t0-20;t1-5`` becomes ``0:t0-20``. To remove a specific number of ticks, see
        :meth:`TraceSchedule.steppedBackward(Trace, long) <TraceSchedule.steppedBackward>`.
        
        :return: the schedule with the last step removed
        :rtype: TraceSchedule
        :raises NoSuchElementException: If there are neither instruction nor p-code steps.
        """

    def dropPSteps(self) -> TraceSchedule:
        """
        Drop the p-code steps
        
        :return: the schedule without ops
        :rtype: TraceSchedule
        """

    def execute(self, trace: ghidra.trace.model.Trace, machine: ghidra.pcode.emu.PcodeMachine[typing.Any], monitor: ghidra.util.task.TaskMonitor):
        """
        Realize the machine state for this schedule using the given trace and machine
         
         
        
        This method executes this schedule and trailing p-code steps on the given machine, assuming
        that machine is already "positioned" at the initial snapshot. Assuming successful execution,
        that machine is now said to be "positioned" at this schedule, and its state is the result of
        said execution.
        
        :param ghidra.trace.model.Trace trace: the trace containing the source snapshot and threads
        :param ghidra.pcode.emu.PcodeMachine[typing.Any] machine: a machine bound to the trace whose current state reflects the initial snapshot
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation and progress reporting
        :raises CancelledException: if the execution is cancelled
        """

    def finish(self, trace: ghidra.trace.model.Trace, position: TraceSchedule, machine: ghidra.pcode.emu.PcodeMachine[typing.Any], monitor: ghidra.util.task.TaskMonitor):
        """
        Realize the machine state for this schedule using the given trace and pre-positioned machine
         
         
        
        This method executes the remaining steps of this schedule and trailing p-code steps on the
        given machine, assuming that machine is already "positioned" at another given schedule.
        Assuming successful execution, that machine is now said to be "positioned" at this schedule,
        and its state is the result of said execution.
        
        :param ghidra.trace.model.Trace trace: the trace containing the source snapshot and threads
        :param TraceSchedule position: the current schedule of the given machine
        :param ghidra.pcode.emu.PcodeMachine[typing.Any] machine: a machine bound to the trace whose current state reflects the given position
        :param ghidra.util.task.TaskMonitor monitor: a monitor for cancellation and progress reporting
        :raises CancelledException: if the execution is cancelled
        :raises IllegalArgumentException: if the given position is not a prefix of this schedule
        """

    def getEventThread(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the event thread for this schedule in the context of the given trace
         
         
        
        This is the thread stepped when no thread is specified for the first step of the sequence.
        
        :param ghidra.trace.model.Trace trace: the trace containing the source snapshot and threads
        :return: the thread to use as "last thread" for the sequence
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getLastThread(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the last thread stepped by this schedule in the context of the given trace
        
        :param ghidra.trace.model.Trace trace: the trace containing the source snapshot and threads
        :return: the thread last stepped, or the "event thread" when no steps are taken, or null
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    def getLastThreadKey(self) -> int:
        """
        Get the last thread key stepped by this schedule
        
        :return: the thread key
        :rtype: int
        """

    def getSnap(self) -> int:
        """
        Get the source snapshot
        
        :return: the snapshot key
        :rtype: int
        """

    def getThreads(self, trace: ghidra.trace.model.Trace) -> java.util.Set[ghidra.trace.model.thread.TraceThread]:
        """
        Get the threads involved in the schedule
        
        :param ghidra.trace.model.Trace trace: the trace whose threads to get
        :return: the set of threads
        :rtype: java.util.Set[ghidra.trace.model.thread.TraceThread]
        """

    def hasPSteps(self) -> bool:
        """
        Check if this schedule has p-code steps
        
        :return: true if this indicates at least one instruction step
        :rtype: bool
        """

    def hasSteps(self) -> bool:
        """
        Check if this schedule has instruction steps
        
        :return: true if this indicates at least one instruction step
        :rtype: bool
        """

    def isSnapOnly(self) -> bool:
        """
        Check if this schedule requires any stepping
        
        :return: true if no stepping is required, i.e., the resulting state can be realized simply by
                loading a snapshot
        :rtype: bool
        """

    def lastStep(self) -> TraceSchedule.StepAndKind:
        """
        :return: the last step of the schedule
        :rtype: TraceSchedule.StepAndKind
        """

    def pPatchCount(self) -> int:
        """
        Compute the number of p-code patches applied
        
        :return: the number of patches
        :rtype: int
        """

    def pTickCount(self) -> int:
        """
        Compute the number of p-code ticks taken
        
        :return: the number of ticks
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def parse(spec: typing.Union[java.lang.String, str], source: TraceSchedule.Source, radix: TraceSchedule.TimeRadix) -> TraceSchedule:
        """
        Parse schedule in the form "``snap[:steps[.pSteps]]``"
         
         
        
        A schedule consists of a snap, a optional :obj:`Sequence` of thread instruction-level steps,
        and optional p-code-level steps (pSteps). The form of ``steps`` and ``pSteps`` is
        specified by :meth:`Sequence.parse(String, TimeRadix) <Sequence.parse>`. Each sequence consists of stepping
        selected threads forward, and/or patching machine state.
        
        :param java.lang.String or str spec: the string specification
        :param TraceSchedule.Source source: the presumed source of the schedule
        :param TraceSchedule.TimeRadix radix: the radix
        :return: the parsed schedule
        :rtype: TraceSchedule
        """

    @staticmethod
    @typing.overload
    def parse(spec: typing.Union[java.lang.String, str], radix: TraceSchedule.TimeRadix) -> TraceSchedule:
        """
        As in :meth:`parse(String, Source, TimeRadix) <.parse>`, but assumed abnormal
        
        :param java.lang.String or str spec: the string specification
        :param TraceSchedule.TimeRadix radix: the radix
        :return: the parsed schedule
        :rtype: TraceSchedule
        """

    @staticmethod
    @typing.overload
    def parse(spec: typing.Union[java.lang.String, str]) -> TraceSchedule:
        """
        As in :meth:`parse(String, TimeRadix) <.parse>`, but with the :obj:`TimeRadix.DEFAULT` radix.
        
        :param java.lang.String or str spec: the string specification
        :return: the parse sequence
        :rtype: TraceSchedule
        """

    def patchCount(self) -> int:
        """
        Compute the number of patches, excluding p-code patches
        
        :return: the number of patches
        :rtype: int
        """

    @typing.overload
    def patched(self, thread: ghidra.trace.model.thread.TraceThread, language: ghidra.program.model.lang.Language, sleigh: typing.Union[java.lang.String, str]) -> TraceSchedule:
        """
        Returns the equivalent of executing this schedule then performing a given patch
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread context for the patch; cannot be null
        :param ghidra.program.model.lang.Language language: the sleigh language for the patch
        :param java.lang.String or str sleigh: a single line of sleigh, excluding the terminating semicolon.
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    @typing.overload
    def patched(self, thread: ghidra.trace.model.thread.TraceThread, language: ghidra.program.model.lang.Language, sleigh: java.util.List[java.lang.String]) -> TraceSchedule:
        """
        Returns the equivalent of executing this schedule then performing the given patches
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread context for the patch; cannot be null
        :param ghidra.program.model.lang.Language language: the sleigh language for the patch
        :param java.util.List[java.lang.String] sleigh: the lines of sleigh, excluding the terminating semicolons
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    def requireLastThread(self, trace: ghidra.trace.model.Trace) -> ghidra.trace.model.thread.TraceThread:
        """
        Get the last thread stepped by this schedule in the context of the given trace
        
        :param ghidra.trace.model.Trace trace: the trace containing the source snapshot and threads
        :return: the thread last stepped, or the "event thread" when no steps are taken
        :rtype: ghidra.trace.model.thread.TraceThread
        :raises IllegalArgumentException: if the last thread cannot be determined from this schedule
                    and the given trace.
        """

    def skippedForward(self, thread: ghidra.trace.model.thread.TraceThread, tickCount: typing.Union[jpype.JLong, int]) -> TraceSchedule:
        """
        Behaves as in :meth:`steppedForward(TraceThread, long) <.steppedForward>`, but by appending skips
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step, or null for the "last thread"
        :param jpype.JLong or int tickCount: the number of skips to take the thread forward
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    def skippedPcodeForward(self, thread: ghidra.trace.model.thread.TraceThread, pTickCount: typing.Union[jpype.JInt, int]) -> TraceSchedule:
        """
        Behaves as in :meth:`steppedPcodeForward(TraceThread, int) <.steppedPcodeForward>`, but by appending skips
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step, or null for the "last thread"
        :param jpype.JInt or int pTickCount: the number of p-code skips to take the thread forward
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    @staticmethod
    def snap(snap: typing.Union[jpype.JLong, int]) -> TraceSchedule:
        """
        Create a schedule that consists solely of a snapshot
        
        :param jpype.JLong or int snap: the snapshot key
        :return: the schedule
        :rtype: TraceSchedule
        """

    def stepCount(self) -> int:
        """
        Count the number of steps, excluding p-code steps
        
        :return: the number of steps
        :rtype: int
        """

    def steppedBackward(self, trace: ghidra.trace.model.Trace, stepCount: typing.Union[jpype.JLong, int]) -> TraceSchedule:
        """
        Returns the equivalent of executing count instructions (and all p-code operations) less than
        this schedule
         
         
        
        This schedule is left unmodified. If it had any p-code steps, those steps and subsequent
        patches are dropped in the resulting schedule. If count exceeds this schedule's steps, it
        will try (recursively) to step the source snapshot's schedule backward, if known. Both ticks
        and patches counts as steps.
        
        :param ghidra.trace.model.Trace trace: the trace of this schedule, for context
        :param jpype.JLong or int stepCount: the number of steps to take backward
        :return: the resulting schedule or null if it cannot be computed
        :rtype: TraceSchedule
        """

    def steppedForward(self, thread: ghidra.trace.model.thread.TraceThread, tickCount: typing.Union[jpype.JLong, int]) -> TraceSchedule:
        """
        Returns the equivalent of executing the schedule (ignoring p-code steps) followed by stepping
        the given thread count more instructions
         
         
        
        This schedule is left unmodified. If it had any p-code steps, those steps are dropped in the
        resulting schedule.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step, or null for the "last thread"
        :param jpype.JLong or int tickCount: the number of ticks to take the thread forward
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    def steppedPcodeBackward(self, pStepCount: typing.Union[jpype.JInt, int]) -> TraceSchedule:
        """
        Returns the equivalent of executing count p-code operations less than this schedule
         
         
        
        If ``pStepCount`` exceeds the p-code steps of this schedule, null is returned, since we
        cannot know *a priori* how many p-code steps would be required to complete the
        preceding instruction step. Both p-code ticks and p-code patches counts as p-code steps.
        
        :param jpype.JInt or int pStepCount: the number of p-code steps to take backward
        :return: the resulting schedule or null if it cannot be computed
        :rtype: TraceSchedule
        """

    def steppedPcodeForward(self, thread: ghidra.trace.model.thread.TraceThread, pTickCount: typing.Union[jpype.JInt, int]) -> TraceSchedule:
        """
        Returns the equivalent of executing the schedule followed by stepping the given thread
        ``pTickCount`` more p-code operations
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread to step, or null for the "last thread"
        :param jpype.JInt or int pTickCount: the number of p-code ticks to take the thread forward
        :return: the resulting schedule
        :rtype: TraceSchedule
        """

    def tickCount(self) -> int:
        """
        Compute the number of ticks taken, excluding p-code ticks
        
        :return: the number of ticks
        :rtype: int
        """

    def toString(self, radix: TraceSchedule.TimeRadix) -> str:
        ...

    def totalPatchCount(self) -> int:
        """
        Compute the total number of patches applied
        
        :return: the number of patches
        :rtype: int
        """

    def totalTickCount(self) -> int:
        """
        Compute the total number of ticks taken, including the p-code ticks
         
         
        
        This is suitable for use with :meth:`TaskMonitor.initialize(long) <TaskMonitor.initialize>`, where that monitor will
        be passed to :meth:`execute(Trace, PcodeMachine, TaskMonitor) <.execute>` or similar. Note that patch
        steps do not count as ticks.
        
        :return: the number of ticks
        :rtype: int
        """

    def truncateToSteps(self, count: typing.Union[jpype.JInt, int]) -> TraceSchedule:
        """
        Drop all p-code steps, if any, and enough instruction steps, such that :meth:`stepCount() <.stepCount>`
        returns the given count.
        
        :param jpype.JInt or int count: the desired step count
        :return: the new schedule
        :rtype: TraceSchedule
        """

    def validate(self, trace: ghidra.trace.model.Trace):
        """
        Validate this schedule for the given trace
         
         
        
        This performs a dry run of the sequence on the given trace. If the schedule starts on the
        "last thread," it verifies the snapshot gives the event thread. It also checks that every
        thread key in the sequence exists in the trace.
        
        :param ghidra.trace.model.Trace trace: the trace against which to validate this schedule
        """

    @property
    def lastThreadKey(self) -> jpype.JLong:
        ...

    @property
    def threads(self) -> java.util.Set[ghidra.trace.model.thread.TraceThread]:
        ...

    @property
    def lastThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def eventThread(self) -> ghidra.trace.model.thread.TraceThread:
        ...

    @property
    def snapOnly(self) -> jpype.JBoolean:
        ...



__all__ = ["SkipStep", "TickStep", "PatchStep", "CompareResult", "Sequence", "AbstractStep", "StepKind", "Step", "Scheduler", "Stepper", "TraceSchedule"]
