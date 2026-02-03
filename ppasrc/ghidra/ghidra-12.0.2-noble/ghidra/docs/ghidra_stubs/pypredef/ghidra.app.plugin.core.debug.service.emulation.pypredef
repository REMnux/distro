from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action.builder
import ghidra.app.services
import ghidra.debug.api.emulation
import ghidra.debug.api.modules
import ghidra.framework.plugintool
import ghidra.pcode.exec_
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.memory
import ghidra.trace.model.target.iface
import ghidra.trace.model.target.path
import ghidra.trace.model.target.schema
import ghidra.trace.model.thread
import ghidra.trace.model.time
import ghidra.trace.model.time.schedule
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class DebuggerEmulationServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerEmulationService):

    class EmulateProgramAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Emulate Program in new Trace"
        DESCRIPTION: typing.Final = "Emulate the current program in a new trace starting at the cursor"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "emulate_program"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class EmulateAddThreadAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Add Emulated Thread to Trace"
        DESCRIPTION: typing.Final = "Add an emulated thread to the current trace starting here"
        ICON: typing.Final[javax.swing.Icon]
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "add_emulated_thread"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class ConfigureEmulatorAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Configure Emulator"
        DESCRIPTION: typing.Final = "Choose and configure the current emulator"
        GROUP: typing.Final = "Dbg1. General"
        HELP_ANCHOR: typing.Final = "configure_emulator"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ToggleActionBuilder:
            ...


    @typing.type_check_only
    class InvalidateEmulatorCacheAction(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        NAME: typing.Final = "Invalidate Emulator Cache"
        DESCRIPTION: typing.Final = "Prevent the emulation service from using cached snapshots from the current trace"
        GROUP: typing.Final = "Dbg8. Maintenance"
        HELP_ANCHOR: typing.Final = "invalidate_cache"

        @staticmethod
        def builder(owner: ghidra.framework.plugintool.Plugin) -> docking.action.builder.ActionBuilder:
            ...


    @typing.type_check_only
    class CacheKey(java.lang.Comparable[DebuggerEmulationServicePlugin.CacheKey]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, time: ghidra.trace.model.time.schedule.TraceSchedule):
            ...

        def compareKey(self, that: DebuggerEmulationServicePlugin.CacheKey) -> ghidra.trace.model.time.schedule.CompareResult:
            ...


    @typing.type_check_only
    class AbstractEmulateTask(ghidra.util.task.Task, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, title: typing.Union[java.lang.String, str], hasProgress: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class EmulateTask(DebuggerEmulationServicePlugin.AbstractEmulateTask[java.lang.Long]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, key: DebuggerEmulationServicePlugin.CacheKey):
            ...


    @typing.type_check_only
    class RunEmulatorTask(DebuggerEmulationServicePlugin.AbstractEmulateTask[ghidra.app.services.DebuggerEmulationService.EmulationResult]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, from_: DebuggerEmulationServicePlugin.CacheKey, scheduler: ghidra.trace.model.time.schedule.Scheduler):
            ...


    @typing.type_check_only
    class BusyEmu(java.lang.AutoCloseable):

        class_: typing.ClassVar[java.lang.Class]

        def dup(self) -> DebuggerEmulationServicePlugin.BusyEmu:
            ...


    @typing.type_check_only
    class TraceMappingWaiter(java.util.concurrent.CompletableFuture[java.lang.Void], ghidra.debug.api.modules.DebuggerStaticMappingChangeListener):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, trace: ghidra.trace.model.Trace):
            ...

        def softWait(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DefaultEmulatorFactory(ghidra.debug.api.emulation.EmulatorFactory):
    """
    The Debugger's default emulator factory
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class Mode(java.lang.Enum[Mode]):
    """
    A write flag for target-associated emulator states
    """

    class_: typing.ClassVar[java.lang.Class]
    RW: typing.Final[Mode]
    """
    The state can write the target directly
    """

    RO: typing.Final[Mode]
    """
    The state will never write the target
    """


    def isWriteTarget(self) -> bool:
        """
        Check if the mode permits writing the target
        
        :return: true to allow, false to prohibit
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Mode:
        ...

    @staticmethod
    def values() -> jpype.JArray[Mode]:
        ...

    @property
    def writeTarget(self) -> jpype.JBoolean:
        ...


class DebuggerEmulationIntegration(java.lang.Enum[DebuggerEmulationIntegration]):
    """
    A collection of static methods for integrating an emulator with a trace and target.
    """

    class TargetBytesPieceHandler(ghidra.pcode.exec_.trace.TraceEmulationIntegration.BytesPieceHandler):
        """
        An extension/replacement of the :obj:`BytesPieceHandler` that may redirect reads and writes
        to/from the target.
        
        
        .. admonition:: Implementation Note
        
            Because piece handlers are keyed by (address-domain, value-domain), adding this to
            a writer will replace the default handler.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mode: Mode):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def bytesDelayedWriteTrace(from_: ghidra.debug.api.emulation.PcodeDebuggerAccess) -> ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer:
        """
        Create a writer (callbacks) that lazily loads data from the given access shim.
         
         
        
        Reads may be redirected to the target. Writes are logged, but *never* sent to the
        target. This is used for forking emulation from a chosen snapshot and saving the results into
        (usually scratch) snapshots. This is the pattern used by the UI when emulation schedules are
        requested.
        
        :param ghidra.debug.api.emulation.PcodeDebuggerAccess from: the access shim for lazy loads
        :return: the writer
        :rtype: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer
        
        .. seealso::
        
            | :obj:`TraceEmulationIntegration.bytesDelayedWrite(PcodeTraceAccess)`
        """

    @staticmethod
    @typing.overload
    def bytesImmediateWriteTarget(access: ghidra.debug.api.emulation.PcodeDebuggerAccess) -> ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer:
        """
        Create a writer (callbacks) that lazily loads data and immediately writes changes to the
        given access shim.
         
         
        
        Reads may be redirected to the target. If redirected, writes are immediately sent to the
        target and presumably stored into the trace at the same snapshot as state is sourced.
        
        :param ghidra.debug.api.emulation.PcodeDebuggerAccess access: the access shim for loads and stores
        :return: the writer
        :rtype: ghidra.pcode.exec_.trace.TraceEmulationIntegration.Writer
        
        .. seealso::
        
            | :obj:`TraceEmulationIntegration.bytesImmediateWrite(PcodeTraceAccess)`
        """

    @staticmethod
    @typing.overload
    def bytesImmediateWriteTarget(access: ghidra.debug.api.emulation.PcodeDebuggerAccess, thread: ghidra.trace.model.thread.TraceThread, frame: typing.Union[jpype.JInt, int]) -> ghidra.pcode.exec_.PcodeStateCallbacks:
        """
        Create state callbacks that lazily load data and immediately write changes to the given
        access shim.
         
         
        
        Reads may be redirected to the target. If redirected, writes are immediately sent to the
        target and presumably stored into the trace at the same snapshot as state is sourced.
        
         
        
        Use this instead of :meth:`bytesImmediateWriteTarget(PcodeDebuggerAccess) <.bytesImmediateWriteTarget>` when interfacing
        directly with a :obj:`PcodeExecutorState` vice a :obj:`PcodeEmulator`.
        
        :param ghidra.debug.api.emulation.PcodeDebuggerAccess access: the access shim for loads and stores
        :param ghidra.trace.model.thread.TraceThread thread: the trace thread for register accesses
        :param jpype.JInt or int frame: the frame for register accesses, usually 0
        :return: the callbacks
        :rtype: ghidra.pcode.exec_.PcodeStateCallbacks
        
        .. seealso::
        
            | :obj:`TraceEmulationIntegration.bytesImmediateWrite(PcodeTraceAccess, TraceThread, int)`
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> DebuggerEmulationIntegration:
        ...

    @staticmethod
    def values() -> jpype.JArray[DebuggerEmulationIntegration]:
        ...


class EmulatorOutOfMemoryException(java.lang.RuntimeException):
    """
    Some emulator-related operation was unable to locate a suitable address in the trace's memory map
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ProgramEmulationUtils(java.lang.Object):
    """
    A set of utilities for emulating programs without necessarily having a debugger connection.
     
     
    
    Most of these are already integrated via the :obj:`DebuggerEmulationService`. Please see if that
    service satisfies your use case before employing these directly.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMU_CTX_XML: typing.Final = "<context>\n    <schema name=\'EmuSession\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'Process\' />\n        <interface name=\'Aggregate\' />\n        <attribute name=\'Breakpoints\' schema=\'BreakpointContainer\' />\n        <attribute name=\'Memory\' schema=\'RegionContainer\' />\n        <attribute name=\'Modules\' schema=\'ModuleContainer\' />\n        <attribute name=\'Threads\' schema=\'ThreadContainer\' />\n    </schema>\n    <schema name=\'BreakpointContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <element schema=\'Breakpoint\' />\n    </schema>\n    <schema name=\'Breakpoint\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'BreakpointSpec\' />\n        <interface name=\'BreakpointLocation\' />\n    </schema>\n    <schema name=\'RegionContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <element schema=\'Region\' />\n    </schema>\n    <schema name=\'Region\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'MemoryRegion\' />\n    </schema>\n    <schema name=\'ModuleContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <element schema=\'Module\' />\n    </schema>\n    <schema name=\'Module\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'Module\' />\n        <attribute name=\'Sections\' schema=\'SectionContainer\' />\n    </schema>\n    <schema name=\'SectionContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <element schema=\'Section\' />\n    </schema>\n    <schema name=\'Section\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'Section\' />\n    </schema>\n    <schema name=\'ThreadContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <element schema=\'Thread\' />\n    </schema>\n    <schema name=\'Thread\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'Thread\' />\n        <interface name=\'Activatable\' />\n        <interface name=\'Aggregate\' />\n        <attribute name=\'Stack\' schema=\'Stack\' />\n        <attribute name=\'Registers\' schema=\'RegisterContainer\' />\n    </schema>\n    <schema name=\'Stack\' canonical=\'yes\'>\n        <interface name=\'Stack\' />\n        <element schema=\'Frame\' />\n    </schema>\n    <schema name=\'Frame\'>\n        <interface name=\'StackFrame\' />\n    </schema>\n    <schema name=\'RegisterContainer\' canonical=\'yes\' elementResync=\'NEVER\'\n            attributeResync=\'NEVER\'>\n        <interface name=\'RegisterContainer\' />\n        <element schema=\'Register\' />\n    </schema>\n    <schema name=\'Register\' elementResync=\'NEVER\' attributeResync=\'NEVER\'>\n        <interface name=\'Register\' />\n    </schema>\n</context>\n"
    EMU_CTX: typing.Final[ghidra.trace.model.target.schema.SchemaContext]
    EMU_SESSION_SCHEMA: typing.Final[ghidra.trace.model.target.schema.TraceObjectSchema]
    BLOCK_NAME_STACK: typing.Final = "STACK"
    EMULATION_STARTED_AT: typing.Final = "Emulation started at "
    """
    Conventional prefix for first snapshot to identify "pure emulation" traces.
    """


    @staticmethod
    def allocateStack(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, program: ghidra.program.model.listing.Program, size: typing.Union[jpype.JLong, int], programPc: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Attempt to allocate a new stack region for the given thread
         
         
        
        If successful, this will create a dynamic memory region representing the stack. If the stack
        is specified by an override (SP register context or STACK block) in the program, and that
        block overlays the image, then no region is created, but the range is still returned.
        
        :param ghidra.trace.model.Trace trace: the trace containing the stack and thread
        :param jpype.JLong or int snap: the creation snap for the new region
        :param ghidra.trace.model.thread.TraceThread thread: the thread for which the stack is being allocated
        :param ghidra.program.model.listing.Program program: the program being emulated (to check for stack allocation override)
        :param jpype.JLong or int size: the desired size of the region
        :param ghidra.program.model.address.Address programPc: the program counter in the program's memory map, in case SP is given by the
                    program context
        :return: the range allocated for the stack
        :rtype: ghidra.program.model.address.AddressRange
        :raises EmulatorOutOfMemoryException: if the stack cannot be allocated
        """

    @staticmethod
    def allocateStackCustomByBlock(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressRange:
        """
        Attempt allocation of the stack using the program's STACK block.
         
         
        
        This tries to find a block named STACK in the emulated program. If it finds one, it will
        attempt to create a region in the trace at the mapped dynamic location. It's possible (likely
        even, for a multi-threaded emulation session) that the region already exists. In that case,
        an error dialog is displayed, but the stack pointer is still initialized to the block.
        
        :param ghidra.trace.model.Trace trace: the trace containing the stack and thread
        :param jpype.JLong or int snap: the creation snap for the new region
        :param ghidra.trace.model.thread.TraceThread thread: the thread for which the stack is being allocated
        :param ghidra.program.model.listing.Program program: the program being emulated (to check for stack allocation override)
        :return: the range allocated for the stack, or null if no STACK block exists
        :rtype: ghidra.program.model.address.AddressRange
        """

    @staticmethod
    def allocateStackCustomByContext(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, program: ghidra.program.model.listing.Program, size: typing.Union[jpype.JLong, int], programPc: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Attempt allocation of the stack using the program context and the initial PC.
         
         
        
        This examines the program context for a stack pointer value at the thread's initial program
        counter. If it has a value, this computes a range, based on the expected stack growth
        direction, of the specified size. If the range would wrap, it is truncated toe the space's
        bounds. This then attempts to create a region at the computed range to allocate the stack. If
        it already exists, an error dialog is presented, but the SP is still initialized as
        specified.
        
        :param ghidra.trace.model.Trace trace: the trace containing the stack and thread
        :param jpype.JLong or int snap: the creation snap for the new region
        :param ghidra.trace.model.thread.TraceThread thread: the thread for which the stack is being allocated
        :param ghidra.program.model.listing.Program program: the program being emulated (to check for stack allocation override)
        :param jpype.JLong or int size: the desired size of the region
        :param ghidra.program.model.address.Address programPc: the program counter in the program's memory map, in case SP is given by the
                    program context
        :return: the range allocated for the stack, or null if no SP value is set
        :rtype: ghidra.program.model.address.AddressRange
        """

    @staticmethod
    def computePattern(root: ghidra.trace.model.target.schema.TraceObjectSchema, trace: ghidra.trace.model.Trace, iface: java.lang.Class[ghidra.trace.model.target.iface.TraceObjectInterface]) -> ghidra.trace.model.target.path.PathPattern:
        ...

    @staticmethod
    def computePatternRegion(trace: ghidra.trace.model.Trace) -> ghidra.trace.model.target.path.PathPattern:
        ...

    @staticmethod
    def computePatternThread(trace: ghidra.trace.model.Trace) -> ghidra.trace.model.target.path.PathPattern:
        ...

    @staticmethod
    def createObjects(trace: ghidra.trace.model.Trace):
        """
        Initialize a given emulation trace with some required/expected objects
        
        :param ghidra.trace.model.Trace trace: the trace
        """

    @staticmethod
    def doLaunchEmulationThread(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program, tracePc: ghidra.program.model.address.Address, programPc: ghidra.program.model.address.Address) -> ghidra.trace.model.thread.TraceThread:
        """
        Create a new emulated thread within an existing trace
        
        :param ghidra.trace.model.Trace trace: the trace to contain the new thread
        :param jpype.JLong or int snap: the creation snap for the new thread
        :param ghidra.program.model.listing.Program program: the program whose context to use for initial register values
        :param ghidra.program.model.address.Address tracePc: the program counter in the trace's memory map
        :param ghidra.program.model.address.Address programPc: the program counter in the program's memory map
        :return: the new thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    @staticmethod
    def getModuleName(program: ghidra.program.model.listing.Program) -> str:
        """
        Suggests the initial module name for loading a program into an emulated trace
        
        :param ghidra.program.model.listing.Program program: the program comprising the module to "load"
        :return: the suggested module name
        :rtype: str
        """

    @staticmethod
    def getRegionFlags(block: ghidra.program.model.mem.MemoryBlock) -> java.util.Set[ghidra.trace.model.memory.TraceMemoryFlag]:
        """
        Convert permissions for a program memory block into flags for a trace memory region
        
        :param ghidra.program.model.mem.MemoryBlock block: the block whose permissions to convert
        :return: the corresponding set of flags
        :rtype: java.util.Set[ghidra.trace.model.memory.TraceMemoryFlag]
        """

    @staticmethod
    def getTraceName(program: ghidra.program.model.listing.Program) -> str:
        """
        Suggests a name for a new trace for emulation of the given program
        
        :param ghidra.program.model.listing.Program program: the program to emulate
        :return: the suggested name
        :rtype: str
        """

    @staticmethod
    def initializeRegisters(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, program: ghidra.program.model.listing.Program, tracePc: ghidra.program.model.address.Address, programPc: ghidra.program.model.address.Address, stack: ghidra.program.model.address.AddressRange):
        """
        Initialize a thread's registers using program context and an optional stack
        
        :param ghidra.trace.model.Trace trace: the trace containing the thread
        :param jpype.JLong or int snap: the destination snap for the register state
        :param ghidra.trace.model.thread.TraceThread thread: the thread whose registers to initialize
        :param ghidra.program.model.listing.Program program: the program whose context to use
        :param ghidra.program.model.address.Address tracePc: the program counter in the trace's memory map
        :param ghidra.program.model.address.Address programPc: the program counter in the program's memory map
        :param ghidra.program.model.address.AddressRange stack: optionally, the range for the thread's stack allocation
        """

    @staticmethod
    def isEmulatedProgram(trace: ghidra.trace.model.Trace) -> bool:
        """
        Check if the given trace is for "pure emulation"
        
        :param ghidra.trace.model.Trace trace: the trace to check
        :return: true if created for emulation, false otherwise
        :rtype: bool
        """

    @staticmethod
    def launchEmulationThread(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int], program: ghidra.program.model.listing.Program, tracePc: ghidra.program.model.address.Address, programPc: ghidra.program.model.address.Address) -> ghidra.trace.model.thread.TraceThread:
        """
        Same as :meth:`doLaunchEmulationThread(Trace, long, Program, Address, Address) <.doLaunchEmulationThread>`, but within
        a transaction
        
        :param ghidra.trace.model.Trace trace: the trace to contain the new thread
        :param jpype.JLong or int snap: the creation snap for the new thread
        :param ghidra.program.model.listing.Program program: the program whose context to use for initial register values
        :param ghidra.program.model.address.Address tracePc: the program counter in the trace's memory map
        :param ghidra.program.model.address.Address programPc: the program counter in the program's memory map
        :return: the new thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """

    @staticmethod
    def launchEmulationTrace(program: ghidra.program.model.listing.Program, pc: ghidra.program.model.address.Address, consumer: java.lang.Object) -> ghidra.trace.model.Trace:
        """
        Create a new trace with a single thread, ready for emulation of the given program
        
        :param ghidra.program.model.listing.Program program: the program to emulate
        :param ghidra.program.model.address.Address pc: the initial program counter for the new single thread
        :param java.lang.Object consumer: the consumer of the new trace
        :return: the new trace
        :rtype: ghidra.trace.model.Trace
        :raises IOException: if the trace cannot be created
        """

    @staticmethod
    def loadExecutable(snapshot: ghidra.trace.model.time.TraceSnapshot, program: ghidra.program.model.listing.Program, activeOverlays: java.util.List[ghidra.program.model.address.AddressSpace]):
        """
        Create regions for each block in a program, without relocation, and map the program in
         
         
        
        This creates a region for each loaded, block in the program. Typically, only non-overlay
        blocks are included. To activate an overlay space, include it in the set of
        ``activeOverlays``. This will alter the mapping from the trace to the static program such
        that the specified overlays are effective. The gaps between overlays are mapped to their
        physical (non-overlay) portions. Permissions/flags are assigned accordingly. Note that no
        bytes are copied in, as that could be prohibitive for large programs. Instead, the emulator
        should load them, based on the static mapping, as needed.
         
         
        
        A transaction must already be started on the destination trace.
        
        :param ghidra.trace.model.time.TraceSnapshot snapshot: the destination snapshot, usually 0
        :param ghidra.program.model.listing.Program program: the program to load
        :param java.util.List[ghidra.program.model.address.AddressSpace] activeOverlays: which overlay spaces to use
        """

    @staticmethod
    def spawnThread(trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.thread.TraceThread:
        """
        Spawn a new thread in the given trace at the given creation snap
         
         
        
        This does not initialize the thread's state. It simply creates it.
        
        :param ghidra.trace.model.Trace trace: the trace to contain the new thread
        :param jpype.JLong or int snap: the creation shap of the new thread
        :return: the new thread
        :rtype: ghidra.trace.model.thread.TraceThread
        """



__all__ = ["DebuggerEmulationServicePlugin", "DefaultEmulatorFactory", "Mode", "DebuggerEmulationIntegration", "EmulatorOutOfMemoryException", "ProgramEmulationUtils"]
