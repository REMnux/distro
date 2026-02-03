from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.actions
import ghidra.app.plugin.core.assembler
import ghidra.debug.api.platform
import ghidra.framework.cmd
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.program
import ghidra.trace.model.target
import ghidra.trace.model.thread
import ghidra.util.classfinder
import java.lang # type: ignore


class FixedPlatformTraceDisassembleAction(AbstractTraceDisassembleAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin, altLangID: ghidra.program.model.lang.LanguageID, platform: ghidra.trace.model.guest.TracePlatform):
        ...


class AbstractTraceDisassembleAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin, name: typing.Union[java.lang.String, str]):
        ...


class CurrentPlatformTraceDisassembleAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin):
        ...


class TraceDisassembleCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.program.TraceProgramView]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, platform: ghidra.trace.model.guest.TracePlatform, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView):
        ...

    def getDisassembledAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def setInitialContext(self, initialContext: ghidra.program.model.lang.RegisterValue):
        ...

    @property
    def disassembledAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...


class FixedPlatformTracePatchInstructionAction(AbstractTracePatchInstructionAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin, altLangID: ghidra.program.model.lang.LanguageID, platform: ghidra.trace.model.guest.TracePlatform):
        ...


class DisassemblyInject(ghidra.util.classfinder.ExtensionPoint):
    """
    A configuration inject for automatic disassembly at the program counter
     
     
    
    Ghidra uses a "context register" to control the modes of disassembly for certain processor
    languages. Debuggers don't have such a context register, but may have access to the various
    status registers actually used by that processor to select, e.g., an ISA. These injects "glue"
    the disassembler to context derived from status registers. Each supported context-sensitive
    processor will likely need its own inject; thus, these are pluggable extensions. It's unlikely
    multiple injects should ever be needed, but it is supported, just in case. The injects are
    invoked in order of priority, starting with the least. Since injects are meant simply to
    configure the disassembler (namely seeding its context), the one invoked last will have "the last
    word." As such, each inject should avoid unnecessarily erasing existing context.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getInfo(self) -> DisassemblyInjectInfo:
        """
        If present, get the information annotation on this inject
        
        :return: the info
        :rtype: DisassemblyInjectInfo
        """

    def getPriority(self) -> int:
        """
        Get this injects position in the invocation order
        
        :return: the priority
        :rtype: int
        """

    def isApplicable(self, platform: ghidra.trace.model.guest.TracePlatform) -> bool:
        """
        Check if this inject applies to the given trace platform
        
        :param ghidra.trace.model.guest.TracePlatform platform: the platform to check
        :return: true if applicable, false otherwise
        :rtype: bool
        """

    def post(self, tool: ghidra.framework.plugintool.PluginTool, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], disassembled: ghidra.program.model.address.AddressSetView):
        """
        A post-auto disassembly hook
         
         
        
        This hook is invoked by the :obj:`DebuggerPlatformMapper` after disassembly completes. The
        callback occurs within the command's background thread.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool that just executed the disassembly command
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform for the disassembler
        :param jpype.JLong or int snap: the snap the snap at which disassembly was performed
        :param ghidra.program.model.address.AddressSetView disassembled: the addresses that were actually disassembled
        """

    def pre(self, tool: ghidra.framework.plugintool.PluginTool, command: TraceDisassembleCommand, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], thread: ghidra.trace.model.thread.TraceThread, startSet: ghidra.program.model.address.AddressSetView, restricted: ghidra.program.model.address.AddressSetView):
        """
        A pre-auto disassembly hook
         
         
        
        This hook is invoked by the :obj:`DebuggerPlatformMapper` before disassembly actually
        begins. The callback occurs within the command's background thread. In general, the inject
        should limit its operation to inspecting the trace database and configuring the command.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool that will execute the command
        :param TraceDisassembleCommand command: the command to be configured, which is about to execute
        :param ghidra.trace.model.guest.TracePlatform platform: the trace platform for the disassembler
        :param jpype.JLong or int snap: the snap the snap at which to disassemble
        :param ghidra.trace.model.thread.TraceThread thread: the thread whose PC is being disassembled
        :param ghidra.program.model.address.AddressSetView startSet: the starting address set, usually just the PC
        :param ghidra.program.model.address.AddressSetView restricted: the set of disassemblable addresses
        """

    @property
    def applicable(self) -> jpype.JBoolean:
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...

    @property
    def info(self) -> DisassemblyInjectInfo:
        ...


class CurrentPlatformTraceDisassembleCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.program.TraceProgramView]):

    class Reqs(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, mapper: ghidra.debug.api.platform.DebuggerPlatformMapper, thread: ghidra.trace.model.thread.TraceThread, object: ghidra.trace.model.target.TraceObject, view: ghidra.trace.model.program.TraceProgramView):
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromContext(tool: ghidra.framework.plugintool.PluginTool, context: docking.ActionContext) -> CurrentPlatformTraceDisassembleCommand.Reqs:
            ...

        @staticmethod
        def fromView(tool: ghidra.framework.plugintool.PluginTool, view: ghidra.trace.model.program.TraceProgramView) -> CurrentPlatformTraceDisassembleCommand.Reqs:
            ...

        def hashCode(self) -> int:
            ...

        def mapper(self) -> ghidra.debug.api.platform.DebuggerPlatformMapper:
            ...

        def object(self) -> ghidra.trace.model.target.TraceObject:
            ...

        def thread(self) -> ghidra.trace.model.thread.TraceThread:
            ...

        def toString(self) -> str:
            ...

        def view(self) -> ghidra.trace.model.program.TraceProgramView:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Disassemble"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, set: ghidra.program.model.address.AddressSetView, reqs: CurrentPlatformTraceDisassembleCommand.Reqs, address: ghidra.program.model.address.Address):
        ...


class CurrentPlatformTracePatchInstructionAction(AbstractTracePatchInstructionAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin):
        ...


class AbstractTracePatchInstructionAction(ghidra.app.plugin.core.assembler.PatchInstructionAction):

    @typing.type_check_only
    class PatchInstructionCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.program.TraceProgramView]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: jpype.JArray[jpype.JByte]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin, name: typing.Union[java.lang.String, str]):
        ...


class DebuggerDisassemblerPlugin(ghidra.framework.plugintool.Plugin, docking.actions.PopupActionProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def computeAutoDisassembleAddresses(start: ghidra.program.model.address.Address, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.AddressSetView:
        """
        Compute a lazy address set for restricting auto-disassembly
         
         
        
        The view contains the addresses in ``known | (readOnly & everKnown)``, where ``known`` is the set of addresses in the :obj:`TraceMemoryState.KNOWN` state, ``readOnly``
        is the set of addresses in a :obj:`TraceMemoryRegion` having
        :meth:`TraceMemoryRegion.isWrite(long) <TraceMemoryRegion.isWrite>` false, and ``everKnown`` is the set of addresses
        in the :obj:`TraceMemoryState.KNOWN` state in any previous snapshot.
         
         
        
        In plainer English, we want addresses that have freshly read bytes right now, or addresses in
        read-only memory that have ever been read. Anything else is either the default 0s (never
        read), or could have changed since last read, and so we will refrain from disassembling.
         
         
        
        TODO: Is this composition of laziness upon laziness efficient enough? Can experiment with
        ordering of address-set-view "expression" to optimize early termination.
        
        :param ghidra.program.model.address.Address start: the intended starting address for disassembly
        :param ghidra.trace.model.Trace trace: the trace whose memory to disassemble
        :param jpype.JLong or int snap: the current snapshot key, possibly a scratch snapshot
        :return: the lazy address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    def deriveAlternativeDefaultContext(language: ghidra.program.model.lang.Language, alternative: ghidra.program.model.lang.LanguageID, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        ...

    @staticmethod
    def isKnownRWOrEverKnownRO(start: ghidra.program.model.address.Address, trace: ghidra.trace.model.Trace, snap: typing.Union[jpype.JLong, int]) -> int:
        """
        Determine whether the given address is known, or has ever been known in read-only memory, for
        the given snapshot
         
         
        
        This first examines the memory state. If the current state is :obj:`TraceMemoryState.KNOWN`,
        then it returns the snap for the entry. (Because scratch snaps are allowed, the returned snap
        may be from an "earlier" snap in the viewport.) Then, it examines the most recent entry. If
        one cannot be found, or the found entry's state is *not*
        :obj:`TraceMemoryState.KNOWN`, it returns null. If the most recent (but not current) entry
        is :obj:`TraceMemoryState.KNOWN`, then it checks whether or not the memory is writable. If
        it's read-only, then the snap for that most-recent entry is returned. Otherwise, this check
        assumes the memory could have changed since, and so it returns null.
        
        :param ghidra.program.model.address.Address start: the address to check
        :param ghidra.trace.model.Trace trace: the trace whose memory to examine
        :param jpype.JLong or int snap: the lastest snapshot key, possibly a scratch snapshot, to consider
        :return: null to indicate the address failed the test, or the defining snapshot key if the
                address passed the test.
        :rtype: int
        """


class TracePatchDataAction(ghidra.app.plugin.core.assembler.PatchDataAction):

    @typing.type_check_only
    class PatchDataCommand(ghidra.framework.cmd.BackgroundCommand[ghidra.trace.model.program.TraceProgramView]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, encoded: jpype.JArray[jpype.JByte]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: DebuggerDisassemblerPlugin):
        ...



__all__ = ["FixedPlatformTraceDisassembleAction", "AbstractTraceDisassembleAction", "CurrentPlatformTraceDisassembleAction", "TraceDisassembleCommand", "FixedPlatformTracePatchInstructionAction", "DisassemblyInject", "CurrentPlatformTraceDisassembleCommand", "CurrentPlatformTracePatchInstructionAction", "AbstractTracePatchInstructionAction", "DebuggerDisassemblerPlugin", "TracePatchDataAction"]
