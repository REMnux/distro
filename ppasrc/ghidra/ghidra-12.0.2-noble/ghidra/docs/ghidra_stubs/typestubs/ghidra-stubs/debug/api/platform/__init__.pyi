from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model.guest
import ghidra.trace.model.target
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang # type: ignore


class DebuggerPlatformMapper(java.lang.Object):
    """
    An object for interpreting a trace according to a chosen platform
     
     
    
    Platform selection is a bit of a work in progress, but the idea is to allow the mapper to choose
    relevant languages, compiler specifications, data organization, etc., based on the current
    debugger context. Most of these are fairly straightforward and relatively static. If the back-end
    creates the trace with an actual language (non-DATA), then there's a default mapper for "known
    hosts," (but this can be out prioritized by more complex mappers). If the back-end creates a
    trace with a DATA language (usually indicating it doesn't recognize the target architecture),
    then some pluggable examine the name of the debugger and its reported architecture to try to map
    it on the front end. There may not be any good opinions, in which case, the user can override
    with any language. That's the "simple" cases.
     
     
    
    In more complex cases, e.g., WoW64, the mapper may need to adjust the recommended language based
    on, e.g., the current program counter and loaded modules. Essentially, it must determine the CPUs
    current ISA mode and adjust accordingly. There are currently two known situations: 1)
    Disassembly, and 2) Data (namely pointer) Organization, controlled by the Compiler Spec. The
    selection logic differs slightly between the two. For disassembly, we allow the mapper specific
    control of the selected platform, based on the starting address. For data placement, we allow the
    mapper specific control of the selected platform, based on the current PC. Note that the starting
    address of the data itself may not always be relevant. At the moment, because of limitations in
    the :obj:`Program` API, we actually cannot support selection based on placement address.
    Instead, at the time we ask the mapper to add a platform to the trace
    (:meth:`addToTrace(TraceObject, long) <.addToTrace>`), we provide the current focus and snap, so that it can
    derive the PC or whatever other context is necessary to make its decision. The returned platform
    is immediately set as current, so that data actions heed the chosen platform.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addToTrace(self, newFocus: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.guest.TracePlatform:
        """
        Prepare the given trace for interpretation under this mapper
         
         
        
        Likely, this will need to modify the trace database. It must start its own transaction for
        doing so.
        
        :param ghidra.trace.model.target.TraceObject newFocus: the newly-focused object
        :param jpype.JLong or int snap: the snap
        :return: the resulting platform, which may have already existed
        :rtype: ghidra.trace.model.guest.TracePlatform
        """

    def canInterpret(self, newFocus: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        When focus changes, decide if this mapper should remain active
        
        :param ghidra.trace.model.target.TraceObject newFocus: the newly-focused object
        :param jpype.JLong or int snap: the snap, usually the current snap
        :return: true to remain active, false to select a new mapper
        :rtype: bool
        """

    def disassemble(self, thread: ghidra.trace.model.thread.TraceThread, object: ghidra.trace.model.target.TraceObject, start: ghidra.program.model.address.Address, restricted: ghidra.program.model.address.AddressSetView, snap: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor) -> DisassemblyResult:
        """
        Disassemble starting at a given address and snap, limited to a given address set
         
         
        
        Note that the mapper may use an alternative platform than that returned by
        :meth:`addToTrace(TraceObject, long) <.addToTrace>`.
        
        :param ghidra.trace.model.thread.TraceThread thread: the thread if applicable
        :param ghidra.trace.model.target.TraceObject object: the object for platform context
        :param ghidra.program.model.address.Address start: the starting address
        :param ghidra.program.model.address.AddressSetView restricted: the limit of disassembly
        :param jpype.JLong or int snap: the snap, usually the current snap
        :param ghidra.util.task.TaskMonitor monitor: a monitor for the disassembler
        :return: the result
        :rtype: DisassemblyResult
        """

    def getCompilerSpec(self, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.lang.CompilerSpec:
        """
        Get the compiler for a given object
        
        :param ghidra.trace.model.target.TraceObject object: the object
        :param jpype.JLong or int snap: the snap
        :return: the compiler spec
        :rtype: ghidra.program.model.lang.CompilerSpec
        """

    def getLangauge(self, object: ghidra.trace.model.target.TraceObject, snap: typing.Union[jpype.JLong, int]) -> ghidra.program.model.lang.Language:
        """
        Get the language for a given object
        
        :param ghidra.trace.model.target.TraceObject object: the object
        :param jpype.JLong or int snap: the snap
        :return: the language
        :rtype: ghidra.program.model.lang.Language
        """


class DisassemblyResult(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    SUCCESS: typing.Final[DisassemblyResult]
    CANCELLED: typing.Final[DisassemblyResult]

    def __init__(self, atLeastOne: typing.Union[jpype.JBoolean, bool], errorMessage: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def failed(errorMessage: typing.Union[java.lang.String, str]) -> DisassemblyResult:
        ...

    def getErrorMessage(self) -> str:
        ...

    def isAtLeastOne(self) -> bool:
        ...

    def isSuccess(self) -> bool:
        ...

    @staticmethod
    def success(atLeastOne: typing.Union[jpype.JBoolean, bool]) -> DisassemblyResult:
        ...

    @property
    def atLeastOne(self) -> jpype.JBoolean:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...



__all__ = ["DebuggerPlatformMapper", "DisassemblyResult"]
