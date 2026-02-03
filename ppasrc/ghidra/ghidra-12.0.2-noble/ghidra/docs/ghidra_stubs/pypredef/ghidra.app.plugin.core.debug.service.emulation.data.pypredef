from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.debug.api.emulation
import ghidra.debug.api.target
import ghidra.framework.plugintool
import ghidra.pcode.exec_.trace.data
import ghidra.trace.model.guest


L = typing.TypeVar("L")
S = typing.TypeVar("S")
T = typing.TypeVar("T")


class AbstractPcodeDebuggerAccess(ghidra.pcode.exec_.trace.data.AbstractPcodeTraceAccess[S, L], ghidra.debug.api.emulation.PcodeDebuggerAccess, typing.Generic[S, L]):
    """
    An abstract implementation of :obj:`PcodeDebuggerAccess`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ghidra.framework.plugintool.ServiceProvider, target: ghidra.debug.api.target.Target, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform, having the same trace as the recorder
        :param jpype.JLong or int snap: the associated snap
        """

    @typing.overload
    def __init__(self, provider: ghidra.framework.plugintool.ServiceProvider, target: ghidra.debug.api.target.Target, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], threadsSnap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform, having the same trace as the recorder
        :param jpype.JLong or int snap: the associated snap
        :param jpype.JLong or int threadsSnap: the snap to use when finding associated threads between trace and emulator
        """


class DefaultPcodeDebuggerPropertyAccess(ghidra.pcode.exec_.trace.data.DefaultPcodeTracePropertyAccess[T], typing.Generic[T]):
    """
    The default trace-and-debugger-property access shim
    
     
    
    This implementation defers to the same property of mapped static images when the property is not
    set in the trace.
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultPcodeDebuggerMemoryAccess(ghidra.pcode.exec_.trace.data.DefaultPcodeTraceMemoryAccess, ghidra.debug.api.emulation.PcodeDebuggerMemoryAccess, InternalPcodeDebuggerDataAccess):
    """
    The default data-and-debugger-access shim for session memory
    """

    class_: typing.ClassVar[java.lang.Class]


class InternalPcodeDebuggerDataAccess(ghidra.pcode.exec_.trace.data.InternalPcodeTraceDataAccess):

    class_: typing.ClassVar[java.lang.Class]

    def getServiceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    def getTarget(self) -> ghidra.debug.api.target.Target:
        ...

    def isLive(self) -> bool:
        ...

    @property
    def serviceProvider(self) -> ghidra.framework.plugintool.ServiceProvider:
        ...

    @property
    def live(self) -> jpype.JBoolean:
        ...

    @property
    def target(self) -> ghidra.debug.api.target.Target:
        ...


class DefaultPcodeDebuggerRegistersAccess(ghidra.pcode.exec_.trace.data.DefaultPcodeTraceRegistersAccess, ghidra.debug.api.emulation.PcodeDebuggerRegistersAccess, InternalPcodeDebuggerDataAccess):
    """
    The default data-and-debugger access shim for session registers
    """

    class_: typing.ClassVar[java.lang.Class]


class DefaultPcodeDebuggerAccess(AbstractPcodeDebuggerAccess[DefaultPcodeDebuggerMemoryAccess, DefaultPcodeDebuggerRegistersAccess]):
    """
    The default target-and-trace access shim for a session
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: ghidra.framework.plugintool.ServiceProvider, target: ghidra.debug.api.target.Target, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform, having the same trace as the recorder
        :param jpype.JLong or int snap: the associated snap
        """

    @typing.overload
    def __init__(self, provider: ghidra.framework.plugintool.ServiceProvider, target: ghidra.debug.api.target.Target, platform: ghidra.trace.model.guest.TracePlatform, snap: typing.Union[jpype.JLong, int], threadsSnap: typing.Union[jpype.JLong, int]):
        """
        Construct a shim
        
        :param ghidra.framework.plugintool.ServiceProvider provider: the service provider (usually the tool)
        :param ghidra.debug.api.target.Target target: the target
        :param ghidra.trace.model.guest.TracePlatform platform: the associated platform, having the same trace as the recorder
        :param jpype.JLong or int snap: the associated snap
        :param jpype.JLong or int threadsSnap: the snap to use when finding associated threads between trace and emulator
        """



__all__ = ["AbstractPcodeDebuggerAccess", "DefaultPcodeDebuggerPropertyAccess", "DefaultPcodeDebuggerMemoryAccess", "InternalPcodeDebuggerDataAccess", "DefaultPcodeDebuggerRegistersAccess", "DefaultPcodeDebuggerAccess"]
