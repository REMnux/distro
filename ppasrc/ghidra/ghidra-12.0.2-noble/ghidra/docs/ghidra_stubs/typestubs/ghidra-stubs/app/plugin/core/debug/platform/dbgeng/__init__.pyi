from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.disassemble
import ghidra.app.plugin.core.debug.mapping
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.trace.model
import java.lang # type: ignore


class DbgengDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):

    @typing.type_check_only
    class Mode(java.lang.Enum[DbgengDebuggerPlatformOpinion.Mode]):

        class_: typing.ClassVar[java.lang.Class]
        X64: typing.Final[DbgengDebuggerPlatformOpinion.Mode]
        X86: typing.Final[DbgengDebuggerPlatformOpinion.Mode]
        UNK: typing.Final[DbgengDebuggerPlatformOpinion.Mode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DbgengDebuggerPlatformOpinion.Mode:
            ...

        @staticmethod
        def values() -> jpype.JArray[DbgengDebuggerPlatformOpinion.Mode]:
            ...


    @typing.type_check_only
    class AbstractDbgengX64DebuggerPlatformMapper(ghidra.app.plugin.core.debug.mapping.DefaultDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class DbgengX64DebuggerPlatformMapper(DbgengDebuggerPlatformOpinion.AbstractDbgengX64DebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class DbgengX64_32DebuggerPlatformMapper(DbgengDebuggerPlatformOpinion.AbstractDbgengX64DebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class DbgengWoW64DebuggerPlatformMapper(DbgengDebuggerPlatformOpinion.AbstractDbgengX64DebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class Offer(java.lang.Enum[DbgengDebuggerPlatformOpinion.Offer], ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]
        X64: typing.Final[DbgengDebuggerPlatformOpinion.Offer]
        X64_32: typing.Final[DbgengDebuggerPlatformOpinion.Offer]
        WOW64: typing.Final[DbgengDebuggerPlatformOpinion.Offer]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> DbgengDebuggerPlatformOpinion.Offer:
            ...

        @staticmethod
        def values() -> jpype.JArray[DbgengDebuggerPlatformOpinion.Offer]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DbgengX64DisassemblyInject(ghidra.app.plugin.core.debug.disassemble.DisassemblyInject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["DbgengDebuggerPlatformOpinion", "DbgengX64DisassemblyInject"]
