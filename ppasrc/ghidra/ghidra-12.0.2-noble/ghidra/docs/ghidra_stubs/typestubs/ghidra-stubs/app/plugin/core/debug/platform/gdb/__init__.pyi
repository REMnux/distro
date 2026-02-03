from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.mapping
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.trace.model
import java.lang # type: ignore
import java.util # type: ignore


class GdbDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):

    @typing.type_check_only
    class GdbDebuggerPlatformOffer(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, description: typing.Union[java.lang.String, str], cSpec: ghidra.program.model.lang.CompilerSpec):
            ...

        @staticmethod
        def fromArchLCSP(arch: typing.Union[java.lang.String, str], lcsp: ghidra.program.model.lang.LanguageCompilerSpecPair) -> GdbDebuggerPlatformOpinion.GdbDebuggerPlatformOffer:
            ...


    @typing.type_check_only
    class GdbDebuggerPlatformMapper(ghidra.app.plugin.core.debug.mapping.DefaultDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    class_: typing.ClassVar[java.lang.Class]
    EXTERNAL_TOOL: typing.Final = "gnu"
    GCC_CSPEC_ID: typing.Final[ghidra.program.model.lang.CompilerSpecID]
    WINDOWS_CSPEC_ID: typing.Final[ghidra.program.model.lang.CompilerSpecID]

    def __init__(self):
        ...

    @staticmethod
    def getCompilerSpecsForGnu(arch: typing.Union[java.lang.String, str], os: typing.Union[java.lang.String, str], endian: ghidra.program.model.lang.Endian) -> java.util.List[ghidra.program.model.lang.LanguageCompilerSpecPair]:
        ...



__all__ = ["GdbDebuggerPlatformOpinion"]
