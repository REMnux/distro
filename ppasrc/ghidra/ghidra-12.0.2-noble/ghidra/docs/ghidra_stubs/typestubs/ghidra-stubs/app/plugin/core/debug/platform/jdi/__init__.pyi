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


class JdiDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):

    @typing.type_check_only
    class JdiDebuggerPlatformMapper(ghidra.app.plugin.core.debug.mapping.DefaultDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class Offers(java.lang.Enum[JdiDebuggerPlatformOpinion.Offers], ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]
        JAVA_VM: typing.Final[JdiDebuggerPlatformOpinion.Offers]
        DALVIK_VM: typing.Final[JdiDebuggerPlatformOpinion.Offers]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> JdiDebuggerPlatformOpinion.Offers:
            ...

        @staticmethod
        def values() -> jpype.JArray[JdiDebuggerPlatformOpinion.Offers]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["JdiDebuggerPlatformOpinion"]
