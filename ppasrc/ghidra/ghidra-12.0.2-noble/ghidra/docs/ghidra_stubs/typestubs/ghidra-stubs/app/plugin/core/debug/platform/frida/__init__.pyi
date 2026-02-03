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


class FridaDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):

    @typing.type_check_only
    class FridaDebuggerPlatformMapper(ghidra.app.plugin.core.debug.mapping.DefaultDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    @typing.type_check_only
    class Offers(java.lang.Enum[FridaDebuggerPlatformOpinion.Offers], ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]
        AARCH64_MACOS: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        I386_LINUX: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        I386_MACOS: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        I386_WINDOWS: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        X86_64_LINUX: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        X86_64_MACOS: typing.Final[FridaDebuggerPlatformOpinion.Offers]
        X86_64_WINDOWS: typing.Final[FridaDebuggerPlatformOpinion.Offers]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FridaDebuggerPlatformOpinion.Offers:
            ...

        @staticmethod
        def values() -> jpype.JArray[FridaDebuggerPlatformOpinion.Offers]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["FridaDebuggerPlatformOpinion"]
