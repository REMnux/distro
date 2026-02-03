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


class OverrideDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):
    """
    An "opinion" which offers every known compiler, but with only default mapping logic.
    """

    @typing.type_check_only
    class OverridePlatformOffer(ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOffer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, description: typing.Union[java.lang.String, str], languageID: ghidra.program.model.lang.LanguageID, cSpecID: ghidra.program.model.lang.CompilerSpecID, confidence: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class OverrideDebuggerPlatformMapper(ghidra.app.plugin.core.debug.mapping.DefaultDebuggerPlatformMapper):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: ghidra.framework.plugintool.PluginTool, trace: ghidra.trace.model.Trace, cSpec: ghidra.program.model.lang.CompilerSpec):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["OverrideDebuggerPlatformOpinion"]
