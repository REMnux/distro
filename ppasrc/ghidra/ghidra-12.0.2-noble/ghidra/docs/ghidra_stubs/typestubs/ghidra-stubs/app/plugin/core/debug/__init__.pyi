from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.lang # type: ignore


class AbstractDebuggerPlugin(ghidra.framework.plugintool.Plugin):
    """
    All this really does anymore is handle the auto-service wiring thing
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DebuggerPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Debugger"

    def __init__(self):
        ...



__all__ = ["AbstractDebuggerPlugin", "DebuggerPluginPackage"]
