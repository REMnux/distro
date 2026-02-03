from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.services
import ghidra.framework.plugintool


class DebuggerPlatformServicePlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerPlatformService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["DebuggerPlatformServicePlugin"]
