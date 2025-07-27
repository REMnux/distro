from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.framework.plugintool
import java.lang # type: ignore


class ScreenshotPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "ScreenshotPlugin"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ScreenshotPlugin"]
