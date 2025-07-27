from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.main
import ghidra.framework.plugintool


@typing.type_check_only
class TipOfTheDayDialog(docking.ReusableDialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


class TipOfTheDayPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["TipOfTheDayDialog", "TipOfTheDayPlugin"]
