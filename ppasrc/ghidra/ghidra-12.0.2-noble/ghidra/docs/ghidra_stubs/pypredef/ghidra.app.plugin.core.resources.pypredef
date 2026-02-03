from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool
import ghidra.util.filechooser


class ResourceActionsPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin that adds actions to manage data resources in the listing
    """

    class_: typing.ClassVar[java.lang.Class]
    GRAPHIC_FORMATS_FILTER: typing.Final[ghidra.util.filechooser.GhidraFileFilter]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ResourceActionsPlugin"]
