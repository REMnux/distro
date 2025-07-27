from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.plugintool
import java.lang # type: ignore
import javax.swing.event # type: ignore


class FallThroughPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class FallThroughModel(javax.swing.event.ChangeListener):
    """
    This class is really a model for the FallThroughDialog state.  However, it is used as a 
    convenience for executing the auto-override and clear-fallthrough actions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def stateChanged(self, e: javax.swing.event.ChangeEvent):
        ...


@typing.type_check_only
class FallThroughDialog(docking.DialogComponentProvider, javax.swing.event.ChangeListener):
    """
    Dialog to prompt for overriding a fallthrough address on an instruction.
    """

    class_: typing.ClassVar[java.lang.Class]

    def updateState(self):
        ...



__all__ = ["FallThroughPlugin", "FallThroughModel", "FallThroughDialog"]
