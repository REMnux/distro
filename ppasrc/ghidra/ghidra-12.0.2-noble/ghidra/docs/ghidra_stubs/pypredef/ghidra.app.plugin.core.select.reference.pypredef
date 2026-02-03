from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.context
import ghidra.framework.plugintool


class SelectBackRefsAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.NavigatableActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


class SelectRefsPlugin(ghidra.framework.plugintool.Plugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class SelectForwardRefsAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.NavigatableActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """



__all__ = ["SelectBackRefsAction", "SelectRefsPlugin", "SelectForwardRefsAction"]
