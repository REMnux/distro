from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.context
import ghidra.framework.plugintool
import ghidra.util.task


class QualifiedSelectionPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to extend selection features to include select data,
    select instructions and select undefined.  Selection will occur
    in the background with a status bar dialog that allows the user
    to cancel select process. If a selection exists then the new
    selection will be limited to a subset of the original selection.
    If there isn't a selection before the select action is invoked, then the
    select will be performed on the entire program.
    """

    @typing.type_check_only
    class SelectTask(ghidra.util.task.Task):
        """
        Handles the progress bar that allow select process to run in 
        the background
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class QualifiedSelectionAction(ghidra.app.context.NavigatableContextAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructs an instance of this plugin.
        
        :param ghidra.framework.plugintool.PluginTool tool: The tool required by this plugin to interact with its 
                environment.
        """



__all__ = ["QualifiedSelectionPlugin"]
