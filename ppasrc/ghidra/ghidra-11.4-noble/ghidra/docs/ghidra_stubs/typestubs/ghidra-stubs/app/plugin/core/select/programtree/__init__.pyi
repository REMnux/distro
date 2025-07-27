from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.plugin
import ghidra.framework.plugintool


class ProgramTreeSelectionPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    This plugin adds the 'Select Addresses' command to the ProgramTree pop-up
    """

    @typing.type_check_only
    class TreeSelectAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def isEnabledForContext(self, context: docking.ActionContext) -> bool:
            """
            Determine if the Module Select action should be visible within
            the popup menu for the specified active object.
            
            :param activeObj: the object under the mouse location for the popup.:return: true if action should be made visible in popup menu.
            :rtype: bool
            """

        @property
        def enabledForContext(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ProgramTreeSelectionPlugin"]
