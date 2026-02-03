from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.context
import ghidra.app.plugin
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.util.task


@typing.type_check_only
class SelectByFlowAction(ghidra.app.context.ListingContextAction):
    """
    ``SelectByFlowAction`` allows the user to Select Code By Flowing from
    the current program selection or by location if there is no selection.
    
    Base class for actions in SelectByFlowPlugin.
    """

    class_: typing.ClassVar[java.lang.Class]


class SelectByFlowPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.options.OptionsChangeListener):
    """
    The SelectByFlowPlugin adds selection of code based on program flow to a
    tool. Selection is based on the initial selection or if there is no selection
    then on where the cursor is located in the program.
    
    This plugin provides the following types of selection:
    
     
    * Select by following the flow from the specified address(es) onward.
    Properties indicate whether or not CALLS or JUMPS should be followed.
    * Select the subroutine(s) for the specified address(es).
    * Select the function(s) for the specified address(es).
    * Select dead subroutine(s) for the specified address(es).
    * Select the current program changes.
    * Select by following the flow to the specified address(es).
    Properties indicate whether or not CALLS or JUMPS should be followed.
    """

    class SelectByFlowTask(ghidra.util.task.Task):
        """
        Task for computing selection
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SELECT_ALL_FLOWS_FROM: typing.ClassVar[jpype.JInt]
    SELECT_LIMITED_FLOWS_FROM: typing.ClassVar[jpype.JInt]
    SELECT_SUBROUTINES: typing.ClassVar[jpype.JInt]
    SELECT_FUNCTIONS: typing.ClassVar[jpype.JInt]
    SELECT_DEAD_SUBROUTINES: typing.ClassVar[jpype.JInt]
    SELECT_ALL_FLOWS_TO: typing.ClassVar[jpype.JInt]
    SELECT_LIMITED_FLOWS_TO: typing.ClassVar[jpype.JInt]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getFlowTypesNotToFollow(self) -> jpype.JArray[ghidra.program.model.symbol.FlowType]:
        """
        Determines the flow types that we do not want to follow according to the
        follow flow properties that are set to false.
        
        :return: array of FlowTypes that should not be followed based on the
        current SelectByFlow property settings.
        :rtype: jpype.JArray[ghidra.program.model.symbol.FlowType]
        """

    @property
    def flowTypesNotToFollow(self) -> jpype.JArray[ghidra.program.model.symbol.FlowType]:
        ...


class SelectByScopedFlowPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    This plugin class contains the structure needed for the user to select code
    blocks that are only reachable by following the flow from the current program
    location (they are unreachable from any other starting point).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["SelectByFlowAction", "SelectByFlowPlugin", "SelectByScopedFlowPlugin"]
