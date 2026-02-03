from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.conditiontestpanel
import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.lang # type: ignore
import java.util # type: ignore


class ValidateProgramDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, list: java.util.List[docking.widgets.conditiontestpanel.ConditionTester]):
        ...


class ValidateProgramPlugin(ghidra.framework.plugintool.Plugin):
    """
    Display a pop-up dialog to run PostAnalysisValidator tests on the Program
    that is currently open in the tool.
    """

    @typing.type_check_only
    class ConditionsComparator(java.util.Comparator[docking.widgets.conditiontestpanel.ConditionTester]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    PLUGIN_NAME: typing.Final = "ValidateProgramPlugin"
    ACTION_NAME: typing.Final = "Validate Program"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ValidateProgramDialog", "ValidateProgramPlugin"]
