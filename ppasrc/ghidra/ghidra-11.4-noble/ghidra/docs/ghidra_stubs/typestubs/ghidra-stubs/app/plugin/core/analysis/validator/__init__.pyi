from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.conditiontestpanel
import ghidra.program.model.listing
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore


class OffcutReferencesValidator(PostAnalysisValidator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class PostAnalysisValidator(docking.widgets.conditiontestpanel.ConditionTester, ghidra.util.classfinder.ExtensionPoint):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    def doRun(self, monitor: ghidra.util.task.TaskMonitor) -> docking.widgets.conditiontestpanel.ConditionResult:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def run(self, monitor: ghidra.util.task.TaskMonitor) -> docking.widgets.conditiontestpanel.ConditionResult:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class RedFlagsValidator(PostAnalysisValidator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...


class PercentAnalyzedValidator(PostAnalysisValidator):

    class_: typing.ClassVar[java.lang.Class]
    COVERAGE_THRESHOLD: typing.Final = "Minimum analysis coverage threshold"
    COVERAGE_THRESHOLD_DEFAULT: typing.Final = 0.75

    def __init__(self, program: ghidra.program.model.listing.Program):
        ...



__all__ = ["OffcutReferencesValidator", "PostAnalysisValidator", "RedFlagsValidator", "PercentAnalyzedValidator"]
