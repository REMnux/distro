from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.label
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ConditionResult(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, status: ConditionStatus) -> None:
        ...

    @typing.overload
    def __init__(self, status: ConditionStatus, message: typing.Union[java.lang.String, str]) -> None:
        ...

    def getMessage(self) -> str:
        ...

    def getStatus(self) -> ConditionStatus:
        ...

    @property
    def message(self) -> java.lang.String:
        ...

    @property
    def status(self) -> ConditionStatus:
        ...


class ConditionTester(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def run(self, monitor: ghidra.util.task.TaskMonitor) -> ConditionResult:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class ConditionTestPanel(javax.swing.JPanel):

    @typing.type_check_only
    class ScrollableLabel(docking.widgets.label.GDHtmlLabel, javax.swing.Scrollable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OverallProgressBar(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self) -> None:
            ...

        def setColor(self, color: java.awt.Color) -> None:
            ...

        def setMaxProgress(self, maxProgress: typing.Union[jpype.JInt, int]) -> None:
            ...

        def setProgress(self, progress: typing.Union[jpype.JInt, int]) -> None:
            ...


    @typing.type_check_only
    class TestPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, conditionTest: ConditionTester) -> None:
            ...

        def getTest(self) -> ConditionTester:
            ...

        def setSelected(self, selectedTest: ConditionTester) -> None:
            ...

        @property
        def test(self) -> ConditionTester:
            ...


    @typing.type_check_only
    class TestStatusPanel(javax.swing.JPanel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, test: ConditionTester) -> None:
            ...

        def getTest(self) -> ConditionTester:
            ...

        def setStatus(self, status: ConditionStatus) -> None:
            ...

        @property
        def test(self) -> ConditionTester:
            ...


    @typing.type_check_only
    class TestConditionRun(ConditionTester):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], runIterations: typing.Union[jpype.JInt, int]) -> None:
            ...

        @typing.overload
        def __init__(self, name: typing.Union[java.lang.String, str], runIterations: typing.Union[jpype.JInt, int], result: ConditionStatus, msg: typing.Union[java.lang.String, str]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tests: java.util.List[ConditionTester]) -> None:
        ...

    def addListener(self, listener: ConditionTestListener) -> None:
        ...

    def cancel(self) -> None:
        ...

    def getErrorCount(self) -> int:
        ...

    def getSkippedCount(self) -> int:
        ...

    def getWarningCount(self) -> int:
        ...

    def hasRunTests(self) -> bool:
        ...

    def isInProgress(self) -> bool:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]) -> None:
        ...

    def removeListener(self, listener: ConditionTestListener) -> None:
        ...

    def runTests(self) -> None:
        ...

    def skipTests(self) -> None:
        ...

    def testsCompleted(self) -> None:
        ...

    @property
    def inProgress(self) -> jpype.JBoolean:
        ...

    @property
    def skippedCount(self) -> jpype.JInt:
        ...

    @property
    def warningCount(self) -> jpype.JInt:
        ...

    @property
    def errorCount(self) -> jpype.JInt:
        ...


class ConditionTestState(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, conditionTest: ConditionTester) -> None:
        ...

    def getConditionTest(self) -> ConditionTester:
        ...

    def getName(self) -> str:
        ...

    def getStatus(self) -> ConditionStatus:
        ...

    def getStatusMessage(self) -> str:
        ...

    def isEnabled(self) -> bool:
        ...

    def setEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def setResult(self, result: ConditionResult) -> None:
        ...

    @property
    def conditionTest(self) -> ConditionTester:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def enabled(self) -> jpype.JBoolean:
        ...

    @enabled.setter
    def enabled(self, value: jpype.JBoolean):
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...

    @property
    def status(self) -> ConditionStatus:
        ...


class ConditionTestListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def testsCompleted(self) -> None:
        ...


class ConditionStatus(java.lang.Enum[ConditionStatus]):

    class_: typing.ClassVar[java.lang.Class]
    None_: typing.Final[ConditionStatus]
    Passed: typing.Final[ConditionStatus]
    Warning: typing.Final[ConditionStatus]
    Error: typing.Final[ConditionStatus]
    Cancelled: typing.Final[ConditionStatus]
    Skipped: typing.Final[ConditionStatus]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ConditionStatus:
        ...

    @staticmethod
    def values() -> jpype.JArray[ConditionStatus]:
        ...


class ConditionTestModel(java.lang.Object):

    @typing.type_check_only
    class ConditionTestRunner(java.lang.Thread):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, conditionTestPanel: ConditionTestPanel, tests: java.util.List[ConditionTester]) -> None:
        ...

    def getCompletedTestCount(self) -> int:
        ...

    def getErrorCount(self) -> int:
        ...

    def getSkippedCount(self) -> int:
        ...

    def getStatus(self, test: ConditionTester) -> ConditionStatus:
        ...

    def getStatusMessage(self, test: ConditionTester) -> str:
        ...

    def getTestCount(self) -> int:
        ...

    def getTests(self) -> java.util.List[ConditionTester]:
        ...

    def getWarningCount(self) -> int:
        ...

    @typing.overload
    def isInProgress(self) -> bool:
        ...

    @typing.overload
    def isInProgress(self, test: ConditionTester) -> bool:
        ...

    def runTests(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        ...

    def setEnabled(self, test: ConditionTester, enabled: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def skipTests(self) -> None:
        ...

    def skippingTest(self, test: ConditionTester) -> None:
        ...

    @property
    def testCount(self) -> jpype.JInt:
        ...

    @property
    def tests(self) -> java.util.List[ConditionTester]:
        ...

    @property
    def inProgress(self) -> jpype.JBoolean:
        ...

    @property
    def completedTestCount(self) -> jpype.JInt:
        ...

    @property
    def skippedCount(self) -> jpype.JInt:
        ...

    @property
    def warningCount(self) -> jpype.JInt:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...

    @property
    def errorCount(self) -> jpype.JInt:
        ...

    @property
    def status(self) -> ConditionStatus:
        ...



__all__ = ["ConditionResult", "ConditionTester", "ConditionTestPanel", "ConditionTestState", "ConditionTestListener", "ConditionStatus", "ConditionTestModel"]
