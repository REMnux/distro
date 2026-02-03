from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.fieldpanel
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.util.task
import java.awt # type: ignore
import java.awt.print # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class CodeUnitPrintable(java.awt.print.Printable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, lm: docking.widgets.fieldpanel.LayoutModel, startIndex: typing.Union[jpype.JInt, int], endIndex: typing.Union[jpype.JInt, int], scaleAmount: typing.Union[jpype.JDouble, float], monitor: ghidra.util.task.TaskMonitor, pod: PrintOptionsDialog, book: java.awt.print.Book, job: java.awt.print.PrinterJob, startDate: java.util.Date):
        ...

    @typing.overload
    def __init__(self, lm: docking.widgets.fieldpanel.LayoutModel, layouts: java.util.List[docking.widgets.fieldpanel.Layout], scaleAmount: typing.Union[jpype.JDouble, float], monitor: ghidra.util.task.TaskMonitor, pod: PrintOptionsDialog, book: java.awt.print.Book, job: java.awt.print.PrinterJob, startDate: java.util.Date):
        ...


class PrintingPlugin(ghidra.app.plugin.ProgramPlugin):

    @typing.type_check_only
    class PrintAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class PageSetupAction(docking.action.DockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @staticmethod
    def getCategory() -> str:
        ...

    @staticmethod
    def getDescription() -> str:
        ...

    @staticmethod
    def getDescriptiveName() -> str:
        ...


class PrintOptionsDialog(docking.ReusableDialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def getHeaderFont(self) -> java.awt.Font:
        ...

    def getHeaderHeight(self) -> int:
        ...

    def getHeaderMetrics(self) -> java.awt.FontMetrics:
        ...

    def getMonochrome(self) -> bool:
        ...

    def getPrintDate(self) -> bool:
        ...

    def getPrintPageNum(self) -> bool:
        ...

    def getPrintTitle(self) -> bool:
        ...

    def getSelection(self) -> bool:
        ...

    def getView(self) -> bool:
        ...

    def getVisible(self) -> bool:
        ...

    def isCancelled(self) -> bool:
        ...

    def setFocusComponent(self):
        ...

    def setSelectionEnabled(self, selectionEnabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def showFooter(self) -> bool:
        ...

    def showHeader(self) -> bool:
        ...

    @property
    def view(self) -> jpype.JBoolean:
        ...

    @property
    def visible(self) -> jpype.JBoolean:
        ...

    @property
    def selection(self) -> jpype.JBoolean:
        ...

    @property
    def headerFont(self) -> java.awt.Font:
        ...

    @property
    def printDate(self) -> jpype.JBoolean:
        ...

    @property
    def printPageNum(self) -> jpype.JBoolean:
        ...

    @property
    def monochrome(self) -> jpype.JBoolean:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def headerMetrics(self) -> java.awt.FontMetrics:
        ...

    @property
    def headerHeight(self) -> jpype.JInt:
        ...

    @property
    def printTitle(self) -> jpype.JBoolean:
        ...



__all__ = ["CodeUnitPrintable", "PrintingPlugin", "PrintOptionsDialog"]
