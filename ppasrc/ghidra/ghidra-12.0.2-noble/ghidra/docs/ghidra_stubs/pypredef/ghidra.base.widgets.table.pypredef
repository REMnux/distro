from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.app.services
import ghidra.framework.plugintool
import javax.swing # type: ignore
import javax.swing.table # type: ignore


class DataTypeTableCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, docking.widgets.table.FocusableEditor):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, service: ghidra.app.services.DataTypeManagerService):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["DataTypeTableCellEditor"]
