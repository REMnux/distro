from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.framework.main
import ghidra.framework.plugintool
import ghidra.util
import javax.swing # type: ignore


K = typing.TypeVar("K")
V = typing.TypeVar("V")


class RuntimeInfoPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelOnlyPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Creates a new :obj:`RuntimeInfoPlugin`
        
        :param ghidra.framework.plugintool.PluginTool tool: The tool
        """


@typing.type_check_only
class RuntimeInfoProvider(docking.ReusableDialogComponentProvider):
    """
    A dialog that shows useful runtime information
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class VersionInfoPanel(javax.swing.JPanel):
    """
    A :obj:`JPanel` that displays version information that would be useful to include in a bug 
    report, and provide a button that copies this information to the system clipboard
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class InstalledProcessorsProvider(docking.ReusableDialogComponentProvider):
    """
    A dialog that shows the supported platforms (processors, loaders, file systems, etc)
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MapTablePanel(javax.swing.JPanel, ghidra.util.Disposable, typing.Generic[K, V]):
    """
    A :obj:`JPanel` that displays a 2-column table created from a :obj:`Map`
    """

    @typing.type_check_only
    class MapModel(docking.widgets.table.GDynamicColumnTableModel[java.util.Map.Entry[K, V], java.util.List[java.util.Map.Entry[K, V]]]):

        @typing.type_check_only
        class KeyColumn(docking.widgets.table.AbstractDynamicTableColumn[java.util.Map.Entry[K, V], K, java.util.List[java.util.Map.Entry[K, V]]]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        @typing.type_check_only
        class ValueColumn(docking.widgets.table.AbstractDynamicTableColumn[java.util.Map.Entry[K, V], V, java.util.List[java.util.Map.Entry[K, V]]]):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class MemoryUsagePanel(javax.swing.JPanel, ghidra.util.Disposable):
    """
    A :obj:`JPanel` that displays live memory usage and provides a button to initiate garbage 
    collection on-demand
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["RuntimeInfoPlugin", "RuntimeInfoProvider", "VersionInfoPanel", "InstalledProcessorsProvider", "MapTablePanel", "MemoryUsagePanel"]
