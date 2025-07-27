from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang # type: ignore
import javax.swing.table # type: ignore


@typing.type_check_only
class PropertyManagerTableModel(javax.swing.table.AbstractTableModel):

    class_: typing.ClassVar[java.lang.Class]

    def getColumnCount(self) -> int:
        ...

    def getRowCount(self) -> int:
        ...

    def getValueAt(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        ...

    def update(self, program: ghidra.program.model.listing.Program, addrSet: ghidra.program.model.address.AddressSetView):
        """
        
        
        :param currentProgram: :param currentSelection: :param searchMarks:
        """

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...


class PropertyManagerPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.framework.model.DomainObjectListener):
    """
    PropertyManagerPlugin
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class PropertyDeleteCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    PropertyDeletedCmd
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, propName: typing.Union[java.lang.String, str], restrictedView: ghidra.program.model.address.AddressSetView):
        """
        Construct command for deleting program properties
        
        :param java.lang.String or str propName: property name
        :param ghidra.program.model.address.AddressSetView restrictedView: set of address over which properties will be removed.
        If this is null or empty, all occurances of the property will be removed.
        """


class PropertyManagerProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    PropertyManagerDialog
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: PropertyManagerPlugin):
        ...



__all__ = ["PropertyManagerTableModel", "PropertyManagerPlugin", "PropertyDeleteCmd", "PropertyManagerProvider"]
