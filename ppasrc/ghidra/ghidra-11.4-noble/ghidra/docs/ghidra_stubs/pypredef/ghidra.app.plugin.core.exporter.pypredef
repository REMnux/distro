from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.util
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.util
import ghidra.util.task
import java.util # type: ignore


class ExporterDialog(docking.DialogComponentProvider, ghidra.app.util.AddressFactoryService):
    """
    Dialog for exporting a program from a Ghidra project to an external file in one of the
    supported export formats.
    """

    @typing.type_check_only
    class ExportTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile):
        """
        Construct a new ExporterDialog for exporting an entire program.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool that launched this dialog.
        :param ghidra.framework.model.DomainFile domainFile: the program to export
        """

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile, domainObject: ghidra.framework.model.DomainObject, selection: ghidra.program.util.ProgramSelection):
        """
        Construct a new ExporterDialog for exporting a program, optionally only exported a
        selected region.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool that launched this dialog.
        :param ghidra.framework.model.DomainFile domainFile: the program file to export. (may be proxy)
        :param ghidra.framework.model.DomainObject domainObject: the program to export if already open, otherwise null.
        :param ghidra.program.util.ProgramSelection selection: the current program selection (ignored for FrontEnd Tool).
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Gets the address factory for the program to be exported, opening it if necessary.
        """

    def getOptions(self) -> java.util.List[ghidra.app.util.Option]:
        ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def options(self) -> java.util.List[ghidra.app.util.Option]:
        ...


class ExporterPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["ExporterDialog", "ExporterPlugin"]
