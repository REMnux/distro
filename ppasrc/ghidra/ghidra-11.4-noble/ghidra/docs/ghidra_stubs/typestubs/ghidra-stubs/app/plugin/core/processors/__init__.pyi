from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.context
import ghidra.app.plugin
import ghidra.app.plugin.processors.sleigh
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import javax.swing.table # type: ignore


@typing.type_check_only
class ShowProcessorManualAction(ghidra.app.context.ProgramContextAction):
    """
    Action class for displaying the processor manual (PDF file)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ShowInstructionInfoPlugin):
        ...


@typing.type_check_only
class ShowInfoAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ShowInstructionInfoPlugin):
        ...


class SetLanguageDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, programArch: ghidra.program.model.lang.ProgramArchitecture, title: typing.Union[java.lang.String, str]):
        """
        Construct set Language/Compiler-Spec dialog
        
        :param ghidra.framework.plugintool.PluginTool tool: parent tool
        :param ghidra.program.model.lang.ProgramArchitecture programArch: current program architecture or null
        :param java.lang.String or str title: dialog title
        """

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, languageId: typing.Union[java.lang.String, str], compilerSpecId: typing.Union[java.lang.String, str], title: typing.Union[java.lang.String, str]):
        """
        Construct set Language/Compiler-Spec dialog
        
        :param ghidra.framework.plugintool.PluginTool tool: parent tool
        :param java.lang.String or str languageId: initial language ID or null
        :param java.lang.String or str compilerSpecId: initial Compiler-Spec ID or null
        :param java.lang.String or str title: dialog title
        """

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, lcsPair: ghidra.program.model.lang.LanguageCompilerSpecPair, title: typing.Union[java.lang.String, str]):
        """
        Construct set Language/Compiler-Spec dialog
        
        :param ghidra.framework.plugintool.PluginTool tool: parent tool
        :param ghidra.program.model.lang.LanguageCompilerSpecPair lcsPair: language/compiler-spec ID pair or null
        :param java.lang.String or str title: dialog title
        """

    def getCompilerSpecDescriptionID(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...

    def getLanguageDescriptionID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def compilerSpecDescriptionID(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...

    @property
    def languageDescriptionID(self) -> ghidra.program.model.lang.LanguageID:
        ...


class LanguageProviderPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin):

    @typing.type_check_only
    class SetLanguageTask(ghidra.util.task.Task):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, domainFile: ghidra.framework.model.DomainFile):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        ...


@typing.type_check_only
class InstructionInfoProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.framework.model.DomainObjectListener):
    """
    Component provider to show the instruction info.
    """

    @typing.type_check_only
    class OperandModel(javax.swing.table.DefaultTableModel):

        class_: typing.ClassVar[java.lang.Class]

        def getColumnCount(self) -> int:
            """
            Returns the number of columns in this data table.
            
            :return: the number of columns in the model
            :rtype: int
            """

        def getColumnName(self, column: typing.Union[jpype.JInt, int]) -> str:
            """
            Returns the column name.
            
            :return: a name for this column using the string value of the
            appropriate member in *columnIdentfiers*. If *columnIdentfiers*
            is null or does not have and entry for this index return the default
            name provided by the superclass.
            :rtype: str
            """

        def getRowCount(self) -> int:
            """
            Returns the number of rows in this data table.
            
            :return: the number of rows in the model
            :rtype: int
            """

        def getValueAt(self, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]) -> java.lang.Object:
            """
            Returns an attribute value for the cell at *row*
            and *column*.
            
            :param jpype.JInt or int row: the row whose value is to be looked up
            :param jpype.JInt or int column: the column whose value is to be looked up
            :return: the value Object at the specified cell
            :rtype: java.lang.Object
            :raises ArrayIndexOutOfBoundsException: if an invalid row or
                        column was given.
            """

        def setInstruction(self, instruction: ghidra.program.model.listing.Instruction, debug: ghidra.app.plugin.processors.sleigh.SleighDebugLogger):
            ...

        @property
        def rowCount(self) -> jpype.JInt:
            ...

        @property
        def columnCount(self) -> jpype.JInt:
            ...

        @property
        def columnName(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def setNonDynamic(self):
        ...

    @property
    def instruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class ShowInstructionInfoPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def remove(self, provider: InstructionInfoProvider):
        """
        Remove this InstructionProvider from list of managed dialogs
        
        :param InstructionInfoProvider provider: the provider to remove
        """



__all__ = ["ShowProcessorManualAction", "ShowInfoAction", "SetLanguageDialog", "LanguageProviderPlugin", "InstructionInfoProvider", "ShowInstructionInfoPlugin"]
