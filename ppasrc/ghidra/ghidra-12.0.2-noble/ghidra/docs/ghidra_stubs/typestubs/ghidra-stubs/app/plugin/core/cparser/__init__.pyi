from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class CParserPlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]
    PARSE_ACTION_NAME: typing.Final = "Import C DataTypes"

    def __init__(self, plugintool: ghidra.framework.plugintool.PluginTool):
        ...

    def getParseMessage(self) -> str:
        ...

    def getParseResults(self) -> ghidra.app.util.cparser.C.CParserUtils.CParseResults:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def isSingleton(self) -> bool:
        ...

    @property
    def singleton(self) -> jpype.JBoolean:
        ...

    @property
    def parseMessage(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def parseResults(self) -> ghidra.app.util.cparser.C.CParserUtils.CParseResults:
        ...


class IncludeFileFinder(java.lang.Object):

    @typing.type_check_only
    class IncludeFile(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getFile(self) -> java.io.File:
            ...

        def getRelativePath(self) -> str:
            ...

        @property
        def file(self) -> java.io.File:
            ...

        @property
        def relativePath(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, rootDir: jpype.protocol.SupportsPath):
        ...

    def getIncludeFileRoots(self, recursive: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        ...

    def getIncludeFiles(self, recursive: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @property
    def includeFileRoots(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def includeFiles(self) -> java.util.List[java.lang.String]:
        ...


@typing.type_check_only
class CParserTask(ghidra.util.task.Task):
    """
    Background task to parse files for cparser plugin
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: CParserPlugin, dataTypeManager: ghidra.program.model.data.DataTypeManager):
        """
        Create task to parse to a dataTypeManager
         
        NOTE: The Language ID and Compiler Spec ID must not be set since the dataTypeManager's
        current architecture will be used.
        
        :param CParserPlugin plugin: CParserPlugin that will do the work
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: target data type manager
        """

    def setCompilerID(self, compilerSpecId: typing.Union[java.lang.String, str]) -> CParserTask:
        """
        Set the compiler spec ID to be used.  This ID must be defined for the specified language.
         
        NOTE: The language ID must also be set, see ``#setLanguageID(String)``.
        See language *.ldefs file for defined compiler spec IDs or existing Program info.
        
        :param java.lang.String or str compilerSpecId: compiler spec ID
        :return: this task
        :rtype: CParserTask
        :raises UnsupportedOperationException: if task was constructed with a DataTypeManager whose
        existing architecture will be used.
        """

    def setFileNames(self, names: jpype.JArray[java.lang.String]) -> CParserTask:
        ...

    def setIncludePaths(self, includePaths: jpype.JArray[java.lang.String]) -> CParserTask:
        ...

    def setLanguageID(self, languageId: typing.Union[java.lang.String, str]) -> CParserTask:
        """
        Set the language ID to be used.
         
        NOTE: The compiler spec ID must also be set, see ``#setCompilerID(String)``.
        See language *.ldefs file for defined compiler spec IDs or existing Program info.
        
        :param java.lang.String or str languageId: language ID
        :return: this task
        :rtype: CParserTask
        :raises UnsupportedOperationException: if task was constructed with a DataTypeManager whose
        existing architecture will be used.
        """

    def setOptions(self, options: typing.Union[java.lang.String, str]) -> CParserTask:
        ...


@typing.type_check_only
class ParseDialog(docking.ReusableDialogComponentProvider):
    """
    Dialog that shows files used for parsing C header files. The profile has a list of source header
    files to parse, followed by parse options (compiler directives). Ghidra supplies a Windows
    profile by default in core/parserprofiles. The user can do "save as" on this default profile to
    create new profiles that will be written to the user's ``<home>/userprofiles`` directory. The
    CParserPlugin creates this directory if it doesn't exist.
     
    
    The data types resulting from the parse operation can either be added to the data type manager in
    the current program, or written to an archive data file.
    """

    @typing.type_check_only
    class ComboBoxItem(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getName(self) -> str:
            ...

        @property
        def name(self) -> java.lang.String:
            ...


    @typing.type_check_only
    class ComboBoxItemComparator(java.util.Comparator[ParseDialog.ComboBoxItem]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getParseOptions(self) -> str:
        ...

    def setupForDisplay(self):
        ...

    @property
    def parseOptions(self) -> java.lang.String:
        ...



__all__ = ["CParserPlugin", "IncludeFileFinder", "CParserTask", "ParseDialog"]
