from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework.main
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.lang
import ghidra.util
import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.regex # type: ignore


class AboutProgramPlugin(ghidra.framework.plugintool.Plugin, ghidra.framework.main.ApplicationLevelPlugin):
    """
    Display a pop-up dialog containing information about the Domain Object that is currently open in
    the tool.
    """

    @typing.type_check_only
    class LcspAndVersion(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]
        LANG_PAT: typing.Final[java.util.regex.Pattern]

        def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        @staticmethod
        def fromMetadata(metadata: collections.abc.Mapping) -> AboutProgramPlugin.LcspAndVersion:
            """
            
            
            :param collections.abc.Mapping metadata: the metadata
            :return: the parsed language, compiler spec, and language version
            :rtype: AboutProgramPlugin.LcspAndVersion
            
            .. seealso::
            
                | :obj:`ProgramDB.getMetadata()`
            """

        def getVersionDisplay(self) -> str:
            ...

        def hashCode(self) -> int:
            ...

        def isMismatch(self) -> bool:
            ...

        def language(self) -> ghidra.program.model.lang.Language:
            ...

        def languageMinorVersion(self) -> int:
            ...

        def languageVersion(self) -> int:
            ...

        def toString(self) -> str:
            ...

        @property
        def versionDisplay(self) -> java.lang.String:
            ...

        @property
        def mismatch(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    PLUGIN_NAME: typing.Final = "AboutProgramPlugin"
    ACTION_NAME: typing.Final = "About Program"

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class AboutDomainObjectUtils(java.lang.Object):

    @typing.type_check_only
    class Dialog(docking.DialogComponentProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PopupMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def displayInformation(tool: ghidra.framework.plugintool.PluginTool, domainFile: ghidra.framework.model.DomainFile, metadata: collections.abc.Mapping, title: typing.Union[java.lang.String, str], additionalInfo: typing.Union[java.lang.String, str], helpLocation: ghidra.util.HelpLocation):
        """
        Displays an informational dialog about the specified domain object
        
        :param ghidra.framework.plugintool.PluginTool tool: plugin tool
        :param ghidra.framework.model.DomainFile domainFile: domain file to display information about
        :param collections.abc.Mapping metadata: the metadata for the domainFile
        :param java.lang.String or str title: title to use for the dialog
        :param java.lang.String or str additionalInfo: additional custom user information to append to
                            the bottom of the dialog
        :param ghidra.util.HelpLocation helpLocation: the help location
        """



__all__ = ["AboutProgramPlugin", "AboutDomainObjectUtils"]
