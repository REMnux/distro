from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import help
import help.validator.model
import java.io # type: ignore
import java.lang # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import javax.help # type: ignore


class GeneratedDirectoryHelpModuleLocation(DirectoryHelpModuleLocation):
    """
    Represents a directory that holds generated content.  At the time of writing, the only known 
    such input is the 'tips of the day' html file that is created from a text file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath):
        ...


class HelpModuleCollection(help.TOCItemProvider):
    """
    A class that is meant to hold a single help **input** directory and 0 or more
    **external, pre-built** help sources (i.e., jar file or directory).
     
                            Note
                            Note
                            Note
    
    This class is a bit conceptually muddled.  Our build system is reflected in this class in that
    we currently build one help module at a time.  Thus, any dependencies of that module being
    built can be passed into this "collection" at build time.   We used to build multiple help
    modules at once, resolving dependencies for all of the input modules after we built each
    module.  This class will need to be tweaked in order to go back to a build system with
    multiple input builds.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addGeneratedHelpLocation(self, file: jpype.protocol.SupportsPath):
        ...

    def containsHelpFiles(self) -> bool:
        ...

    @staticmethod
    def fromFiles(files: collections.abc.Sequence) -> HelpModuleCollection:
        """
        Creates a help module collection that assumes zero or more pre-built help jar files and
        one help directory that is an input into the help building process.
        
        :param collections.abc.Sequence files: the files from which to get help
        :return: the help collection
        :rtype: HelpModuleCollection
        """

    @staticmethod
    def fromHelpDirectory(dir: jpype.protocol.SupportsPath) -> HelpModuleCollection:
        """
        Creates a help module collection that contains only a singe help module from a help
        directory, not a pre-built help jar.
        
        :param jpype.protocol.SupportsPath dir: the directory containing help
        :return: the help collection
        :rtype: HelpModuleCollection
        """

    @staticmethod
    def fromHelpLocations(locations: collections.abc.Sequence) -> HelpModuleCollection:
        """
        Creates a help module collection that assumes zero or more pre-built help jar files and
        one help directory that is an input into the help building process.
        
        :param collections.abc.Sequence locations: the locations from which to get help
        :return: the help collection
        :rtype: HelpModuleCollection
        """

    def getAllAnchorDefinitions(self) -> java.util.Collection[help.validator.model.AnchorDefinition]:
        ...

    def getAllHREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    def getAllIMGs(self) -> java.util.Collection[help.validator.model.IMG]:
        ...

    def getAnchorDefinition(self, target: jpype.protocol.SupportsPath) -> help.validator.model.AnchorDefinition:
        ...

    def getDuplicateAnchorsByFile(self) -> java.util.Map[help.validator.model.HelpFile, java.util.Map[java.lang.String, java.util.List[help.validator.model.AnchorDefinition]]]:
        ...

    def getDuplicateAnchorsByTopic(self) -> java.util.Map[help.validator.model.HelpTopic, java.util.List[help.validator.model.AnchorDefinition]]:
        ...

    def getHelpFile(self, helpPath: jpype.protocol.SupportsPath) -> help.validator.model.HelpFile:
        ...

    def getHelpRoots(self) -> java.util.Collection[java.nio.file.Path]:
        ...

    def getInputTOCItems(self) -> java.util.Collection[help.validator.model.TOCItem]:
        """
        Input TOC items are those that we are building for the input help module of this collection
        
        :return: the items
        :rtype: java.util.Collection[help.validator.model.TOCItem]
        """

    def getSourceTOCFile(self) -> help.validator.model.GhidraTOCFile:
        ...

    def getTOC_HREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    @property
    def inputTOCItems(self) -> java.util.Collection[help.validator.model.TOCItem]:
        ...

    @property
    def duplicateAnchorsByFile(self) -> java.util.Map[help.validator.model.HelpFile, java.util.Map[java.lang.String, java.util.List[help.validator.model.AnchorDefinition]]]:
        ...

    @property
    def tOC_HREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    @property
    def duplicateAnchorsByTopic(self) -> java.util.Map[help.validator.model.HelpTopic, java.util.List[help.validator.model.AnchorDefinition]]:
        ...

    @property
    def helpRoots(self) -> java.util.Collection[java.nio.file.Path]:
        ...

    @property
    def helpFile(self) -> help.validator.model.HelpFile:
        ...

    @property
    def allHREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    @property
    def anchorDefinition(self) -> help.validator.model.AnchorDefinition:
        ...

    @property
    def allIMGs(self) -> java.util.Collection[help.validator.model.IMG]:
        ...

    @property
    def allAnchorDefinitions(self) -> java.util.Collection[help.validator.model.AnchorDefinition]:
        ...

    @property
    def sourceTOCFile(self) -> help.validator.model.GhidraTOCFile:
        ...


class HelpModuleLocation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAllHREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    def getAllIMGs(self) -> java.util.Collection[help.validator.model.IMG]:
        ...

    def getHelpLocation(self) -> java.nio.file.Path:
        ...

    def getHelpModuleLocation(self) -> java.nio.file.Path:
        ...

    def getHelpTopics(self) -> java.util.Collection[help.validator.model.HelpTopic]:
        ...

    def getModuleRepoRoot(self) -> java.nio.file.Path:
        ...

    def isHelpInputSource(self) -> bool:
        """
        Returns true if this help location represents a source of input files to generate help output
        
        :return: true if this help location represents a source of input files to generate help output
        :rtype: bool
        """

    def loadHelpSet(self) -> javax.help.HelpSet:
        ...

    def loadSourceTOCFile(self) -> help.validator.model.GhidraTOCFile:
        ...

    @property
    def helpTopics(self) -> java.util.Collection[help.validator.model.HelpTopic]:
        ...

    @property
    def helpModuleLocation(self) -> java.nio.file.Path:
        ...

    @property
    def helpLocation(self) -> java.nio.file.Path:
        ...

    @property
    def moduleRepoRoot(self) -> java.nio.file.Path:
        ...

    @property
    def allHREFs(self) -> java.util.Collection[help.validator.model.HREF]:
        ...

    @property
    def allIMGs(self) -> java.util.Collection[help.validator.model.IMG]:
        ...

    @property
    def helpInputSource(self) -> jpype.JBoolean:
        ...


class JarHelpModuleLocation(HelpModuleLocation):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def fromFile(jar: jpype.protocol.SupportsPath) -> JarHelpModuleLocation:
        ...


class DirectoryHelpModuleLocation(HelpModuleLocation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath):
        ...



__all__ = ["GeneratedDirectoryHelpModuleLocation", "HelpModuleCollection", "HelpModuleLocation", "JarHelpModuleLocation", "DirectoryHelpModuleLocation"]
