from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import help
import help.validator.links
import help.validator.location
import help.validator.model
import java.lang # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore


class JavaHelpValidator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    EXTERNAL_PREFIX: typing.Final = "external:"

    def __init__(self, moduleName: typing.Union[java.lang.String, str], help: help.validator.location.HelpModuleCollection):
        ...

    def setDebugEnabled(self, debug: typing.Union[jpype.JBoolean, bool]):
        ...

    def validate(self, linkDatabase: LinkDatabase) -> java.util.Collection[help.validator.links.InvalidLink]:
        ...


class DuplicateAnchorCollection(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class HTMLFileParser(java.lang.Object):

    @typing.type_check_only
    class Line(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ScanResult(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TagBlock(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def scanHtmlFile(file: jpype.protocol.SupportsPath, tagProcessor: TagProcessor):
        ...


class DuplicateAnchorCollectionByHelpTopic(DuplicateAnchorCollection, java.lang.Comparable[DuplicateAnchorCollectionByHelpTopic]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class AnchorManager(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addAnchor(self, file: jpype.protocol.SupportsPath, anchorName: typing.Union[java.lang.String, str], srcLineNo: typing.Union[jpype.JInt, int]):
        ...

    def addAnchorRef(self, href: help.validator.model.HREF):
        ...

    def addImageRef(self, ref: help.validator.model.IMG):
        ...

    def getAnchorForHelpPath(self, path: typing.Union[java.lang.String, str]) -> help.validator.model.AnchorDefinition:
        ...

    def getAnchorForName(self, anchorName: typing.Union[java.lang.String, str]) -> help.validator.model.AnchorDefinition:
        ...

    def getAnchorRefs(self) -> java.util.List[help.validator.model.HREF]:
        ...

    def getAnchorsByHelpPath(self) -> java.util.Map[help.PathKey, help.validator.model.AnchorDefinition]:
        ...

    def getDuplicateAnchorsByID(self) -> java.util.Map[java.lang.String, java.util.List[help.validator.model.AnchorDefinition]]:
        ...

    def getImageRefs(self) -> java.util.List[help.validator.model.IMG]:
        ...

    @property
    def anchorForName(self) -> help.validator.model.AnchorDefinition:
        ...

    @property
    def anchorForHelpPath(self) -> help.validator.model.AnchorDefinition:
        ...

    @property
    def duplicateAnchorsByID(self) -> java.util.Map[java.lang.String, java.util.List[help.validator.model.AnchorDefinition]]:
        ...

    @property
    def anchorsByHelpPath(self) -> java.util.Map[help.PathKey, help.validator.model.AnchorDefinition]:
        ...

    @property
    def anchorRefs(self) -> java.util.List[help.validator.model.HREF]:
        ...

    @property
    def imageRefs(self) -> java.util.List[help.validator.model.IMG]:
        ...


class DuplicateAnchorCollectionByHelpFile(DuplicateAnchorCollection, java.lang.Comparable[DuplicateAnchorCollectionByHelpFile]):

    class_: typing.ClassVar[java.lang.Class]

    def getHelpFile(self) -> help.validator.model.HelpFile:
        ...

    @property
    def helpFile(self) -> help.validator.model.HelpFile:
        ...


class ReferenceTagProcessor(TagProcessor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, help: help.validator.location.HelpModuleLocation, anchorManager: AnchorManager):
        ...

    def getErrorText(self) -> str:
        ...

    @property
    def errorText(self) -> java.lang.String:
        ...


class LinkDatabase(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, helpCollection: help.validator.location.HelpModuleCollection):
        ...

    def generateTOCOutputFile(self, outputFile: jpype.protocol.SupportsPath, file: help.validator.model.GhidraTOCFile):
        ...

    def getDuplicateAnchors(self) -> java.util.Collection[DuplicateAnchorCollection]:
        ...

    def getIDForLink(self, target: typing.Union[java.lang.String, str]) -> str:
        ...

    def getTOCDefinition(self, referenceTOC: help.validator.model.TOCItemReference) -> help.validator.model.TOCItemDefinition:
        ...

    def getTOCExternal(self, referenceTOC: help.validator.model.TOCItemReference) -> help.validator.model.TOCItemExternal:
        ...

    @property
    def iDForLink(self) -> java.lang.String:
        ...

    @property
    def tOCExternal(self) -> help.validator.model.TOCItemExternal:
        ...

    @property
    def duplicateAnchors(self) -> java.util.Collection[DuplicateAnchorCollection]:
        ...

    @property
    def tOCDefinition(self) -> help.validator.model.TOCItemDefinition:
        ...


class TagProcessor(java.lang.Object):

    @typing.type_check_only
    class TagProcessingState(java.lang.Enum[TagProcessor.TagProcessingState]):

        class_: typing.ClassVar[java.lang.Class]
        LOOKING_FOR_NEXT_ATTR: typing.Final[TagProcessor.TagProcessingState]
        READING_ATTR: typing.Final[TagProcessor.TagProcessingState]
        LOOKING_FOR_VALUE: typing.Final[TagProcessor.TagProcessingState]
        READING_VALUE: typing.Final[TagProcessor.TagProcessingState]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TagProcessor.TagProcessingState:
            ...

        @staticmethod
        def values() -> jpype.JArray[TagProcessor.TagProcessingState]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def endOfFile(self):
        ...

    def getErrorCount(self) -> int:
        ...

    def isTagSupported(self, tagType: typing.Union[java.lang.String, str]) -> bool:
        ...

    def processText(self, text: typing.Union[java.lang.String, str]) -> str:
        ...

    def startOfFile(self, htmlFile: jpype.protocol.SupportsPath):
        ...

    @property
    def tagSupported(self) -> jpype.JBoolean:
        ...

    @property
    def errorCount(self) -> jpype.JInt:
        ...


class UnusedHelpImageFileFinder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, helpCollections: collections.abc.Sequence):
        ...

    @typing.overload
    def __init__(self, helpCollections: collections.abc.Sequence, debugEnabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def getUnusedImages(self) -> java.util.SortedSet[java.nio.file.Path]:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @property
    def unusedImages(self) -> java.util.SortedSet[java.nio.file.Path]:
        ...



__all__ = ["JavaHelpValidator", "DuplicateAnchorCollection", "HTMLFileParser", "DuplicateAnchorCollectionByHelpTopic", "AnchorManager", "DuplicateAnchorCollectionByHelpFile", "ReferenceTagProcessor", "LinkDatabase", "TagProcessor", "UnusedHelpImageFileFinder"]
