from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import help.validator.location
import help.validator.model
import java.lang # type: ignore
import java.nio.file # type: ignore


class InvalidLink(java.lang.Comparable[InvalidLink]):

    class_: typing.ClassVar[java.lang.Class]

    def getLineNumber(self) -> int:
        ...

    def getSourceFile(self) -> java.nio.file.Path:
        ...

    def identityHashCode(self) -> int:
        ...

    @property
    def lineNumber(self) -> jpype.JInt:
        ...

    @property
    def sourceFile(self) -> java.nio.file.Path:
        ...


@typing.type_check_only
class IllegalHModuleAssociationHREFInvalidLink(InvalidHREFLink):
    ...
    class_: typing.ClassVar[java.lang.Class]


class InvalidHREFLink(InvalidLink):

    class_: typing.ClassVar[java.lang.Class]

    def getHREF(self) -> help.validator.model.HREF:
        ...

    @property
    def hREF(self) -> help.validator.model.HREF:
        ...


class IllegalHModuleAssociationIMGInvalidLink(InvalidIMGLink):
    ...
    class_: typing.ClassVar[java.lang.Class]


class InvalidIMGLink(InvalidLink):

    class_: typing.ClassVar[java.lang.Class]

    def getIMG(self) -> help.validator.model.IMG:
        ...

    @property
    def iMG(self) -> help.validator.model.IMG:
        ...


class IncorrectIMGFilenameCaseInvalidLink(InvalidIMGLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, img: help.validator.model.IMG) -> None:
        ...


class InvalidRuntimeIMGFileInvalidLink(InvalidIMGLink):
    """
    A link that represents the case where the HTML tried to reference a runtime Java image, but 
    that value is not found
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, img: help.validator.model.IMG) -> None:
        ...


class MissingAnchorInvalidLink(InvalidHREFLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, href: help.validator.model.HREF) -> None:
        ...


class MissingFileInvalidLink(InvalidHREFLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, href: help.validator.model.HREF) -> None:
        ...


class MissingIMGFileInvalidLink(InvalidIMGLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, img: help.validator.model.IMG) -> None:
        ...


class MissingTOCDefinitionInvalidLink(InvalidLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, help: help.validator.location.HelpModuleCollection, reference: help.validator.model.TOCItemReference) -> None:
        ...


class MissingTOCTargetIDInvalidLink(InvalidLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, help: help.validator.location.HelpModuleCollection, item: help.validator.model.TOCItem) -> None:
        ...


class NonExistentIMGFileInvalidLink(InvalidIMGLink):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, img: help.validator.model.IMG) -> None:
        ...



__all__ = ["InvalidLink", "IllegalHModuleAssociationHREFInvalidLink", "InvalidHREFLink", "IllegalHModuleAssociationIMGInvalidLink", "InvalidIMGLink", "IncorrectIMGFilenameCaseInvalidLink", "InvalidRuntimeIMGFileInvalidLink", "MissingAnchorInvalidLink", "MissingFileInvalidLink", "MissingIMGFileInvalidLink", "MissingTOCDefinitionInvalidLink", "MissingTOCTargetIDInvalidLink", "NonExistentIMGFileInvalidLink"]
