from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.html
import java.lang # type: ignore
import java.util # type: ignore


class DiffLines(java.util.ArrayList[ghidra.app.util.html.ValidatableLine]):
    """
    A class that holds lines that will be used to generate diffs.  It also has a reference to 
    the source of the data so that it can create the correct type of empty lines as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, input: DataTypeDiffInput):
        ...

    @typing.overload
    def __init__(self, input: DataTypeDiffInput, validatedLines: java.util.List[ghidra.app.util.html.ValidatableLine]):
        ...


class DataTypeDiffBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def diffBody(left: DataTypeDiffInput, right: DataTypeDiffInput) -> DataTypeDiff:
        ...

    @staticmethod
    def diffHeader(left: DataTypeDiffInput, right: DataTypeDiffInput) -> DataTypeDiff:
        ...

    @staticmethod
    def diffLines(left: DataTypeDiffInput, right: DataTypeDiffInput) -> DataTypeDiff:
        ...

    @staticmethod
    def highlightDifferences(left: java.util.List[ghidra.app.util.html.ValidatableLine], right: java.util.List[ghidra.app.util.html.ValidatableLine]):
        ...

    @staticmethod
    def padLines(leftLines: DiffLines, rightLines: DiffLines):
        ...


class DataTypeDiff(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getLeftLines(self) -> DiffLines:
        ...

    def getRightLines(self) -> DiffLines:
        ...

    @property
    def rightLines(self) -> DiffLines:
        ...

    @property
    def leftLines(self) -> DiffLines:
        ...


@typing.type_check_only
class DiffLinesValidator(java.lang.Object):
    """
    A class that knows how to traverse a set a lines that are being used to generate a diff.
    """

    class_: typing.ClassVar[java.lang.Class]

    def increment(self):
        """
        Push forward the current marker position.  The marker starts at the beginning and 
        only moves forward past validated lines.
        """


class DataTypeDiffInput(java.lang.Object):
    """
    An interface that provides lines that are to be used in a diff and can also create 
    specialized placeholder lines upon request.
    """

    class_: typing.ClassVar[java.lang.Class]

    def createPlaceHolder(self, oppositeLine: ghidra.app.util.html.ValidatableLine) -> ghidra.app.util.html.PlaceHolderLine:
        ...

    def getLines(self) -> java.util.List[ghidra.app.util.html.ValidatableLine]:
        ...

    @property
    def lines(self) -> java.util.List[ghidra.app.util.html.ValidatableLine]:
        ...



__all__ = ["DiffLines", "DataTypeDiffBuilder", "DataTypeDiff", "DiffLinesValidator", "DataTypeDiffInput"]
