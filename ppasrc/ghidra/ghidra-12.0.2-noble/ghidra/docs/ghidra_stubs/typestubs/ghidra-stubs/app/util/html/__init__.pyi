from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.html.diff
import ghidra.program.model.data
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class TextLine(ValidatableLine):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, text: typing.Union[java.lang.String, str]):
        ...

    def getTextColor(self) -> java.awt.Color:
        ...

    @property
    def textColor(self) -> java.awt.Color:
        ...


class CompletelyDifferentHTMLDataTypeRepresentationWrapper(HTMLDataTypeRepresentation):
    ...
    class_: typing.ClassVar[java.lang.Class]


class HTMLDataTypeRepresentation(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def diff(self, otherRepresentation: HTMLDataTypeRepresentation) -> jpype.JArray[HTMLDataTypeRepresentation]:
        """
        Compares this representation and the given representation creates a diff string for both
        representations.
        
        :param HTMLDataTypeRepresentation otherRepresentation: the other representation to diff against.
        :return: An array of two strings: the first is this object's diff value, the second is the
                given objects diff value.
        :rtype: jpype.JArray[HTMLDataTypeRepresentation]
        """

    def getFullHTMLContentString(self) -> str:
        """
        This is like :meth:`getHTMLString() <.getHTMLString>`, but does not put HTML tags around the data
        
        :return: the content
        :rtype: str
        """

    def getFullHTMLString(self) -> str:
        """
        Returns an HTML string for this data representation object
        
        :return: the html
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getHTMLString()`
        """

    def getHTMLContentString(self) -> str:
        """
        This is like :meth:`getHTMLString() <.getHTMLString>`, but does not put HTML tags around the data
        
        :return: the content
        :rtype: str
        """

    def getHTMLString(self) -> str:
        """
        Returns an HTML string for this data representation object.  The HTML returned will be
        truncated if it is too long.   To get the full HTML, call :meth:`getFullHTMLString() <.getFullHTMLString>`.
        
        :return: the html
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getFullHTMLString()`
        """

    @property
    def fullHTMLString(self) -> java.lang.String:
        ...

    @property
    def hTMLString(self) -> java.lang.String:
        ...

    @property
    def fullHTMLContentString(self) -> java.lang.String:
        ...

    @property
    def hTMLContentString(self) -> java.lang.String:
        ...


class HTMLDataTypeRepresentationDiffInput(ghidra.app.util.html.diff.DataTypeDiffInput):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, source: HTMLDataTypeRepresentation, lines: java.util.List[ValidatableLine]):
        ...


class ValidatableLine(java.lang.Object):
    """
    A loose concept that represents a line of text, potentially with multiple parts, that can
    be validated against other instances and can change the color of the text.
     
    
    Validation is performed against another :obj:`ValidatableLine`, which will be set by 
    calling :meth:`setValidationLine(ValidatableLine) <.setValidationLine>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID_COLOR: typing.Final[java.awt.Color]

    def copy(self) -> ValidatableLine:
        ...

    def getText(self) -> str:
        ...

    def isDiffColored(self) -> bool:
        ...

    def isValidated(self) -> bool:
        """
        True means that this line has been matched against another line, **regardless of whether 
        the two lines are the same or not**.
        
        :return: true if this line has been matched against another line
        :rtype: bool
        """

    def matches(self, otherLine: ValidatableLine) -> bool:
        ...

    def setTextColor(self, color: java.awt.Color):
        """
        Set color for all text.
        
        :param java.awt.Color color: text color
        """

    def setValidationLine(self, line: ValidatableLine):
        """
        Sets the other line that this line is validated against.  The other line may be a full, 
        partial, or no match at all.
        
        :param ValidatableLine line: the line against which this line is validated
        """

    def updateColor(self, otherLine: ValidatableLine, invalidColor: java.awt.Color):
        ...

    @property
    def validated(self) -> jpype.JBoolean:
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @property
    def diffColored(self) -> jpype.JBoolean:
        ...


class DefaultDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dataType: ghidra.program.model.data.DataType):
        ...


class EmptyDataTypeLine(DataTypeLine, PlaceHolderLine):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class NullDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class CompositeDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comp: ghidra.program.model.data.Composite):
        ...


class BitFieldDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bitFieldDt: ghidra.program.model.data.BitFieldDataType):
        ...


class EnumDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, enumDataType: ghidra.program.model.data.Enum):
        ...


class VariableTextLine(ValidatableLine):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, variableType: typing.Union[java.lang.String, str], variableName: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType):
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getVariableName(self) -> str:
        ...

    def getVariableNameColor(self) -> java.awt.Color:
        ...

    def getVariableType(self) -> str:
        ...

    def getVariableTypeColor(self) -> java.awt.Color:
        ...

    def hasUniversalId(self) -> bool:
        ...

    @property
    def variableType(self) -> java.lang.String:
        ...

    @property
    def variableName(self) -> java.lang.String:
        ...

    @property
    def variableNameColor(self) -> java.awt.Color:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def variableTypeColor(self) -> java.awt.Color:
        ...


class EmptyTextLine(TextLine, PlaceHolderLine):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, widthInCharacters: typing.Union[jpype.JInt, int]):
        ...


class MissingArchiveDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceArchive: ghidra.program.model.data.SourceArchive):
        ...


class PointerDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pointer: ghidra.program.model.data.Pointer):
        ...


class EmptyVariableTextLine(VariableTextLine, PlaceHolderLine):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numberOfCharacters: typing.Union[jpype.JInt, int]):
        ...


class ArrayDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, array: ghidra.program.model.data.Array):
        ...


class FunctionDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, functionDefinition: ghidra.program.model.data.FunctionDefinition):
        ...


class PlaceHolderLine(ValidatableLine):
    """
    Marker interface for lines that are generic place holders for diffing
    """

    class_: typing.ClassVar[java.lang.Class]


class TypeDefDataTypeHTMLRepresentation(HTMLDataTypeRepresentation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, typeDef: ghidra.program.model.data.TypeDef):
        ...


class DataTypeLine(ValidatableLine):

    class_: typing.ClassVar[java.lang.Class]

    def getComment(self) -> str:
        ...

    def getCommentColor(self) -> java.awt.Color:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getName(self) -> str:
        ...

    def getNameColor(self) -> java.awt.Color:
        ...

    def getType(self) -> str:
        ...

    def getTypeColor(self) -> java.awt.Color:
        ...

    def hasUniversalId(self) -> bool:
        ...

    def setCommentColor(self, commentColor: java.awt.Color):
        ...

    def setNameColor(self, nameColor: java.awt.Color):
        ...

    def setTypeColor(self, typeColor: java.awt.Color):
        ...

    @property
    def typeColor(self) -> java.awt.Color:
        ...

    @typeColor.setter
    def typeColor(self, value: java.awt.Color):
        ...

    @property
    def nameColor(self) -> java.awt.Color:
        ...

    @nameColor.setter
    def nameColor(self, value: java.awt.Color):
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def commentColor(self) -> java.awt.Color:
        ...

    @commentColor.setter
    def commentColor(self, value: java.awt.Color):
        ...

    @property
    def type(self) -> java.lang.String:
        ...



__all__ = ["TextLine", "CompletelyDifferentHTMLDataTypeRepresentationWrapper", "HTMLDataTypeRepresentation", "HTMLDataTypeRepresentationDiffInput", "ValidatableLine", "DefaultDataTypeHTMLRepresentation", "EmptyDataTypeLine", "NullDataTypeHTMLRepresentation", "CompositeDataTypeHTMLRepresentation", "BitFieldDataTypeHTMLRepresentation", "EnumDataTypeHTMLRepresentation", "VariableTextLine", "EmptyTextLine", "MissingArchiveDataTypeHTMLRepresentation", "PointerDataTypeHTMLRepresentation", "EmptyVariableTextLine", "ArrayDataTypeHTMLRepresentation", "FunctionDataTypeHTMLRepresentation", "PlaceHolderLine", "TypeDefDataTypeHTMLRepresentation", "DataTypeLine"]
