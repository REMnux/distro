from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.processors.sleigh.template
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


A = typing.TypeVar("A")
T = typing.TypeVar("T")


class AttributedStringPcodeFormatter(AbstractPcodeFormatter[java.util.List[docking.widgets.fieldpanel.field.AttributedString], AttributedStringPcodeFormatter.ToAttributedStringsAppender]):

    @typing.type_check_only
    class ToAttributedStringsAppender(AbstractAppender[java.util.List[docking.widgets.fieldpanel.field.AttributedString]]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, indent: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor
        """

    def setFontMetrics(self, metrics: java.awt.FontMetrics):
        """
        Set font metrics for AttributedString objects
        
        :param java.awt.FontMetrics metrics: the font metrics
        """

    def setOptions(self, maxDisplayLines: typing.Union[jpype.JInt, int], displayRawPcode: typing.Union[jpype.JBoolean, bool]):
        """
        Set general formatting options
        
        :param jpype.JInt or int maxDisplayLines: the maximum number of lines to display
        :param jpype.JBoolean or bool displayRawPcode: show raw pcode
        """


class StringPcodeFormatter(AbstractPcodeFormatter[java.lang.String, StringPcodeFormatter.ToStringAppender]):

    @typing.type_check_only
    class ToStringAppender(AbstractAppender[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, language: ghidra.program.model.lang.Language, labeled: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PcodeFormatter(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def formatOps(self, language: ghidra.program.model.lang.Language, pcodeOps: java.util.List[ghidra.program.model.pcode.PcodeOp]) -> T:
        """
        Format the p-code ops
        
        :param ghidra.program.model.lang.Language language: the language generating the p-code
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] pcodeOps: the p-code ops
        :return: the formatted result
        :rtype: T
        """

    @typing.overload
    def formatOps(self, language: ghidra.program.model.lang.Language, addrFactory: ghidra.program.model.address.AddressFactory, pcodeOps: java.util.List[ghidra.program.model.pcode.PcodeOp]) -> T:
        """
        Format the pcode ops with a specified :obj:`AddressFactory`. For use when the pcode ops can
        reference program-specific address spaces.
        
        :param ghidra.program.model.lang.Language language: the language generating the p-code
        :param ghidra.program.model.address.AddressFactory addrFactory: addressFactory to use when generating pcodeop templates
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] pcodeOps: p-code ops to format
        :return: the formatted result
        :rtype: T
        """

    def formatTemplates(self, language: ghidra.program.model.lang.Language, pcodeOpTemplates: java.util.List[ghidra.app.plugin.processors.sleigh.template.OpTpl]) -> T:
        """
        Format the p-code op templates
        
        :param ghidra.program.model.lang.Language language: the language generating the p-code
        :param java.util.List[ghidra.app.plugin.processors.sleigh.template.OpTpl] pcodeOpTemplates: the templates
        :return: the formatted result
        :rtype: T
        """

    @staticmethod
    def getPcodeOpTemplates(addrFactory: ghidra.program.model.address.AddressFactory, pcodeOps: java.util.List[ghidra.program.model.pcode.PcodeOp]) -> java.util.List[ghidra.app.plugin.processors.sleigh.template.OpTpl]:
        """
        Convert flattened p-code ops into templates.
        
        :param ghidra.program.model.address.AddressFactory addrFactory: the language's address factory
        :param java.util.List[ghidra.program.model.pcode.PcodeOp] pcodeOps: the p-code ops to convert
        :return: p-code op templates
        :rtype: java.util.List[ghidra.app.plugin.processors.sleigh.template.OpTpl]
        """


class AbstractAppender(Appender[T], typing.Generic[T]):
    """
    A base implementation of :obj:`Appender` suitable for most cases.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language, indent: typing.Union[jpype.JBoolean, bool]):
        """
        Create a new appender.
        
        :param ghidra.program.model.lang.Language language: the language of the p-code ops to format
        :param jpype.JBoolean or bool indent: whether or not to indent
        """


@typing.type_check_only
class Appender(java.lang.Object, typing.Generic[T]):
    """
    An appender to receive formatted p-code ops.
     
     
    
    Using :obj:`AbstractAppender` is highly recommended, as it makes available methods for
    displaying elements according to established Ghidra conventions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def appendAddressWordOffcut(self, wordOffset: typing.Union[jpype.JLong, int], offcut: typing.Union[jpype.JLong, int]):
        """
        Append an address in word-offcut form
        
        :param jpype.JLong or int wordOffset: the word offset
        :param jpype.JLong or int offcut: the byte within the word
        """

    def appendCharacter(self, c: typing.Union[jpype.JChar, int, str]):
        """
        Append a character
         
         
        
        **NOTE:** if extra spacing is desired, esp., surrounding the equals sign, it must be
        appended manually.
        
        :param jpype.JChar or int or str c: the character
        """

    def appendIndent(self):
        """
        Append indentation, usually meant for the beginning of a line
        """

    def appendLabel(self, label: typing.Union[java.lang.String, str]):
        """
        Append a local label
        
        :param java.lang.String or str label: the label name, e.g., ``instr_next``
        """

    def appendLineLabel(self, label: typing.Union[jpype.JLong, int]):
        """
        Append a line label, usually meant to be on its own line
        
        :param jpype.JLong or int label: the label number
        """

    def appendLineLabelRef(self, label: typing.Union[jpype.JLong, int]):
        """
        Append a reference to the given line label
        
        :param jpype.JLong or int label: the label number
        """

    def appendMnemonic(self, opcode: typing.Union[jpype.JInt, int]):
        """
        Append the given opcode
        
        :param jpype.JInt or int opcode: the op's opcode
        """

    def appendRawVarnode(self, space: ghidra.program.model.address.AddressSpace, offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JLong, int]):
        """
        Append the given varnode in raw form
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :param jpype.JLong or int offset: the offset in the space
        :param jpype.JLong or int size: the size in bytes
        """

    def appendRegister(self, register: ghidra.program.model.lang.Register):
        """
        Append a register
        
        :param ghidra.program.model.lang.Register register: the register
        """

    def appendScalar(self, value: typing.Union[jpype.JLong, int]):
        """
        Append a scalar value
        
        :param jpype.JLong or int value: the value
        """

    def appendSpace(self, space: ghidra.program.model.address.AddressSpace):
        """
        Append an address space
        
        :param ghidra.program.model.address.AddressSpace space: the space
        """

    def appendUnique(self, offset: typing.Union[jpype.JLong, int]):
        """
        Append a unique variable
        
        :param jpype.JLong or int offset: the offset in unique space
        """

    def appendUserop(self, id: typing.Union[jpype.JInt, int]):
        """
        Append the given userop
        
        :param jpype.JInt or int id: the userop id
        """

    def finish(self) -> T:
        """
        Finish formatting and return the final result
        
        :return: the final result
        :rtype: T
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the language of the p-code being formatted
        
        :return: 
        :rtype: ghidra.program.model.lang.Language
        """

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...


class AbstractPcodeFormatter(PcodeFormatter[T], typing.Generic[T, A]):
    """
    An abstract p-code formatter which can take a list of p-code ops or op templates and consistently
    format them. The general pattern is to extend this class and specify another class which extends
    an :obj:`AbstractAppender`. In most cases, it is only necessary to override
    :meth:`formatOpTemplate(Appender, OpTpl) <.formatOpTemplate>`. Otherwise, most formatting logic is implemented by
    the appender.
    
    
    .. seealso::
    
        | :obj:`StringPcodeFormatter`for an example
    
        | :obj:`AbstractAppender`
    """

    @typing.type_check_only
    class FormatResult(java.lang.Enum[AbstractPcodeFormatter.FormatResult]):
        """
        A result instructing the formatter whether or not to continue
        """

        class_: typing.ClassVar[java.lang.Class]
        CONTINUE: typing.Final[AbstractPcodeFormatter.FormatResult]
        TERMINATE: typing.Final[AbstractPcodeFormatter.FormatResult]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AbstractPcodeFormatter.FormatResult:
            ...

        @staticmethod
        def values() -> jpype.JArray[AbstractPcodeFormatter.FormatResult]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["AttributedStringPcodeFormatter", "StringPcodeFormatter", "PcodeFormatter", "AbstractAppender", "Appender", "AbstractPcodeFormatter"]
