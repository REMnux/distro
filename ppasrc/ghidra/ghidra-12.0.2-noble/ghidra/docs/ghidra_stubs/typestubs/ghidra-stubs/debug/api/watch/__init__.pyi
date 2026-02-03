from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.docking.settings
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.symbol
import java.lang # type: ignore


class WatchRow(java.lang.Object):
    """
    A row in the Watches table
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the value, if it exists at one (memory or register)
        
        :return: the address, or null
        :rtype: ghidra.program.model.address.Address
        """

    def getComment(self) -> str:
        """
        Get the user-defined comment for this row
        
        :return: the comment
        :rtype: str
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the data type for interpreting the value
        
        :return: the data type
        :rtype: ghidra.program.model.data.DataType
        """

    def getError(self) -> java.lang.Throwable:
        """
        If the watch could not be evaluated, get the cause
        
        :return: the error
        :rtype: java.lang.Throwable
        """

    def getErrorMessage(self) -> str:
        """
        If the watch could not be evaluated, get a message explaining why
         
         
        
        This is essentially the message given by :meth:`getError() <.getError>`. If the exception does not
        provide a message, this will at least give the name of the exception class.
        
        :return: the error message, or an empty string
        :rtype: str
        """

    def getExpression(self) -> str:
        """
        Get the Sleigh expression
        
        :return: the expression
        :rtype: str
        """

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the address range of the value, if it exists at an address (memory or register)
        
        :return: the range, or null
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getRawValueString(self) -> str:
        """
        Get the raw value displayed as a string
         
         
        
        For values in memory, this is a list of hex bytes. For others, it is a hex integer subject to
        the platform's endian.
        
        :return: the value, or null
        :rtype: str
        """

    def getReads(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the complete set of all addresses read to evaluate the expression
        
        :return: the address set, or null
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getSettings(self) -> ghidra.docking.settings.Settings:
        """
        Get the settings on the data type
         
         
        
        The returned settings may be modified, after which :meth:`settingsChanged() <.settingsChanged>` must be called.
        There is no ``setSettings`` method.
        
        :return: the settings
        :rtype: ghidra.docking.settings.Settings
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get the nearest symbol before the value's address, if applicable
        
        :return: the symbol, or null
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def getValue(self) -> jpype.JArray[jpype.JByte]:
        """
        Get the raw value
        
        :return: the value, or null
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getValueLength(self) -> int:
        """
        Get the number of bytes in the value
        
        :return: the length, or 0 if evaluation failed
        :rtype: int
        """

    def getValueObject(self) -> java.lang.Object:
        """
        Get the value as returned by the data type
        
        :return: the data-type defined value
        :rtype: java.lang.Object
        """

    def getValueString(self) -> str:
        """
        Get the value as represented by the data type
        
        :return: the value's data-type-defined representation
        :rtype: str
        """

    def isChanged(self) -> bool:
        """
        Check if the value has changed
         
         
        
        "Changed" technically deals in navigation. In the case of a step, resume-and-break, patch,
        etc. This will detect the changes as expected. When manually navigating, this compares the
        two most recent times visited. Only the value itself is compared, without consideration for
        any intermediate values encountered during evaluation. Consider an array whose elements are
        all currently 0. An expression that dereferences an index in that array will be considered
        unchanged, even if the index did change.
        
        :return: true if the value changed, false otherwise.
        :rtype: bool
        """

    def isKnown(self) -> bool:
        """
        Check if the value given is actually known to be the value
         
         
        
        If the value itself or any value encountered during the evaluation of the expression is
        stale, then the final value is considered stale, i.e., not known.
        
        :return: true all memory and registers involved in the evaluation are known, false otherwise.
        :rtype: bool
        """

    def isRawValueEditable(self) -> bool:
        """
        Check if :meth:`setRawValueString(String) <.setRawValueString>` is supported
         
         
        
        Setting the value may not be supported for many reasons: 1) The expression is not valid, 2)
        The expression could not be evaluated, 3) The value has no address or register. Reason 3 is
        somewhat strict, but reasonable, lest we have to implement a solver.
        
        :return: whether or not the value can be modified
        :rtype: bool
        """

    def isValueEditable(self) -> bool:
        """
        Check if :meth:`setValueString(String) <.setValueString>` is supported
         
         
        
        In addition to those reasons given in :meth:`isRawValueEditable() <.isRawValueEditable>`, setting the value may
        not be supported because: 1) No data type is set, or 2) The selected data type does not
        support encoding.
        
        :return: whether or not the data-type interpreted value can be modified
        :rtype: bool
        """

    def setComment(self, comment: typing.Union[java.lang.String, str]):
        """
        Set the user-defined comment for this row
        
        :param java.lang.String or str comment: the comment
        """

    def setDataType(self, dataType: ghidra.program.model.data.DataType):
        """
        Set the data type for interpreting the value
        
        :param ghidra.program.model.data.DataType dataType: the data type
        """

    def setExpression(self, expression: typing.Union[java.lang.String, str]):
        """
        Set the Sleigh expression
        
        :param java.lang.String or str expression: the expression
        """

    def setRawValueString(self, value: typing.Union[java.lang.String, str]):
        """
        Patch memory or register values such that the expression evaluates to the given raw value
         
         
        
        This is only supported when :obj:`.isRawValueEditable` returns true. The given value must be
        a list of hex bytes (as returned by :meth:`getRawValueString() <.getRawValueString>`), or a hex integer subject
        to the platform's endian. Either is accepted, regardless of whether the value resides in
        memory.
        
        :param java.lang.String or str value: the raw value as returned by :meth:`getRawValueString() <.getRawValueString>`
        
        .. seealso::
        
            | :obj:`.getAddress()`
        """

    def setValueString(self, value: typing.Union[java.lang.String, str]):
        """
        Patch memory or register values such that the expression evaluates to the given value
         
         
        
        This is only supported when :meth:`isValueEditable() <.isValueEditable>` returns true. The given value must be
        encodable by the data type.
        
        :param java.lang.String or str value: the desired value, as returned by :meth:`getValueString() <.getValueString>`
        """

    def settingsChanged(self):
        """
        Notify the row that the settings were changed
        
        
        .. seealso::
        
            | :obj:`.getSettings()`
        """

    @property
    def rawValueEditable(self) -> jpype.JBoolean:
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def settings(self) -> ghidra.docking.settings.Settings:
        ...

    @property
    def expression(self) -> java.lang.String:
        ...

    @expression.setter
    def expression(self, value: java.lang.String):
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def rawValueString(self) -> java.lang.String:
        ...

    @rawValueString.setter
    def rawValueString(self, value: java.lang.String):
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType):
        ...

    @property
    def valueEditable(self) -> jpype.JBoolean:
        ...

    @property
    def reads(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def error(self) -> java.lang.Throwable:
        ...

    @property
    def valueObject(self) -> java.lang.Object:
        ...

    @property
    def known(self) -> jpype.JBoolean:
        ...

    @property
    def valueString(self) -> java.lang.String:
        ...

    @valueString.setter
    def valueString(self, value: java.lang.String):
        ...

    @property
    def valueLength(self) -> jpype.JInt:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @comment.setter
    def comment(self, value: java.lang.String):
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def changed(self) -> jpype.JBoolean:
        ...



__all__ = ["WatchRow"]
