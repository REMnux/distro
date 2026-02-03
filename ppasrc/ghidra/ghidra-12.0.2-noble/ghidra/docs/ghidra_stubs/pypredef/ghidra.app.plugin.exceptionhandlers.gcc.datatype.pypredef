from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data


class DwarfEncodingModeDataType(ghidra.program.model.data.BuiltIn):
    """
    A data type whose value is a particular Dwarf decoder.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[DwarfEncodingModeDataType]

    @typing.overload
    def __init__(self):
        """
        Data type whose value indicates the type of Dwarf encoding used for other data.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Data type whose value indicates the type of Dwarf encoding used for other data.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager associated with this data type.
        """


class PcRelative31AddressDataType(ghidra.program.model.data.BuiltIn):
    """
    An Address datatype whose value is computed in relation to its location in memory.
    """

    class_: typing.ClassVar[java.lang.Class]
    dataType: typing.Final[PcRelative31AddressDataType]

    @typing.overload
    def __init__(self):
        """
        Creates a PC relative address data type using the bottom 31 bits.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a PC relative address data type using the bottom 31 bits.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager associated with this data type.
        """



__all__ = ["DwarfEncodingModeDataType", "PcRelative31AddressDataType"]
