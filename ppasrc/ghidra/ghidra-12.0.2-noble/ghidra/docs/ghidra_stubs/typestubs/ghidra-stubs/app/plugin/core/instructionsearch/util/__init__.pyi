from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.instructionsearch
import ghidra.app.plugin.core.instructionsearch.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import java.lang # type: ignore
import java.util # type: ignore


class InstructionSearchUtils(java.lang.Object):
    """
    Helper functions for the instruction search package.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def addSpaceOnByteBoundary(str: typing.Union[java.lang.String, str], mode: ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode) -> str:
        """
        Formats a string by adding spaces on each byte boundary. The input mode specifies whether
        this boundary is every 2(hex) or 8(binary) characters.
        
        :param java.lang.String or str str: 
        :param ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode mode: hex or binary
        :return: 
        :rtype: str
        """

    @staticmethod
    def byteArrayAnd(mask: jpype.JArray[jpype.JByte], bytes: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Performs a bitwise AND on the given arrays.
        
        :param jpype.JArray[jpype.JByte] mask: 
        :param jpype.JArray[jpype.JByte] bytes: 
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def byteArrayOr(arr1: jpype.JArray[jpype.JByte], arr2: jpype.JArray[jpype.JByte]) -> jpype.JArray[jpype.JByte]:
        """
        Performs an bitwise OR on the given arrays.
        
        :param jpype.JArray[jpype.JByte] arr1: 
        :param jpype.JArray[jpype.JByte] arr2: 
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def containsOnBit(bytearray: jpype.JArray[jpype.JByte]) -> bool:
        """
        Returns true if any bit in the given array is 'on' (set to 1).
        
        :param jpype.JArray[jpype.JByte] bytearray: 
        :return: 
        :rtype: bool
        """

    @staticmethod
    def formatSearchString(searchStr: typing.Union[java.lang.String, str], mask: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a binary string with '.' characters where bits are masked.  This is used in
        formatting strings for display in the preview table.
        
        :param java.lang.String or str searchStr: 
        :param java.lang.String or str mask: 
        :return: 
        :rtype: str
        :raises InvalidInputException:
        """

    @staticmethod
    def getGroupSizes(source: typing.Union[java.lang.String, str], mode: ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode) -> java.util.List[java.lang.Integer]:
        """
        Returns a list of the sizes of each group, in terms of bytes, in the input string. 
        eg: if the input string is "1001 01 AAAA BB ABCDEF" the returned list will be 
        {2, 1, 2, 1, 3}.
        
        :param java.lang.String or str source: 
        :param ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode mode: BINARY or HEX
        :return: 
        :rtype: java.util.List[java.lang.Integer]
        :raises java.lang.Exception:
        """

    @staticmethod
    def getInstructionSearchPlugin(tool: ghidra.framework.plugintool.PluginTool) -> ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin:
        """
        Finds the :obj:`InstructionSearchPlugin`; returns null if it doesn't exist.
        
        :param ghidra.framework.plugintool.PluginTool tool: 
        :return: 
        :rtype: ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin
        """

    @staticmethod
    def getWhitespace(source: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Returns a list of all whitespaces in the given string. eg: if the input string is
        "aaa bb  cc     ddd e", the returned list will be: {" ", "  ", "     ", " "}.
         
        Note 1: This will match newline characters as well, so those will be preserved in the 
                returned strings.
         
        Note 2: This is here so that we can 'remember' what the spaces are in an input string, and 
                subsequently restore those spaces after manipulating (ie: converting from binary
                to hex or vica-versa).
        
        :param java.lang.String or str source: 
        :return: 
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def isBinary(input: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the input is a valid binary string (all 0's and 1's).
        
        :param java.lang.String or str input: 
        :return: 
        :rtype: bool
        """

    @staticmethod
    def isFullBinaryByte(input: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the input string represents a full byte of information.
        
        :param java.lang.String or str input: 
        :return: 
        :rtype: bool
        """

    @staticmethod
    def isFullHexByte(input: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the input string represents a full byte of information.
        
        :param java.lang.String or str input: 
        :return: 
        :rtype: bool
        """

    @staticmethod
    def isHex(input: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the input is a valid hex string.  
         
        Note that spaces are allowed in the input, but are ignored.
        
        :param java.lang.String or str input: 
        :return: 
        :rtype: bool
        """

    @staticmethod
    def toAddressList(searchResults: java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata]) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Returns a list of :obj:`Address` items contained in the given :obj:`InstructionMetadata` 
        list.
        
        :param java.util.List[ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata] searchResults: 
        :return: a list of addresses indicating starting positions of matches.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    @staticmethod
    def toBinary(hex: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a binary representation of the given hex string.  This will pad the string
        with '0's at the beginning to make a full byte.
         
        Note that spaces are allowed in the input, but will be ignored.
        
        :param java.lang.String or str hex: 
        :return: 
        :rtype: str
        """

    @staticmethod
    def toBinaryStr(bs: jpype.JArray[jpype.JByte]) -> str:
        """
        Converts the given byte array to a binary string.
        
        :param jpype.JArray[jpype.JByte] bs: 
        :return: 
        :rtype: str
        """

    @staticmethod
    def toBinaryString(byteval: typing.Union[jpype.JByte, int]) -> str:
        """
        Converts the given byte to a binary string.
        
        :param jpype.JByte or int byteval: 
        :return: 
        :rtype: str
        """

    @staticmethod
    def toByteArray(byteStr: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.Byte]:
        """
        Returns a :obj:`Byte` list from the given byte string.
        
        :param java.lang.String or str byteStr: 
        :return: 
        :rtype: java.util.List[java.lang.Byte]
        """

    @staticmethod
    def toHex(binaryStr: typing.Union[java.lang.String, str], zeroFill: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Converts the given binary instruction to hex.
        
        :param java.lang.String or str binaryStr: binary string
        :return: hex string
        :rtype: str
        """

    @staticmethod
    def toHexNibblesOnly(instr: typing.Union[java.lang.String, str]) -> java.lang.StringBuilder:
        """
        Converts the given binary string to hex, but isn't granular beyond the nibble level. 
        e.g. If the byte string is '00101...' the trailing '1' will be treated as a wildcard ('0010....').
         
        Note: This is primarily for YARA work, since YARA does not get down to the bit level.
        
        :param java.lang.String or str instr: 
        :return: 
        :rtype: java.lang.StringBuilder
        """

    @staticmethod
    def toPrimitive(bytes: jpype.JArray[java.lang.Byte]) -> jpype.JArray[jpype.JByte]:
        """
        Converts a :obj:`Byte` array to a :obj:`byte` array.
        
        :param jpype.JArray[java.lang.Byte] bytes: 
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """



__all__ = ["InstructionSearchUtils"]
