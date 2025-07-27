from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import java.lang # type: ignore
import javax.swing # type: ignore


class MergeUtilities(java.lang.Object):
    """
    ``MergeUtilities`` provides generic static methods for use by the 
    multi-user program merge managers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def adjustSets(latestDiffs: ghidra.program.model.address.AddressSetView, myDiffs: ghidra.program.model.address.AddressSetView, autoChanges: ghidra.program.model.address.AddressSet, conflictChanges: ghidra.program.model.address.AddressSet):
        """
        Adds addresses to autoChanges where there are changes in the myDiffs set,
        but none in the latestDiffs set.
        Adds addresses to conflictChanges where there are changes in the myDiffs 
        set and also some changes in the latestDiffs set.
        
        :param ghidra.program.model.address.AddressSetView latestDiffs: the address set of the changes in LATEST.
        :param ghidra.program.model.address.AddressSetView myDiffs: the address set of the changes in MY.
        :param ghidra.program.model.address.AddressSet autoChanges: address set for the myDiffs non-conflicting changes.
        :param ghidra.program.model.address.AddressSet conflictChanges: address set for the myDiffs conflicting changes
        """


class ConflictCountPanel(javax.swing.JPanel):
    """
    Panel that shows the current conflict number and the total number of
    conflicts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructor
        """

    def updateCount(self, currentCount: typing.Union[jpype.JInt, int], totalCount: typing.Union[jpype.JInt, int]):
        """
        Update the counts, e.g., Conflict # 1 of 3.
        
        :param jpype.JInt or int currentCount: current
        :param jpype.JInt or int totalCount: total
        """


class ConflictUtility(java.lang.Object):
    """
    ``ConflictUtility`` provides some constants and static methods 
    used by the Listing Merge portion of the multi-user merge.
    For now, the VariousChoicesPanel and VerticalChoicesPanel use HTML in
    JLabels to display color etc. This is because they also show radiobuttons
    and checkboxes.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAROON: typing.ClassVar[java.lang.String]
    GREEN: typing.ClassVar[java.lang.String]
    BLUE: typing.ClassVar[java.lang.String]
    PURPLE: typing.ClassVar[java.lang.String]
    DARK_CYAN: typing.ClassVar[java.lang.String]
    OLIVE: typing.ClassVar[java.lang.String]
    ORANGE: typing.ClassVar[java.lang.String]
    PINK: typing.ClassVar[java.lang.String]
    YELLOW: typing.ClassVar[java.lang.String]
    GRAY: typing.ClassVar[java.lang.String]
    ADDRESS_COLOR: typing.ClassVar[java.lang.String]
    """
    Color to use for displaying addresses.
    """

    NUMBER_COLOR: typing.ClassVar[java.lang.String]
    """
    Color to use for displaying numeric values.
    """

    EMPHASIZE_COLOR: typing.ClassVar[java.lang.String]
    """
    Color to use for displaying emphasized text. (for example, this is used when displaying symbols.)
    """

    OFFSET_COLOR: typing.ClassVar[java.lang.String]
    """
    Color to use for displaying offsets.
    """

    NO_VALUE: typing.ClassVar[java.lang.String]
    """
    String to display when a version doesn't have a value for an element of the program.
    """


    def __init__(self):
        ...

    @staticmethod
    def addAddress(buf: java.lang.StringBuffer, addr: ghidra.program.model.address.Address):
        """
        Adds a color program address to the indicated string buffer.
        
        :param java.lang.StringBuffer buf: the string buffer
        :param ghidra.program.model.address.Address addr: the program address
        """

    @staticmethod
    def addCount(buf: java.lang.StringBuffer, value: typing.Union[jpype.JInt, int]):
        """
        Adds a color number to the indicated string  buffer.
        
        :param java.lang.StringBuffer buf: the string buffer
        :param jpype.JInt or int value: the integer number
        """

    @staticmethod
    @typing.overload
    def colorString(rgbColor: typing.Union[java.lang.String, str], text: typing.Union[java.lang.String, str]) -> str:
        """
        This creates color text by wrapping a text string with an HTML font tag 
        that has a color attribute.
        
        :param java.lang.String or str rgbColor: (eg. "#8c0000")
        :param java.lang.String or str text: the text to be colored
        :return: the tagged string.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def colorString(rgbColor: typing.Union[java.lang.String, str], value: typing.Union[jpype.JInt, int]) -> str:
        """
        This creates a colored number by converting the number to a string and 
        wrapping it with an HTML font tag that has a color attribute.
        
        :param java.lang.String or str rgbColor: (eg. "#8c0000")
        :param jpype.JInt or int value: the integer number
        :return: the tagged string.
        :rtype: str
        """

    @staticmethod
    def getAddressConflictCount(addressNum: typing.Union[jpype.JInt, int], totalAddresses: typing.Union[jpype.JInt, int], isRange: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Creates a standard address set conflict count message. This indicates 
        which address or address range with conflicts you are resolving of some 
        total number of addresses or address ranges with conflicts.
        
        :param jpype.JInt or int addressNum: the current conflicting address number.
        :param jpype.JInt or int totalAddresses: the total number of conflicting addresses.
        :param jpype.JBoolean or bool isRange: true if the current conflict is for an address range.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getAddressString(address: ghidra.program.model.address.Address) -> str:
        """
        Creates a string containing HTML tags to represent the address in color.
        
        :param ghidra.program.model.address.Address address: the program address.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getAddressString(address: ghidra.program.model.address.Address, showAddressSpace: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Creates a string containing HTML tags to represent the address in color.
        
        :param ghidra.program.model.address.Address address: the program address.
        :param jpype.JBoolean or bool showAddressSpace: true indicates the address string should show the address space.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getConflictCount(conflictNum: typing.Union[jpype.JInt, int], totalConflicts: typing.Union[jpype.JInt, int]) -> str:
        """
        Creates a standard conflict count message. This indicates which conflict
        you are resolving of some total number of conflicts.
        
        :param jpype.JInt or int conflictNum: the current conflict number.
        :param jpype.JInt or int totalConflicts: the total number of conflicts
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getConflictCount(conflictNum: typing.Union[jpype.JInt, int], totalConflicts: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> str:
        """
        Creates a standard conflict count message for an address. This indicates which conflict
        you are resolving of some total number of conflicts at a given address.
        
        :param jpype.JInt or int conflictNum: the current conflict number.
        :param jpype.JInt or int totalConflicts: the total number of conflicts
        :param ghidra.program.model.address.Address addr: the address for the indicated conflicts.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getConflictCount(conflictNum: typing.Union[jpype.JInt, int], totalConflicts: typing.Union[jpype.JInt, int], range: ghidra.program.model.address.AddressRange) -> str:
        """
        Creates a standard conflict count message for an address range. This indicates which conflict
        you are resolving of some total number of conflicts for a given address range.
        
        :param jpype.JInt or int conflictNum: the current conflict number.
        :param jpype.JInt or int totalConflicts: the total number of conflicts
        :param ghidra.program.model.address.AddressRange range: the address range for the indicated conflicts.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def getEmphasizeString(text: typing.Union[java.lang.String, str]) -> str:
        """
        Creates a string containing HTML tags to represent the text in color for emphasis.
        
        :param java.lang.String or str text: the text to be emphasized.
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def getHashString(hash: typing.Union[jpype.JLong, int]) -> str:
        """
        Creates a string containing HTML tags to represent the hash value in 
        color as an unsigned hexadecimal value.
        
        :param jpype.JLong or int hash: the hash to be displayed in hexadecimal
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def getNumberString(count: typing.Union[jpype.JInt, int]) -> str:
        """
        Creates a string containing HTML tags to represent the integer number in color.
        
        :param jpype.JInt or int count: the integer number
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def getOffsetString(offset: typing.Union[jpype.JInt, int]) -> str:
        """
        Creates a string containing HTML tags to represent the offset value in 
        color as a hexadecimal value.
        
        :param jpype.JInt or int offset: the offset to be displayed in hexadecimal
        :return: the message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def getTruncatedHTMLString(originalString: typing.Union[java.lang.String, str], truncLength: typing.Union[jpype.JInt, int]) -> str:
        """
        Surrounds the originalString with HTML tags. It truncates the string at
        truncLength number of characters and adds "..." if it is longer than truncLength.
        It also replaces newline characters with HTML break tags.
         
        
        Warning: The originalString should not contain special HTML tags. If it does,
        they may get truncated in the middle of a tag.
        
        :param java.lang.String or str originalString: 
        :param jpype.JInt or int truncLength: truncate at this length
        :return: the truncated message string containing HTML tags.
        :rtype: str
        """

    @staticmethod
    def spaces(num: typing.Union[jpype.JInt, int]) -> str:
        """
        Creates a string for the number of spaces indicated that can be used in HTML.
        This string can be used to preserve spacing.
        
        :param jpype.JInt or int num: the number of spaces
        :return: the string representing that many spaces in HTML.
        :rtype: str
        """

    @staticmethod
    def wrapAsHTML(text: typing.Union[java.lang.String, str]) -> str:
        """
        Puts HTML and BODY tags around the string.
        """



__all__ = ["MergeUtilities", "ConflictCountPanel", "ConflictUtility"]
