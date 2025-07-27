from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.block
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class SubroutineMatchSet(java.util.ArrayList[SubroutineMatch]):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
    """

    class_: typing.ClassVar[java.lang.Class]
    aProgram: typing.Final[ghidra.program.model.listing.Program]
    bProgram: typing.Final[ghidra.program.model.listing.Program]

    def __init__(self, aProgram: ghidra.program.model.listing.Program, aModel: ghidra.program.model.block.CodeBlockModel, bProgram: ghidra.program.model.listing.Program, bModel: ghidra.program.model.block.CodeBlockModel):
        """
        
        
        :param ghidra.program.model.listing.Program aProgram: The program from which the matching was initiated.
        :param ghidra.program.model.listing.Program bProgram: The program being matched.
        """

    @typing.overload
    def getLength(self, addr: ghidra.program.model.address.Address, model: ghidra.program.model.block.CodeBlockModel) -> int:
        ...

    @typing.overload
    def getLength(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Assumes the address is in program a
        """

    def getMatches(self) -> jpype.JArray[SubroutineMatch]:
        """
        
        
        :return: The sorted array of matches.
        :rtype: jpype.JArray[SubroutineMatch]
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def matches(self) -> jpype.JArray[SubroutineMatch]:
        ...


class MatchSymbol(java.lang.Object):

    @typing.type_check_only
    class SymbolMatchType(java.lang.Enum[MatchSymbol.SymbolMatchType]):

        class_: typing.ClassVar[java.lang.Class]
        FUNCTION: typing.Final[MatchSymbol.SymbolMatchType]
        DATA: typing.Final[MatchSymbol.SymbolMatchType]
        OTHER: typing.Final[MatchSymbol.SymbolMatchType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> MatchSymbol.SymbolMatchType:
            ...

        @staticmethod
        def values() -> jpype.JArray[MatchSymbol.SymbolMatchType]:
            ...


    @typing.type_check_only
    class SymbolIdentifier(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Match(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class MatchedSymbol(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getAProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getASymbolAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getBProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getBSymbolAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getMatchCount(self) -> int:
            ...

        def getMatchType(self) -> ghidra.program.model.symbol.SymbolType:
            ...

        @property
        def matchType(self) -> ghidra.program.model.symbol.SymbolType:
            ...

        @property
        def bSymbolAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def bProgram(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def matchCount(self) -> jpype.JInt:
            ...

        @property
        def aProgram(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def aSymbolAddress(self) -> ghidra.program.model.address.Address:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def matchSymbol(aProgram: ghidra.program.model.listing.Program, setA: ghidra.program.model.address.AddressSetView, bProgram: ghidra.program.model.listing.Program, setB: ghidra.program.model.address.AddressSetView, minSymbolNameLength: typing.Union[jpype.JInt, int], includeOneToOneOnly: typing.Union[jpype.JBoolean, bool], includeExternals: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MatchSymbol.MatchedSymbol]:
        ...


class SubroutineMatch(java.lang.Object):
    """
    Cheap container for match info.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reason: typing.Union[java.lang.String, str]):
        ...

    def add(self, addr: ghidra.program.model.address.Address, isA: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def getAAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    def getBAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    def getReason(self) -> str:
        ...

    def remove(self, addr: ghidra.program.model.address.Address, isA: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @property
    def reason(self) -> java.lang.String:
        ...

    @property
    def aAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def bAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...


class ExactInstructionsFunctionHasher(AbstractFunctionHasher):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ExactInstructionsFunctionHasher]


class MatchedData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAData(self) -> ghidra.program.model.listing.Data:
        ...

    def getADataAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getAMatchNum(self) -> int:
        ...

    def getAProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getBData(self) -> ghidra.program.model.listing.Data:
        ...

    def getBDataAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getBMatchNum(self) -> int:
        ...

    def getBProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def getReason(self) -> str:
        ...

    @property
    def reason(self) -> java.lang.String:
        ...

    @property
    def bDataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def bProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def aMatchNum(self) -> jpype.JInt:
        ...

    @property
    def bData(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def aProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def bMatchNum(self) -> jpype.JInt:
        ...

    @property
    def aData(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def aDataAddress(self) -> ghidra.program.model.address.Address:
        ...


class MatchFunctions(java.lang.Object):
    """
    This class does the work of matching subroutines. Every subroutine
    in the current program is hashed and the start address is put into a 
    table. There are often identical subroutines which may have the same hash
    value. Then the subroutines in the other program are hashed as well. All unique
    match pairs are returned as matches. The next step would be to use call graph
    information or address order to get additional matches.
    """

    @typing.type_check_only
    class Match(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def add(self, address: ghidra.program.model.address.Address, isProgA: typing.Union[jpype.JBoolean, bool]):
            ...


    class MatchedFunctions(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def getAFunctionAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getAMatchNum(self) -> int:
            ...

        def getAProgram(self) -> ghidra.program.model.listing.Program:
            ...

        def getBFunctionAddress(self) -> ghidra.program.model.address.Address:
            ...

        def getBMatchNum(self) -> int:
            ...

        def getBProgram(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def aFunctionAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def bProgram(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def aMatchNum(self) -> jpype.JInt:
            ...

        @property
        def bFunctionAddress(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def aProgram(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def bMatchNum(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def matchFunctions(aProgram: ghidra.program.model.listing.Program, setA: ghidra.program.model.address.AddressSetView, bProgram: ghidra.program.model.listing.Program, setB: ghidra.program.model.address.AddressSetView, minimumFunctionSize: typing.Union[jpype.JInt, int], includeOneToOne: typing.Union[jpype.JBoolean, bool], includeNonOneToOne: typing.Union[jpype.JBoolean, bool], hasher: FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MatchFunctions.MatchedFunctions]:
        ...

    @staticmethod
    @typing.overload
    def matchOneFunction(aProgram: ghidra.program.model.listing.Program, aEntryPoint: ghidra.program.model.address.Address, bProgram: ghidra.program.model.listing.Program, hasher: FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MatchFunctions.MatchedFunctions]:
        ...

    @staticmethod
    @typing.overload
    def matchOneFunction(aProgram: ghidra.program.model.listing.Program, aEntryPoint: ghidra.program.model.address.Address, bProgram: ghidra.program.model.listing.Program, bAddressSet: ghidra.program.model.address.AddressSetView, hasher: FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MatchFunctions.MatchedFunctions]:
        ...


class MatchData(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def matchData(aProgram: ghidra.program.model.listing.Program, setA: ghidra.program.model.address.AddressSetView, bProgram: ghidra.program.model.listing.Program, setB: ghidra.program.model.address.AddressSetView, minimumDataSize: typing.Union[jpype.JInt, int], maximumDataSize: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], skipHomogenousData: typing.Union[jpype.JBoolean, bool], includeOneToOne: typing.Union[jpype.JBoolean, bool], includeNonOneToOne: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[MatchedData]:
        ...


class ExactBytesFunctionHasher(AbstractFunctionHasher):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ExactBytesFunctionHasher]


class Match(java.lang.Comparable[Match]):
    """
    Match maintains information about a single match between two programs.
    The match can consist of either bytes or code units.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, thisBeginning: ghidra.program.model.address.Address, otherBeginning: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], length: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.address.Address thisBeginning: The start Address of the match in the program
        from which the matches are being found.
        :param ghidra.program.model.address.Address otherBeginning: The start Address of the match in the program
        to which the matches are being found.
        :param jpype.JArray[jpype.JByte] bytes: the bytes which make up this match.
        :param jpype.JInt or int length: the length of the bytes array.
        """

    @typing.overload
    def __init__(self, thisBeginning: ghidra.program.model.address.Address, otherBeginning: ghidra.program.model.address.Address, codeUnits: jpype.JArray[ghidra.program.model.listing.CodeUnit], otherUnits: jpype.JArray[ghidra.program.model.listing.CodeUnit], length: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.address.Address thisBeginning: The start Address of the match in the program
        from which the matches are being found.
        :param ghidra.program.model.address.Address otherBeginning: The start Address of the match in the program
        to which the matches are being found.
        :param jpype.JArray[ghidra.program.model.listing.CodeUnit] codeUnits: The CodeUnits which make up the match in this
        Program.
        :param jpype.JArray[ghidra.program.model.listing.CodeUnit] otherUnits: The CodeUnits which make up this match in the 
        other program. Note, the code units need no match up byte for 
        byte.
        :param jpype.JInt or int length: The length of the CodeUnit arrays.
        """

    def compareTo(self, m: Match) -> int:
        ...

    @typing.overload
    def continueMatch(self, b: typing.Union[jpype.JByte, int]):
        """
        
        
        :param jpype.JByte or int b: Continue the match by adding the additional byte b.
        """

    @typing.overload
    def continueMatch(self, cu: ghidra.program.model.listing.CodeUnit, otherUnit: ghidra.program.model.listing.CodeUnit):
        """
        
        
        :param ghidra.program.model.listing.CodeUnit cu: The CodeUnit which extends the match in 'this' program.
        :param ghidra.program.model.listing.CodeUnit otherUnit: The CodeUnit which extends the match in 'the other'
        program.
        """

    def expectedAddressForNextMatch(self, baseLength: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        
        
        :param jpype.JInt or int baseLength: the minimum number of items which make up a match.
        There are different values for instruction and byte matches. This
        value should either be NaiveMatchPlugin.MATCH_LENGTH_FOR_INSTRUCTIONS
        or NaiveMatchPlugin.MATCH_LENGTH_FOR_BYTES which can be found by
        calling getMatchLengthForInstructions() or getMatchLengthForBytes().
        :return: The Address at which a continuing byte or code unit would
        be expected to be found in the other program.
        :rtype: ghidra.program.model.address.Address
        """

    def getBytes(self) -> jpype.JArray[java.lang.Object]:
        """
        
        
        :return: array containing the objects that make up the match 
        in this program.
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getOtherBeginning(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: The Address that starts the match in the other program.
        :rtype: ghidra.program.model.address.Address
        """

    def getOtherBytes(self) -> jpype.JArray[java.lang.Object]:
        """
        
        
        :return: array containing the objects that make up the match 
        in the other program.
        :rtype: jpype.JArray[java.lang.Object]
        """

    def getThisBeginning(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: The Address that starts the match in this program.
        :rtype: ghidra.program.model.address.Address
        """

    def length(self) -> int:
        """
        
        
        :return: The number of items that make up this match.
        :rtype: int
        """

    def printMatch(self) -> str:
        ...

    def totalLength(self) -> int:
        """
        
        
        :return: The total number of bytes that make up this match.
        :rtype: int
        """

    @property
    def otherBeginning(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def otherBytes(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def bytes(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def thisBeginning(self) -> ghidra.program.model.address.Address:
        ...


class FunctionHasher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def commonBitCount(self, funcA: ghidra.program.model.listing.Function, funcB: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> int:
        ...

    def hash(self, function: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> int:
        ...


class AbstractFunctionHasher(FunctionHasher):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionMatchSet(java.util.ArrayList[SubroutineMatch]):
    """
    To change the template for this generated type comment go to
    Window>Preferences>Java>Code Generation>Code and Comments
    """

    class_: typing.ClassVar[java.lang.Class]
    aProgram: typing.Final[ghidra.program.model.listing.Program]
    bProgram: typing.Final[ghidra.program.model.listing.Program]

    def __init__(self, aProgram: ghidra.program.model.listing.Program, bProgram: ghidra.program.model.listing.Program):
        """
        
        
        :param ghidra.program.model.listing.Program aProgram: The program from which the matching was initiated.
        :param ghidra.program.model.listing.Program bProgram: The program being matched.
        """

    @typing.overload
    def getLength(self, addr: ghidra.program.model.address.Address, aProgram: ghidra.program.model.listing.Program) -> int:
        ...

    @typing.overload
    def getLength(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Assumes the address is in program a
        """

    def getMatches(self) -> jpype.JArray[SubroutineMatch]:
        """
        
        
        :return: The sorted array of matches.
        :rtype: jpype.JArray[SubroutineMatch]
        """

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def matches(self) -> jpype.JArray[SubroutineMatch]:
        ...


class ExactMnemonicsFunctionHasher(ExactInstructionsFunctionHasher):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ExactMnemonicsFunctionHasher]


class MatchSet(java.util.HashSet[Match]):
    """
    class that contains a collection of matches.
    """

    class_: typing.ClassVar[java.lang.Class]
    thisName: typing.Final[java.lang.String]
    otherName: typing.Final[java.lang.String]

    def __init__(self, thisProgramName: typing.Union[java.lang.String, str], otherProgramName: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str thisProgramName: Name of this program (i.e. the program from 
        which the matching was initiated.
        :param java.lang.String or str otherProgramName: Name of the program being matched.
        """

    def getMatches(self) -> jpype.JArray[Match]:
        """
        
        
        :return: The sorted array of matches.
        :rtype: jpype.JArray[Match]
        """

    def getResultsArray(self, m: Match) -> jpype.JArray[java.lang.Object]:
        """
        
        
        :return: The match as an Object array.
        :rtype: jpype.JArray[java.lang.Object]
        """

    @property
    def resultsArray(self) -> jpype.JArray[java.lang.Object]:
        ...

    @property
    def matches(self) -> jpype.JArray[Match]:
        ...



__all__ = ["SubroutineMatchSet", "MatchSymbol", "SubroutineMatch", "ExactInstructionsFunctionHasher", "MatchedData", "MatchFunctions", "MatchData", "ExactBytesFunctionHasher", "Match", "FunctionHasher", "AbstractFunctionHasher", "FunctionMatchSet", "ExactMnemonicsFunctionHasher", "MatchSet"]
