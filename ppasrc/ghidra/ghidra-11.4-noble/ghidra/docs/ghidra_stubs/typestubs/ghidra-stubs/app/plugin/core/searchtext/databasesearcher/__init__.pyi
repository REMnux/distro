from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.searchtext
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util.regex # type: ignore


class LabelFieldSearcher(ProgramDatabaseFieldSearcher):

    @typing.type_check_only
    class SymbolAddressIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern):
        ...


class FunctionFieldSearcher(ProgramDatabaseFieldSearcher):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern):
        ...


class ProgramDatabaseFieldSearcher(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getMatch(self) -> ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult:
        ...

    def getNextSignificantAddress(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def hasMatch(self, address: ghidra.program.model.address.Address) -> bool:
        ...

    @property
    def match(self) -> ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult:
        ...

    @property
    def nextSignificantAddress(self) -> ghidra.program.model.address.Address:
        ...


class DataMnemonicOperandFieldSearcher(ProgramDatabaseFieldSearcher):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CommentFieldSearcher(ProgramDatabaseFieldSearcher):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern, commentType: ghidra.program.model.listing.CommentType):
        ...


class InstructionMnemonicOperandFieldSearcher(ProgramDatabaseFieldSearcher):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createInstructionMnemonicAndOperandFieldSearcher(program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern, format: ghidra.program.model.listing.CodeUnitFormat) -> InstructionMnemonicOperandFieldSearcher:
        ...

    @staticmethod
    def createInstructionMnemonicOnlyFieldSearcher(program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern, format: ghidra.program.model.listing.CodeUnitFormat) -> InstructionMnemonicOperandFieldSearcher:
        ...

    @staticmethod
    def createInstructionOperandOnlyFieldSearcher(program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool], pattern: java.util.regex.Pattern, format: ghidra.program.model.listing.CodeUnitFormat) -> InstructionMnemonicOperandFieldSearcher:
        ...


class ProgramDatabaseSearcher(ghidra.app.plugin.core.searchtext.Searcher):
    """
    This class combines multiple field searchers to present a simple searcher interface for users of 
    this class. First, based on the searchOptions, a field searcher is created for each field to be
    search (comments, mnemonics, operands, etc.)  The searchers are ordered based on which field's matches
    should be presented before another field's match at the same address.  Backwards searches would
    have the searchers in the opposite order for forward searches.  This search is an efficient breadth
    first search by requiring that each searcher only advance one record and only move to the next record
    when all the other searches have reached records at or beyond the address of this searcher's current
    record.  The basic algorithm is to ask each searcher if they have a match at the current address.  Since
    they are asked in the appropriate order, if any of them has a match at the current address, it is
    immediately returned.  Once all the searchers report not having a match at the current address, the
    current address is advanced to the next address of the searcher whose current record is closest to
    the current address (if the searcher's record is the current address, this is when it would fetch
    its next record).
     
    
    When a searcher's getMatch() method is called, the searcher should return it current match and 
    advance its internal pointer to any additional matches at the same address or be prepared to 
    report no match when the hasMatch() method is called again at the same address.  When the 
    findNextSignificantAddress() method is called, the searcher should report its current record's
    address if that address is not the current address.  Otherwise, the searcher should advance to
    its next record and report that address.  When a search has no more records in the search
    address set, it should return null for the findNextSignificantAddress() method and hasMatch should
    return false.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, startLoc: ghidra.program.util.ProgramLocation, set: ghidra.program.model.address.AddressSetView, options: ghidra.app.plugin.core.searchtext.SearchOptions, monitor: ghidra.util.task.TaskMonitor):
        ...


class ProgramDatabaseSearchTableModel(ghidra.app.plugin.core.searchtext.AbstractSearchTableModel):
    """
    Table model for showing results of "Search All" in a program database Text search.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, p: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, options: ghidra.app.plugin.core.searchtext.SearchOptions):
        """
        Constructs a program database text search table model.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        :param ghidra.program.model.listing.Program p: the program
        :param ghidra.program.model.address.AddressSetView set: address set to search
        :param ghidra.app.plugin.core.searchtext.SearchOptions options: search options
        """



__all__ = ["LabelFieldSearcher", "FunctionFieldSearcher", "ProgramDatabaseFieldSearcher", "DataMnemonicOperandFieldSearcher", "CommentFieldSearcher", "InstructionMnemonicOperandFieldSearcher", "ProgramDatabaseSearcher", "ProgramDatabaseSearchTableModel"]
