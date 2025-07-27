from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.program.util.string
import ghidra.util.datastruct
import ghidra.util.table
import ghidra.util.table.field
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class FoundStringToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.util.string.FoundString, ghidra.program.model.address.Address]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class SearchStringDialog(docking.DialogComponentProvider):
    """
    Dialog that allows users to search for strings within a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: StringTablePlugin, addressSet: ghidra.program.model.address.AddressSetView):
        ...


class StringTablePlugin(ghidra.app.plugin.ProgramPlugin):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def createStringsProvider(self, options: StringTableOptions):
        ...

    def removeTransientProvider(self, stringTableProvider: StringTableProvider):
        ...


class FoundDefinedStringIterator(java.util.Iterator[ghidra.program.util.string.FoundString]):
    """
    Class to find and iterate over existing defined strings even if they are
    in arrays or structures.  It recursively descends into arrays and structures looking
    for strings.
     
    
    Basic Algorithm: Uses a defined data iterator to find all defined data in a program.  For
    each defined data, strings are searched as follows:
     
    1.  is it a string?  if so, add to the queue of results
    2.  is it an array?  if so, are they non-primitive elements?  if so, recursively search them for strings.
    3.  is it a composite (structure or union)? if so, recursively search each element of the structure.
    
     
    
    This class maintains a queue of all strings found at any given top-level data element.  When
    the queue is empty, it uses the defined data iterator to find the next top-level data element, filling
    the resultQueue with any string found by recursively searching that data element.
     
    
    The iterator is over when the resultQueue is empty and the defined data iterator's hasNext() method is false.
    """

    class_: typing.ClassVar[java.lang.Class]


class NGramUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getLastLoadedTrigramModel() -> str:
        ...

    @staticmethod
    def getLastLoadedTrigramModelPath() -> str:
        ...

    @staticmethod
    def getMinimumStringLength() -> int:
        ...

    @staticmethod
    def getModelType() -> str:
        """
        Return the model type that was stored with the model.
        
        :return: String
        :rtype: str
        """

    @staticmethod
    def isLowerCaseModel() -> bool:
        """
        Returns true if the model is lowercase
        
        :return: boolean
        :rtype: bool
        """

    @staticmethod
    def scoreString(strAndScores: StringAndScores):
        """
        Calculates and stores scores for the [string in the] given StringAndScores object.
        
        :param StringAndScores strAndScores: Object that stores input string and associated scores
        """

    @staticmethod
    def scoreStrings(strAndScoresList: java.util.List[StringAndScores]):
        """
        Calculates and stores scores for a list of StringAndScores objects.
        
        :param java.util.List[StringAndScores] strAndScoresList: List of StringAndScores objects
        """

    @staticmethod
    @typing.overload
    def startNewSession(trigramFile: typing.Union[java.lang.String, str], forceReload: typing.Union[jpype.JBoolean, bool]):
        """
        Invoked when the given model should be loaded, or checked against an existing one to see if it is different (in 
        which case, it would be loaded).
        
        :param java.lang.String or str trigramFile: Name of trigram model file
        :param jpype.JBoolean or bool forceReload: if true, reloads model (even if it is the same name as the previously-loaded model)
        :raises IOException:
        """

    @staticmethod
    @typing.overload
    def startNewSession(model: StringModel):
        """
        Invoked when the given model should be loaded.
        
        :param StringModel model: Model to be loaded.
        """

    @staticmethod
    @typing.overload
    def startNewSession(model: jpype.protocol.SupportsPath):
        """
        Invoked when the given model file should be loaded.
        
        :param jpype.protocol.SupportsPath model: Model file to be loaded
        """


class CombinedStringSearcher(java.lang.Object):

    @typing.type_check_only
    class AccumulatorAdapter(ghidra.program.util.string.FoundStringCallback):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, options: StringTableOptions, accumulator: ghidra.util.datastruct.Accumulator[ghidra.program.util.string.FoundString]):
        ...

    def onlyShowWordStrings(self) -> bool:
        ...

    def search(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Searches the current program for strings based on the user-defined settings in
        :obj:`StringTableOptions`.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises CancelledException:
        """

    def shouldAddDefinedString(self, string: ghidra.program.util.string.FoundString) -> bool:
        ...


class StringAddedEvent(StringEvent):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, stringDataType: ghidra.program.model.data.DataType, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]):
        ...


class StringTableOptions(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def copy(self) -> StringTableOptions:
        ...

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    def getAlignment(self) -> int:
        ...

    def getIncludeAllCharSizes(self) -> bool:
        ...

    def getMinStringSize(self) -> int:
        ...

    def getWordModelFile(self) -> str:
        ...

    def getWordModelInitialized(self) -> bool:
        ...

    def includeConflictingStrings(self) -> bool:
        ...

    def includeDefinedStrings(self) -> bool:
        ...

    def includePartiallyDefinedStrings(self) -> bool:
        ...

    def includeUndefinedStrings(self) -> bool:
        ...

    def isNullTerminationRequired(self) -> bool:
        ...

    def isPascalRequired(self) -> bool:
        ...

    def onlyShowWordStrings(self) -> bool:
        ...

    def setAddressSet(self, addressSet: ghidra.program.model.address.AddressSetView):
        ...

    def setAlignment(self, alignment: typing.Union[jpype.JInt, int]):
        ...

    def setIncludeAllCharSizes(self, includeAllCharSizes: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeConflictingStrings(self, includeConflictingStrings: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeDefinedStrings(self, includeDefinedStrings: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludePartiallyDefinedStrings(self, includePartiallyDefinedStrings: typing.Union[jpype.JBoolean, bool]):
        ...

    def setIncludeUndefinedStrings(self, includeUndefinedStrings: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMinStringSize(self, minStringSize: typing.Union[jpype.JInt, int]):
        ...

    def setNullTerminationRequired(self, required: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOnlyShowWordStrings(self, onlyShowWordStrings: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRequirePascal(self, requirePascal: typing.Union[jpype.JBoolean, bool]):
        ...

    def setUseLoadedBlocksOnly(self, loadedBlocksOnly: typing.Union[jpype.JBoolean, bool]):
        ...

    def setWordModelFile(self, wordModelFile: typing.Union[java.lang.String, str]):
        ...

    def setWordModelInitialized(self, wordModelInitialized: typing.Union[jpype.JBoolean, bool]):
        ...

    def useLoadedBlocksOnly(self) -> bool:
        ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @addressSet.setter
    def addressSet(self, value: ghidra.program.model.address.AddressSetView):
        ...

    @property
    def pascalRequired(self) -> jpype.JBoolean:
        ...

    @property
    def includeAllCharSizes(self) -> jpype.JBoolean:
        ...

    @includeAllCharSizes.setter
    def includeAllCharSizes(self, value: jpype.JBoolean):
        ...

    @property
    def nullTerminationRequired(self) -> jpype.JBoolean:
        ...

    @nullTerminationRequired.setter
    def nullTerminationRequired(self, value: jpype.JBoolean):
        ...

    @property
    def wordModelFile(self) -> java.lang.String:
        ...

    @wordModelFile.setter
    def wordModelFile(self, value: java.lang.String):
        ...

    @property
    def wordModelInitialized(self) -> jpype.JBoolean:
        ...

    @wordModelInitialized.setter
    def wordModelInitialized(self, value: jpype.JBoolean):
        ...

    @property
    def alignment(self) -> jpype.JInt:
        ...

    @alignment.setter
    def alignment(self, value: jpype.JInt):
        ...

    @property
    def minStringSize(self) -> jpype.JInt:
        ...

    @minStringSize.setter
    def minStringSize(self, value: jpype.JInt):
        ...


class StringEventsTask(ghidra.util.task.Task):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, stringModel: StringTableModel, options: StringTableOptions, list: java.util.List[StringEvent]):
        ...


class StringAndScores(java.lang.Object):
    """
    Storage class for Strings identified by the String Searcher and their associated
    ngram scores.  The scores, combined with the score thresholds, determine if this 
    string passes or fails.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, str: typing.Union[java.lang.String, str], isLowerCaseModel: typing.Union[jpype.JBoolean, bool]):
        ...

    def getAsciiCodes(self) -> jpype.JArray[jpype.JInt]:
        ...

    def getNgramScore(self) -> float:
        ...

    def getOriginalString(self) -> str:
        ...

    def getScoreThreshold(self) -> float:
        ...

    def getScoredString(self) -> str:
        ...

    def getScoredStringLength(self) -> int:
        ...

    def isScoreAboveThreshold(self) -> bool:
        ...

    def setNgramScore(self, ngSc: typing.Union[jpype.JDouble, float]):
        ...

    def setScoreThreshold(self, thresh: typing.Union[jpype.JDouble, float]):
        ...

    def summaryToString(self) -> str:
        ...

    @property
    def scoreThreshold(self) -> jpype.JDouble:
        ...

    @scoreThreshold.setter
    def scoreThreshold(self, value: jpype.JDouble):
        ...

    @property
    def asciiCodes(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def scoredString(self) -> java.lang.String:
        ...

    @property
    def ngramScore(self) -> jpype.JDouble:
        ...

    @ngramScore.setter
    def ngramScore(self, value: jpype.JDouble):
        ...

    @property
    def scoreAboveThreshold(self) -> jpype.JBoolean:
        ...

    @property
    def originalString(self) -> java.lang.String:
        ...

    @property
    def scoredStringLength(self) -> jpype.JInt:
        ...


class StringsAnalyzer(ghidra.app.services.AbstractAnalyzer):

    class Alignment(java.lang.Enum[StringsAnalyzer.Alignment]):

        class_: typing.ClassVar[java.lang.Class]
        ALIGN_1: typing.Final[StringsAnalyzer.Alignment]
        ALIGN_2: typing.Final[StringsAnalyzer.Alignment]
        ALIGN_4: typing.Final[StringsAnalyzer.Alignment]

        def getAlignment(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StringsAnalyzer.Alignment:
            ...

        @staticmethod
        def values() -> jpype.JArray[StringsAnalyzer.Alignment]:
            ...

        @property
        def alignment(self) -> jpype.JInt:
            ...


    class MinStringLen(java.lang.Enum[StringsAnalyzer.MinStringLen]):

        class_: typing.ClassVar[java.lang.Class]
        LEN_4: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_5: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_6: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_7: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_8: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_9: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_10: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_11: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_12: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_13: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_14: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_15: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_16: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_17: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_18: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_19: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_20: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_21: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_22: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_23: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_24: typing.Final[StringsAnalyzer.MinStringLen]
        LEN_25: typing.Final[StringsAnalyzer.MinStringLen]

        def getMinLength(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> StringsAnalyzer.MinStringLen:
            ...

        @staticmethod
        def values() -> jpype.JArray[StringsAnalyzer.MinStringLen]:
            ...

        @property
        def minLength(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FoundStringToProgramLocationTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[ghidra.program.util.string.FoundString, ghidra.program.util.ProgramLocation]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MakeStringsTask(ghidra.program.util.ProgramTask):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, foundStrings: java.util.List[ghidra.program.util.string.FoundString], offset: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], autoLabel: typing.Union[jpype.JBoolean, bool], addAlignmentBytes: typing.Union[jpype.JBoolean, bool], allowTruncate: typing.Union[jpype.JBoolean, bool], makeArray: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, foundString: ghidra.program.util.string.FoundString, offset: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], autoLabel: typing.Union[jpype.JBoolean, bool], addAlignmentBytes: typing.Union[jpype.JBoolean, bool], allowTruncate: typing.Union[jpype.JBoolean, bool], makeArray: typing.Union[jpype.JBoolean, bool]):
        ...

    def getStringEvents(self) -> java.util.List[StringEvent]:
        ...

    def hasErrors(self) -> bool:
        ...

    @property
    def stringEvents(self) -> java.util.List[StringEvent]:
        ...


class StringTableProvider(ghidra.framework.plugintool.ComponentProviderAdapter, ghidra.framework.model.DomainObjectListener):
    """
    Component provider for the Search -> For Strings... result dialog.
    """

    @typing.type_check_only
    class DefinedColumnRenderer(docking.widgets.table.GTableCellRenderer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: StringTablePlugin, options: StringTableOptions, isTransient: typing.Union[jpype.JBoolean, bool]):
        ...

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program):
        ...


class StringModel(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, asciiTrigrams: jpype.JArray[jpype.JArray[jpype.JArray[jpype.JInt]]], beginTrigram: jpype.JArray[jpype.JArray[jpype.JInt]], endTrigram: jpype.JArray[jpype.JArray[jpype.JInt]], numTrigrams: typing.Union[jpype.JLong, int]):
        ...

    def getBeginTrigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JInt]]:
        ...

    def getEndTrigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JInt]]:
        ...

    def getTotalNumTrigrams(self) -> int:
        ...

    def getTrigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JArray[jpype.JInt]]]:
        ...

    def setTrigramCounts(self, asciiTrigrams: jpype.JArray[jpype.JArray[jpype.JArray[jpype.JInt]]], beginTrigram: jpype.JArray[jpype.JArray[jpype.JInt]], endTrigram: jpype.JArray[jpype.JArray[jpype.JInt]], numTrigrams: typing.Union[jpype.JLong, int]):
        ...

    def writeTrigramModelFile(self, trigramFilename: typing.Union[java.lang.String, str], trainingFiles: java.util.List[java.lang.String], modelType: typing.Union[java.lang.String, str], outputPath: jpype.protocol.SupportsPath):
        ...

    @property
    def trigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JArray[jpype.JInt]]]:
        ...

    @property
    def totalNumTrigrams(self) -> jpype.JLong:
        ...

    @property
    def beginTrigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JInt]]:
        ...

    @property
    def endTrigramCounts(self) -> jpype.JArray[jpype.JArray[jpype.JInt]]:
        ...


class FoundStringWithWordStatus(ghidra.program.util.string.FoundString):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, source: ghidra.program.util.string.FoundString):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType, definedState: ghidra.program.util.string.FoundString.DefinedState):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType, isWord: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], stringDataType: ghidra.program.model.data.DataType, definedState: ghidra.program.util.string.FoundString.DefinedState, isWord: typing.Union[jpype.JBoolean, bool]):
        ...

    def isHighConfidenceWord(self) -> bool:
        ...

    def setIsHighConfidenceWord(self, isWord: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def highConfidenceWord(self) -> jpype.JBoolean:
        ...


class StringEvent(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getMaxAddress(self, addr1: ghidra.program.model.address.Address, addr2: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def getMinAddress(self, addr1: ghidra.program.model.address.Address, addr2: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def process(self, model: StringTableModel, options: StringTableOptions):
        ...


@typing.type_check_only
class ModelLogProbabilities(java.lang.Object):
    """
    Storage for log probabilities calculated for a model (after counts have been smoothed).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, numAsciiChars: typing.Union[jpype.JInt, int]):
        ...

    def getBeginLogTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JDouble]]:
        ...

    def getEndLogTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JDouble]]:
        ...

    def getLogTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JArray[jpype.JDouble]]]:
        ...

    @property
    def endLogTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JDouble]]:
        ...

    @property
    def logTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JArray[jpype.JDouble]]]:
        ...

    @property
    def beginLogTrigrams(self) -> jpype.JArray[jpype.JArray[jpype.JDouble]]:
        ...


class StringTableModel(ghidra.util.table.AddressBasedTableModel[ghidra.program.util.string.FoundString]):
    """
    Table model for the Search -> For Strings... result dialog.
    """

    @typing.type_check_only
    class StringTypeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.util.string.FoundString, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringLengthTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.util.string.FoundString, java.lang.Integer]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class IsDefinedTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.util.string.FoundString, ghidra.program.util.string.FoundString.DefinedState]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StringViewTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.util.string.FoundString, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ConfidenceWordTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ghidra.program.util.string.FoundString, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["FoundStringToAddressTableRowMapper", "SearchStringDialog", "StringTablePlugin", "FoundDefinedStringIterator", "NGramUtils", "CombinedStringSearcher", "StringAddedEvent", "StringTableOptions", "StringEventsTask", "StringAndScores", "StringsAnalyzer", "FoundStringToProgramLocationTableRowMapper", "MakeStringsTask", "StringTableProvider", "StringModel", "FoundStringWithWordStatus", "StringEvent", "ModelLogProbabilities", "StringTableModel"]
