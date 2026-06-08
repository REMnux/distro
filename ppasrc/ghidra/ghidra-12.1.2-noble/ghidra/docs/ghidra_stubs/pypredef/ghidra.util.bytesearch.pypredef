from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.features.base.memsearch.bytesource
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


class PatternFactory(java.lang.Object):
    """
    Interface for factories that create Match Pattern classes
    """

    class_: typing.ClassVar[java.lang.Class]

    def getMatchActionByName(self, nm: typing.Union[java.lang.String, str]) -> MatchAction:
        """
        Get a named match action
        
        :param java.lang.String or str nm: name of action to find
        :return: match action with the given name, null otherwise
        :rtype: MatchAction
        """

    def getPostRuleByName(self, nm: typing.Union[java.lang.String, str]) -> PostRule:
        """
        Get a named post match rule by name
        
        :param java.lang.String or str nm: name of the post rule
        :return: the post rule with the name, null otherwise
        :rtype: PostRule
        """

    @property
    def matchActionByName(self) -> MatchAction:
        ...

    @property
    def postRuleByName(self) -> PostRule:
        ...


class MatchAction(java.lang.Object):
    """
    Interface for a match action to be taken for the Program@Address for a ditted bit seqence pattern
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, match: Match[Pattern]) -> None:
        """
        Apply the match action to the program at the address.
        
        :param ghidra.program.model.listing.Program program: program in which the match occurred
        :param ghidra.program.model.address.Address addr: where the match occured
        :param Match[Pattern] match: information about the match that occurred
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser) -> None:
        """
        Action can be constructed from XML
        
        :param ghidra.xml.XmlPullParser parser: XML pull parser to restore action from XML
        """


class PatternPairSet(java.lang.Object):
    """
    A set of "pre" DittedBitSequences and a set of "post" Patterns are paired to form a larger pattern.
    To match, a sequence from the "pre" sequence set must first match, then one of the "post" patterns
    is matched relative to the matching "pre" pattern.  This class is really a storage object for the
    patterns and provides a mechanism to read the pre/post patterns from an XML file.
     
    
    The larger pattern has the idea of bits of check, which means the number of bits that are fixed to
    a value when matching (not don't care).  There is a pre pattern bits of check and post pattern bits
    of check.  The bits of check are used to statistically gauge the accuracy of the pattern.
     
    
    An example of the XML format follows:
    ``<patternpairs totalbits="32" postbits="16">  <prepatterns>    <data>0xe12fff1.                  </data>    <data>0xe12fff1e 0x46c0           </data>    <data>0xe12fff1e 0xe1a00000       </data>  </prepatterns>  <postpatterns>    <data> 0xe24dd...                              11101001 00101101 .1...... ....0000  </data>    <data> 11101001 00101101 .1...... ....0000     0xe24dd...                           </data>    <data> 11101001 00101101 .1...... ....0000     0x........ 0xe24dd...                </data>    <align mark="0" bits="3"/>    <setcontext name="TMode" value="0"/>    <funcstart/>  </postpatterns></patternpairs>``
     
      
    Note: The post Patterns can also have a set of rules that must be satisfied along with one of the
    Pattern DittedBitSequence matches.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        """
        Construct an empty PatternPairSet.  Use XML to initialize the pattern sets.
        """

    def createFinalPatterns(self, finalpats: java.util.ArrayList[Pattern]) -> None:
        ...

    def extractPostPatterns(self, postpats: java.util.ArrayList[Pattern]) -> None:
        """
        Add this PatternPairSets post patterns to an existing arraylist of patterns.
        
        :param java.util.ArrayList[Pattern] postpats: array to add this PatternPairSets post patterns into
        """

    def getPostBitsOfCheck(self) -> int:
        """
        Get the required number of fixed bits after the prepattern
        
        :return: number of post bits
        :rtype: int
        """

    def getPostPatterns(self) -> java.util.ArrayList[Pattern]:
        """
        Get the "post" parts of the patterns
        
        :return: post patterns
        :rtype: java.util.ArrayList[Pattern]
        """

    def getPreSequences(self) -> java.util.ArrayList[DittedBitSequence]:
        """
        Get the "pre" parts of the patterns
        
        :return: pre sequences
        :rtype: java.util.ArrayList[DittedBitSequence]
        """

    def getTotalBitsOfCheck(self) -> int:
        """
        Get the required number of fixed bits in the whole pattern
        
        :return: number of total fixed bits
        :rtype: int
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory) -> None:
        """
        Restore PatternPairSet from XML pull parser
        
        :param ghidra.xml.XmlPullParser parser: XML pull parser
        :param PatternFactory pfactory: pattern factory user to construct patterns
        :raises IOException: if pull parsing fails
        """

    @property
    def postPatterns(self) -> java.util.ArrayList[Pattern]:
        ...

    @property
    def preSequences(self) -> java.util.ArrayList[DittedBitSequence]:
        ...

    @property
    def postBitsOfCheck(self) -> jpype.JInt:
        ...

    @property
    def totalBitsOfCheck(self) -> jpype.JInt:
        ...


class MemoryBytePatternSearcher(java.lang.Object):
    """
    Multi pattern/mask/action memory searcher. This is the legacy memory searcher that specifically
    uses :obj:`Pattern` objects which relies on patterns having actions that get invoked as the
    pattern is found in memory. If you want a simpler, more generic way to search for bulk patterns
    in memory, you can use the :obj:`ProgramMemorySearcher`, . If you want an even more generic
    searcher that isn't restricted to just searching program memory, you can directly use a
    :obj:`BulkPatternSearcher`.
     
    
    In this class, patterns can be given at construction time or added one at a time. Optionally,
    this class can be called with a pre-built BulkPatternSearcher, which is a bit awkward since
    it is not compatible with adding patterns later. In that case, a new BulkPatternSearcher will be 
    created with only the patterns that were added after construction.
     
    
    Once patterns have been added, simply call the search or searchAll methods to perform a search.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str], patternList: java.util.List[Pattern]) -> None:
        """
        Create with pre-created patternList
        
        :param java.lang.String or str searchName: name of search
        :param java.util.List[Pattern] patternList: - list of patterns(bytes/mask/action)
        """

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str], searcher: BulkPatternSearcher[Pattern]) -> None:
        """
        Create with an initialized BulkPatternSearcher
        
        :param java.lang.String or str searchName: name of search
        :param BulkPatternSearcher[Pattern] searcher: search state pre-initialized
        """

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str]) -> None:
        """
        Create with no patternList, must add patterns before searching
        
        :param java.lang.String or str searchName: name of search
        """

    def addPattern(self, pattern: Pattern) -> None:
        """
        Add a search pattern
        
        :param Pattern pattern: - pattern(bytes/mask/action)
        """

    def postMatchApply(self, actions: jpype.JArray[MatchAction], address: ghidra.program.model.address.Address) -> None:
        """
        Called just after any match rules are applied.
        Can be used for cross post rule matching state application and cleanup.
        
        :param jpype.JArray[MatchAction] actions: the actions from the pattern that matched
        :param ghidra.program.model.address.Address address: the address of match
        """

    def preMatchApply(self, actions: jpype.JArray[MatchAction], address: ghidra.program.model.address.Address) -> None:
        """
        Called just before any match rules are applied.
        
        :param jpype.JArray[MatchAction] actions: the actions from the pattern that matched
        :param ghidra.program.model.address.Address address: address of match
        """

    def search(self, program: ghidra.program.model.listing.Program, searchSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Search initialized memory blocks for all patterns(bytes/mask/action).
        Call associated action for each pattern matched.
        
        :param ghidra.program.model.listing.Program program: to be searched
        :param ghidra.program.model.address.AddressSetView searchSet: set of bytes to restrict search, if null or empty then search all memory blocks
        :param ghidra.util.task.TaskMonitor monitor: allow canceling and reporting of progress
        :raises CancelledException: if canceled
        """

    def searchAll(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Search all initialized memory blocks and associated actions on matches
        
        :param ghidra.program.model.listing.Program program: to be searched
        :param ghidra.util.task.TaskMonitor monitor: allow canceling and reporting of progress
        :raises CancelledException: if canceled
        """

    def setSearchExecutableOnly(self, doExecutableBlocksOnly: typing.Union[jpype.JBoolean, bool]) -> None:
        ...


class ByteSequence(java.lang.Object):
    """
    An interface for accessing bytes from a byte source.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getByte(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the byte at the given index. The index must between 0 and the extended length.
        
        :param jpype.JInt or int index: the index in the byte sequence to retrieve a byte value
        :return: the byte at the given index
        :rtype: int
        """

    def getBytes(self, start: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Returns a byte array containing the bytes from the given range.
        
        :param jpype.JInt or int start: the start index of the range to get bytes
        :param jpype.JInt or int length: the number of bytes to get
        :return: a byte array containing the bytes from the given range
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLength(self) -> int:
        """
        Returns the length of available bytes.
        
        :return: the length of the sequence of bytes
        :rtype: int
        """

    def hasAvailableBytes(self, index: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> bool:
        """
        A convenience method for checking if this sequence can provide a range of bytes from some
        offset.
        
        :param jpype.JInt or int index: the index of the start of the range to check for available bytes
        :param jpype.JInt or int length: the length of the range to check for available bytes
        :return: true if bytes are available for the given range
        :rtype: bool
        """

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class ProgramMemorySearcher(java.lang.Object, typing.Generic[T]):
    """
    Class for efficiently searching for one or more patterns in memory. Patterns used by this 
    class can be any class that implements :obj:`BytePattern`, so clients are free to create
    their own custom pattern classes.
     
    
    Note: this searcher searches each memory block individually. It intentionally does not find
    patterns that span memory blocks (even if the memory blocks are adjacent). If you want patterns
    to span memory blocks, you can use the :obj:`MemorySearcher` class, which is not block
    oriented.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, patterns: java.util.List[T]) -> None:
        """
        Constructor
        
        :param java.lang.String or str name: the name of the searcher. (Used by the task monitor messages)
        :param ghidra.program.model.listing.Program program: The program whose memory is to be searched
        :param java.util.List[T] patterns: the list of pattern objects to search for
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, patternSearcher: BulkPatternSearcher[T]) -> None:
        """
        Constructor
        
        :param java.lang.String or str name: the name of the searcher. (Used by the task monitor messages)
        :param ghidra.program.model.listing.Program program: The program whose memory is to be searched
        :param BulkPatternSearcher[T] patternSearcher: the pre-constructed pattern searcher which is state-less and be
        reused, saving the time of building the state machine for the patterns.
        """

    def search(self, addresses: ghidra.program.model.address.AddressSetView, consumer: java.util.function.Consumer[AddressMatch[T]], monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Searches the given address set within initialized memory for the patterns given to this
        searcher.
        
        :param ghidra.program.model.address.AddressSetView addresses: The address within the program to search. This address set will be further
        restricted to initialized program memory
        :param java.util.function.Consumer[AddressMatch[T]] consumer: the consumer to be called back when a match is found
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for reporting progress and allowing for cancellation
        :raises CancelledException: thrown if the search is cancelled via the task monitor
        """

    def searchAll(self, consumer: java.util.function.Consumer[AddressMatch[T]], monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Searches all initialized memory in the program for the patterns given to this searcher.
        
        :param java.util.function.Consumer[AddressMatch[T]] consumer: the consumer to be called back when a match is found
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for reporting progress and allowing for cancellation
        :raises CancelledException: thrown if the search is cancelled via the task monitor
        """


class DummyMatchAction(MatchAction):
    """
    Dummy action attached to a match sequence.  Action is not restored from XML
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class DittedBitSequence(BytePattern):
    """
    A pattern of bits/mask to match to a stream of bytes.  The bits/mask can be of any length.
    The sequence can be initialized by:
     
        a string
        an array of bytes (no mask)
        an array of bytes and for mask
        
    The dits represent bits(binary) or nibbles(hex) that are don't care, for example:
        0x..d.4de2 ....0000 .1...... 00101101 11101001
    where 0x starts a hex number and '.' is a don't care nibble (hex) or bit (binary)
    """

    class_: typing.ClassVar[java.lang.Class]
    popcount: typing.ClassVar[jpype.JArray[jpype.JInt]]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, dittedBitData: typing.Union[java.lang.String, str]) -> None:
        """
        Constructor from a ditted-bit-sequence string where white space is ignored (e.g., "10..11.0");
        
        :param java.lang.String or str dittedBitData: ditted sequence specified as a string
        :raises IllegalArgumentException: if invalid dittedBitData specified
        """

    @typing.overload
    def __init__(self, dittedBitData: typing.Union[java.lang.String, str], hex: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Constructor from a ditted-bit string where white space is ignored.  If there are no dits,
        ``hex`` is true, and ``hex`` does not begin with {code 0x}, ``0x`` will be
        prepended to the string before constructing the :obj:`DittedBitSequence`.
        
        :param java.lang.String or str dittedBitData: string of bits and dits or hex numbers and dits (e.g., 0.1..0, 0xAB..)
        :param jpype.JBoolean or bool hex: true to force hex on the sequence
        """

    @typing.overload
    def __init__(self, op2: DittedBitSequence) -> None:
        """
        Copy contructor
        
        :param DittedBitSequence op2: is bit sequence being copied
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]) -> None:
        """
        Construct a sequence of bytes to search for. No bits are masked off.
        
        :param jpype.JArray[jpype.JByte] bytes: byte values that must match
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte], mask: jpype.JArray[jpype.JByte]) -> None:
        """
        Construct a bit pattern to search for consisting of
        0 bits, 1 bits, and don't care bits
        
        :param jpype.JArray[jpype.JByte] bytes: is an array of bytes indicating the 0 and 1 bits that are cared about
        :param jpype.JArray[jpype.JByte] mask: is an array of bytes masking off the bits that should be cared about, a 0 indicates a "don't care"
        """

    @typing.overload
    def __init__(self, s1: DittedBitSequence, s2: DittedBitSequence) -> None:
        ...

    def concatenate(self, toConat: DittedBitSequence) -> DittedBitSequence:
        """
        Concatenates a sequence to the end of another sequence and
        returns a new sequence.
        
        :param DittedBitSequence toConat: sequence to concatenate to this sequence
        :return: a new sequence that is the concat of this and toConcat
        :rtype: DittedBitSequence
        """

    def getHexString(self) -> str:
        """
        get a ditted hex string representing this sequence
        
        :return: ditted hex string
        :rtype: str
        """

    def getIndex(self) -> int:
        """
        Get the index or identifying id attached to this pattern
        
        :return: index or unique id attached to this sequence
        :rtype: int
        """

    def getMaskBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: mask bytes which correspond to value bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getNumFixedBits(self) -> int:
        """
        Get number of bits that must be 0/1
        
        :return: number of bits that are not don't care (ditted)
        :rtype: int
        """

    def getNumInitialFixedBits(self, marked: typing.Union[jpype.JInt, int]) -> int:
        """
        Get the number of bits that are fixed, not ditted (don't care)
        
        :param jpype.JInt or int marked: number of bytes in the pattern to check
        :return: number of initial fixed bits
        :rtype: int
        """

    def getNumUncertainBits(self) -> int:
        """
        Get number of bits that are ditted (don't care)
        
        :return: number of ditted bits (don't care)
        :rtype: int
        """

    def getSize(self) -> int:
        """
        get the size of this sequence in bytes
        
        :return: size in bytes
        :rtype: int
        """

    def getValueBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        
        
        :return: value bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def isMatch(self, pos: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check for a match of a value at a certain offset in the pattern.
        An outside matcher will keep track of the match position within this
        ditted bit sequence.  Then call this method to match.
        
        :param jpype.JInt or int pos: position in the pattern to match
        :param jpype.JInt or int val: a byte to be match at the given byte offset in the pattern
        :return: true if the byte matches the sequence mask/value
        :rtype: bool
        """

    def setIndex(self, index: typing.Union[jpype.JInt, int]) -> None:
        """
        Set a an index in a larger sequence, or identifing id on this pattern
        
        :param jpype.JInt or int index: - index in match sequence, or unique id
        """

    def writeBits(self, buf: java.lang.StringBuffer) -> None:
        ...

    @property
    def numFixedBits(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def numUncertainBits(self) -> jpype.JInt:
        ...

    @property
    def hexString(self) -> java.lang.String:
        ...

    @property
    def numInitialFixedBits(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @index.setter
    def index(self, value: jpype.JInt):
        ...

    @property
    def maskBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def valueBytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class BulkPatternSearcher(java.lang.Object, typing.Generic[T]):
    """
    State machine for searching for a list of :obj:`BytePattern`s simultaneously in a byte
    sequence. Once this BulkPatternMatcher is constructed from a list of patterns, it can
    be used any number of times to search byte sequences. There are an assortment of search methods
    to meet various client needs.
     
    
    The search methods break down into the following categories:
    1) Searching a byte buffer with the result being an iterator over matches.
    2) Searching a byte buffer with the results being added to a given list.
    3) Searching an input stream with the results being added to a given list.
    4) Searching an :obj:`ExtendedByteSequence` with the results being added to a given list
     
    
    In addition, the byte buffer methods all have a variation that takes an additional parameter
    stating how many of the bytes in the buffer are searchable. (The buffer is not full).
    Also, the input stream method has a variation where the max bytes to read from the stream
    is given.
    """

    @typing.type_check_only
    class ByteArrayMatchIterator(java.util.Iterator[Match[T]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SearchState(java.lang.Object, typing.Generic[T]):
        """
        A single state in the state machine that represents one or more active patterns that have
        matched the sequence of bytes so far.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RestrictedStream(java.io.InputStream):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, patterns: java.util.List[T]) -> None:
        """
        Constructor
        
        :param java.util.List[T] patterns: the list of patterns that can be search simultaneously using an internal
        finite state machine
        """

    def getMaxPatternLength(self) -> int:
        """
        :return: the length of the longest pattern
        :rtype: int
        """

    def getUniqueStateCount(self) -> int:
        """
        :return: the number of unique states generated. Used for testing.
        :rtype: int
        """

    def matches(self, input: jpype.JArray[jpype.JByte], numBytes: typing.Union[jpype.JInt, int], results: java.util.List[Match[T]]) -> None:
        """
        Searches for the patterns in the given byte array that start at the first byte in the array.
        Resulting matches are added to the given results list.
        
        :param jpype.JArray[jpype.JByte] input: the byte array to search for patterns
        :param jpype.JInt or int numBytes: the number of bytes to use from the given byte array. (The byte array might
        not be fully populated with valid data.)
        :param java.util.List[Match[T]] results: the list of match results to populate
        """

    @typing.overload
    def search(self, input: jpype.JArray[jpype.JByte]) -> java.util.Iterator[Match[T]]:
        """
        Search the given byte buffer for any of this searcher's patterns.
        
        :param jpype.JArray[jpype.JByte] input: the byte buffer to search
        :return: An iterator that will return pattern matches one at a time.
        :rtype: java.util.Iterator[Match[T]]
        """

    @typing.overload
    def search(self, input: jpype.JArray[jpype.JByte], length: typing.Union[jpype.JInt, int]) -> java.util.Iterator[Match[T]]:
        """
        Search the given byte buffer up the specified length for any of this searcher's patterns.
        
        :param jpype.JArray[jpype.JByte] input: the byte buffer to search
        :param jpype.JInt or int length: the actual number of the bytes in the buffer to search.
        :return: An iterator that will return pattern matches one at a time.
        :rtype: java.util.Iterator[Match[T]]
        """

    @typing.overload
    def search(self, input: jpype.JArray[jpype.JByte], results: java.util.List[Match[T]]) -> None:
        """
        Searches for the patterns in the given byte array, adding match results to the given list
        of results.
        
        :param jpype.JArray[jpype.JByte] input: the byte array to search for patterns
        :param java.util.List[Match[T]] results: the list of match results to populate
        """

    @typing.overload
    def search(self, input: jpype.JArray[jpype.JByte], numBytes: typing.Union[jpype.JInt, int], results: java.util.List[Match[T]]) -> None:
        """
        Searches for the patterns in the given byte array, adding match results to the given list
        of results.
        
        :param jpype.JArray[jpype.JByte] input: the byte array to search for patterns
        :param jpype.JInt or int numBytes: the number of valid bytes in the input buffer to search
        :param java.util.List[Match[T]] results: the list of match results to populate
        """

    @typing.overload
    def search(self, bytes: ExtendedByteSequence, results: java.util.List[Match[T]]) -> None:
        """
        Searches for the patterns in the given :obj:`ExtendedByteSequence`, adding match results
        to the given list of results.
        
        :param ExtendedByteSequence bytes: the extended byte sequence to search
        :param java.util.List[Match[T]] results: the list of match results to populate
        Users of this method may have split a larger byte sequence into chunks and the final match
        position needs to be the sum of the chunk offset plus the offset within this chunk.
        """

    @typing.overload
    def search(self, is_: java.io.InputStream, results: java.util.List[Match[T]], monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Searches for the patterns in the given input stream, adding match results to the given list
        of results.
        
        :param java.io.InputStream is: the input stream of bytes to scan for patterns
        :param java.util.List[Match[T]] results: the list of match results to populate
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if an exception occurs reading the input stream
        """

    @typing.overload
    def search(self, inputStream: java.io.InputStream, maxRead: typing.Union[jpype.JLong, int], results: java.util.List[Match[T]], monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Searches for the patterns in the given input stream, adding match results to the given
        list of results.
        
        :param java.io.InputStream inputStream: the input stream of bytes to scan for patterns
        :param jpype.JLong or int maxRead: the maximum offset into the input stream where a match can start. Additional
        bytes can be read from the stream to complete patterns
        :param java.util.List[Match[T]] results: the list of match results to populate
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises IOException: if an exception occurs reading the input stream
        """

    def setBufferSize(self, bufferSize: typing.Union[jpype.JInt, int]) -> None:
        """
        Sets the buffer size used when using one of the search methods that takes an input stream.
        Mostly used for testing.
        
        :param jpype.JInt or int bufferSize: the size of the buffers to use when searching input streams.
        """

    @property
    def uniqueStateCount(self) -> jpype.JInt:
        ...

    @property
    def maxPatternLength(self) -> jpype.JInt:
        ...


class GenericMatchAction(DummyMatchAction, typing.Generic[T]):
    """
    Template for generic match action attached to a match sequence.
    Used to store an associated value to the matching sequence.
    The associated value can be retrieved when the sequence is matched.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, matchValue: T) -> None:
        """
        Construct a match action used when a match occurs for some GenericByteSequece
        
        :param T matchValue: specialized object used when match occurs
        """

    def getMatchValue(self) -> T:
        """
        
        
        :return: the specialized object associated with this match action
        :rtype: T
        """

    @property
    def matchValue(self) -> T:
        ...


class InputStreamBufferByteSequence(ByteSequence):
    """
    ByteSequence that buffers an :obj:`InputStream`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, bufferSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def load(self, is_: java.io.InputStream, amount: typing.Union[jpype.JInt, int]) -> None:
        """
        Loads data into this byte sequence from the given input stream
        
        :param java.io.InputStream is: the input stream to read bytes from
        :param jpype.JInt or int amount: the number of bytes to read from the stream
        :raises IOException: if an error occurs reading from the stream
        """


class AlignRule(PostRule):
    """
    ByteSearch post search rule when a pattern is found. Used when a pattern must have a certain
    alignment at an offset from the location the pattern matches. 
     
    
    The pattern can be constructed or restored from XML of the form,
    where alignOffset=mark, alignmask=bits
    ``  <align mark="0" bits="1"/>``
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, alignOffset: typing.Union[jpype.JInt, int], alignmask: typing.Union[jpype.JInt, int]) -> None:
        """
        ByteSearch post search rule when a pattern is found. Used when a pattern must have a certain
        alignment at an offset from the location the pattern matches. The alignment is
        specified by the alignmask bits that must be zero.
         
        Normally alignOffset is 0, since most patterns will match at the address that must be aligned
        To align a match, use the following
        
        align to  2 = alignmask 0x1 - lower bit must be zero
        align to  4 = alignmask 0x3 - lower two bits must be zero
        align to  8 = alignmask 0x7 - lower three bits must be zero
        align to 16 = alignmask 0xF - lower four bits must be zero
        ....
        Other strange alignments could be specified, but most likely the above suffice.
        
        :param jpype.JInt or int alignOffset: - bytes offset from pattern to check for alignment
        :param jpype.JInt or int alignmask: - the mask where a 1 bit must be zero
        """

    def getAlignMask(self) -> int:
        ...

    @property
    def alignMask(self) -> jpype.JInt:
        ...


class PostRule(java.lang.Object):
    """
    Inteface for post match rules that are checked after a match is idenfied
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self, pat: Pattern, matchoffset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Apply a post rule given the matching pattern and offset into the byte stream.
        
        :param Pattern pat: pattern that matched
        :param jpype.JLong or int matchoffset: offset of the match
        :return: true if the PostRule is satisfied
        :rtype: bool
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser) -> None:
        """
        Can restore state of instance PostRule from XML
        
        :param ghidra.xml.XmlPullParser parser: XML pull parser
        """


class Match(java.lang.Object, typing.Generic[T]):
    """
    Represents a match of a pattern at a given offset in a byte sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pattern: T, start: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int]) -> None:
        """
        Construct a Match of a BytePattern that matched at a position in the input byte sequence.
        
        :param T pattern: the byte pattern that matched
        :param jpype.JLong or int start: the location in the input byte sequence where the pattern match begins
        :param jpype.JInt or int length: the length of the matching sequence
        """

    def getLength(self) -> int:
        """
        
        
        :return: length in bytes of the matched pattern
        :rtype: int
        """

    def getPattern(self) -> T:
        """
        
        
        :return: the sequence that was matched
        :rtype: T
        """

    def getStart(self) -> int:
        """
        
        
        :return: offset of match in sequence of bytes
        :rtype: int
        """

    @property
    def start(self) -> jpype.JLong:
        ...

    @property
    def pattern(self) -> T:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...


class GenericByteSequencePattern(Pattern, typing.Generic[T]):
    """
    Templated simple DittedBitSequence Pattern for a byte/mask pattern and associated action.
    The DittedBitSequence is provided by value and mask in byte arrays.
     
    This class is normally used to find some number of SequencePatterns within a seqence of bytes.
    When the byte/mask pattern is matched, the GenericMatchAction will be "applied".
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bytesSequence: jpype.JArray[jpype.JByte], action: GenericMatchAction[T]) -> None:
        """
        Construct a sequence of bytes with no mask, and associated action
        to be called if this pattern matches.
        
        :param jpype.JArray[jpype.JByte] bytesSequence: sequence of bytes to match
        :param GenericMatchAction[T] action: action to apply if the match succeeds
        """

    @typing.overload
    def __init__(self, bytesSequence: jpype.JArray[jpype.JByte], mask: jpype.JArray[jpype.JByte], action: GenericMatchAction[T]) -> None:
        """
        Construct a sequence of bytes with a mask, and associated action
        to be called if this pattern matches.
        
        :param jpype.JArray[jpype.JByte] bytesSequence: sequence of bytes to match
        :param jpype.JArray[jpype.JByte] mask: mask, bits that are 1 must match the byteSequence bits
        :param GenericMatchAction[T] action: to apply if the match succeeds
        """


class AddressMatch(Match[T], typing.Generic[T]):
    """
    Represents a match of a pattern at a given address in program memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pattern: T, offset: typing.Union[jpype.JLong, int], length: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address) -> None:
        """
        Constructor
        
        :param T pattern: the byte pattern that matched
        :param jpype.JLong or int offset: offset within a searched buffer
        :param jpype.JInt or int length: the length of the matching sequence
        :param ghidra.program.model.address.Address address: the address in the program where the match occurred
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the address where this match occurred
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class AddressableByteSequence(ByteSequence):
    """
    This class provides a :obj:`ByteSequence` view into an :obj:`AddressableByteSource`. By 
    specifying an address and length, this class provides a view into the byte source
    as a indexable sequence of bytes. It is mutable and can be reused by setting a new
    address range for this sequence. This was to avoid constantly allocating large byte arrays.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, byteSource: ghidra.features.base.memsearch.bytesource.AddressableByteSource, capacity: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructor
        
        :param ghidra.features.base.memsearch.bytesource.AddressableByteSource byteSource: the source of the underlying bytes that is a buffer into
        :param jpype.JInt or int capacity: the maximum size range that this object will buffer
        """

    def clear(self) -> None:
        """
        Sets this view to an empty byte sequence
        """

    def getAddress(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address of the byte represented by the given index into this buffer.
        
        :param jpype.JInt or int index: the index into the buffer to get its associated address
        :return: the Address for the given index
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def setRange(self, range: ghidra.program.model.address.AddressRange) -> None:
        """
        Sets the range of bytes that this object will buffer. This immediately will read the bytes
        from the byte source into it's internal byte array buffer.
        
        :param ghidra.program.model.address.AddressRange range: the range of bytes to buffer
        """

    @typing.overload
    def setRange(self, start: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> None:
        """
        Sets the range of bytes that this object will buffer. This immediately will read the bytes
        from the byte source into it's internal byte array buffer.
        
        :param ghidra.program.model.address.Address start: the address to start reading bytes
        :param jpype.JInt or int length: the number of bytes to read
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class Pattern(DittedBitSequence):
    """
    Pattern is an association of a DittedBitSequence to match,
    a set of post rules after a match is found that must be satisfied,
    and a set of actions to be taken if the pattern matches.
     
    These patterns can be restored from an XML file.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        """
        Construct an empty pattern.  Use XML to initialize
        """

    @typing.overload
    def __init__(self, seq: DittedBitSequence, offset: typing.Union[jpype.JInt, int], postArray: jpype.JArray[PostRule], matchArray: jpype.JArray[MatchAction]) -> None:
        """
        Construct the pattern based on a DittedByteSequence a match offset, post matching rules,
        and a set of actions to take when the match occurs.
        
        :param DittedBitSequence seq: DittedByteSequence
        :param jpype.JInt or int offset: offset from the actual match location to report a match
        :param jpype.JArray[PostRule] postArray: post set of rules to check for the match
        :param jpype.JArray[MatchAction] matchArray: MatchActions to apply when a match occurs
        """

    def checkPostRules(self, offset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check that the possible post rules are satisfied
        
        :param jpype.JLong or int offset: offset in stream to check postrules.
        :return: true if post rules are satisfied
        :rtype: bool
        """

    def getMarkOffset(self) -> int:
        ...

    def getMatchActions(self) -> jpype.JArray[MatchAction]:
        ...

    def getPostRules(self) -> jpype.JArray[PostRule]:
        ...

    @staticmethod
    def readPatterns(file: generic.jar.ResourceFile, patlist: java.util.ArrayList[Pattern], pfactory: PatternFactory) -> None:
        """
        Read patterns from specified file
        
        :param generic.jar.ResourceFile file: pattern file
        :param java.util.ArrayList[Pattern] patlist: list for patterns to be added to
        :param PatternFactory pfactory: optional factory for use in parsing PostRule and MatchAction elements.  
        If null such elements may not be present.
        :raises SAXException: 
        :raises IOException:
        """

    @staticmethod
    def readPostPatterns(file: jpype.protocol.SupportsPath, patternList: java.util.ArrayList[Pattern], pfactory: PatternFactory) -> None:
        """
        Read just the post patterns from the ``<patternpair>`` tags
        
        :param jpype.protocol.SupportsPath file: is the file to read from
        :param java.util.ArrayList[Pattern] patternList: collects the resulting Pattern objects
        :param PatternFactory pfactory: is the factory for constructing postrules and matchactions
        :raises IOException: 
        :raises SAXException:
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory) -> None:
        ...

    @staticmethod
    def restoreXmlAttributes(postrulelist: java.util.ArrayList[PostRule], actionlist: java.util.ArrayList[MatchAction], parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory) -> None:
        """
        Restore the PostRule and the MatchAction tags
        
        :param ghidra.xml.XmlPullParser parser: is the parser at the start of tags
        :param PatternFactory pfactory: is the factory for the PostRule and MatchAction objects
        :raises IOException:
        """

    def setMatchActions(self, actions: jpype.JArray[MatchAction]) -> None:
        ...

    @property
    def markOffset(self) -> jpype.JInt:
        ...

    @property
    def matchActions(self) -> jpype.JArray[MatchAction]:
        ...

    @matchActions.setter
    def matchActions(self, value: jpype.JArray[MatchAction]):
        ...

    @property
    def postRules(self) -> jpype.JArray[PostRule]:
        ...


class ExtendedByteSequence(ByteSequence):
    """
    A class for accessing a contiguous sequence of bytes from some underlying byte source to 
    be used for searching for a byte pattern within the byte source. This sequence of bytes 
    consists of three parts; the primary sequence, a pre sequence, and an extended sequence. 
    Search matches must begin in the primary sequence, but may extend into the extended sequence. The
    pre-sequence is used for searching that supports look-behind such as some regular expressions. 
     
    
    Searching large ranges of memory can be partitioned into searching smaller chunks. But
    to handle search sequences that span chunks, three chunks are presented at a time. Look-behind
    patterns can use the pre-chunk to see the bytes before the main chunk. Actual matches must start
    in the main chunk, but can extend into the extended chunk. On the next iteration of the search
    loop, the main chunk becomes the pre-chunk and the extended chunk becomes the main chunk and a 
    new post-chunk is read from the input source.
    """

    @typing.type_check_only
    class EmptyByteSequence(ByteSequence):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, main: ByteSequence, pre: ByteSequence, post: ByteSequence, overlap: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs an extended byte sequence from two :obj:`ByteSequence`s.
        
        :param ByteSequence main: the byte sequence where search matches may start
        :param ByteSequence pre: the byte sequence bytes before the main byte sequence used by searchers
        that support "look behind"
        :param ByteSequence post: the byte sequence where search matches may extend into
        :param jpype.JInt or int overlap: specifies how much of the extended byte sequence to allow search
        matches to extend into. (The extended buffer will be the primary buffer next time, so
        it is a full size buffer, but we only need to use a portion of it to support overlap.
        """

    def getExtendedLength(self) -> int:
        """
        Returns the overall length of sequence of available bytes. This will be the length of
        the primary sequence as returned by :meth:`getLength() <.getLength>` plus the length of the available
        extended bytes, if any.
        
        :return: the
        :rtype: int
        """

    def getPreLength(self) -> int:
        """
        :return: the length of the pre sequence that is available
        :rtype: int
        """

    @property
    def preLength(self) -> jpype.JInt:
        ...

    @property
    def extendedLength(self) -> jpype.JInt:
        ...


class BytePattern(java.lang.Object):
    """
    Interface for fixed length patterns that can be combined into a single state machine that can be 
    simultaneously searched for in a byte sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPreSequenceLength(self) -> int:
        """
        Returns the number of bytes in this pattern that represent a pre-sequence that must match
        before the official start of the matching pattern. For example if looking for a pattern of
        "abcd", but only if it follows "xyz", then the pattern would be "xyzabcd", with a pre
        sequence length of 3. So when this pattern matches, we want the "match to be at the position
        where the "a" is and not the "x". This is know as "look behind" when using regular
        expressions.
        
        :return: the number of bytes in the pattern that represent a required pre sequence before the
        actual pattern we want to find the position of
        :rtype: int
        """

    def getSize(self) -> int:
        """
        :return: the size of this pattern.
        :rtype: int
        """

    def isMatch(self, patternOffset: typing.Union[jpype.JInt, int], byteValue: typing.Union[jpype.JInt, int]) -> bool:
        """
        Checks if this pattern matches a byte value at a specific offset into the pattern.
        
        :param jpype.JInt or int patternOffset: the position in the pattern to check if it matches the given byte value
        :param jpype.JInt or int byteValue: the byte value to check if it matches the pattern at the given offset. This
        value is passed as an int so that the byte can be treated as unsigned.
        :return: true if this pattern matches the given byte value at the given pattern offset.
        :rtype: bool
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def preSequenceLength(self) -> jpype.JInt:
        ...



__all__ = ["PatternFactory", "MatchAction", "PatternPairSet", "MemoryBytePatternSearcher", "ByteSequence", "ProgramMemorySearcher", "DummyMatchAction", "DittedBitSequence", "BulkPatternSearcher", "GenericMatchAction", "InputStreamBufferByteSequence", "AlignRule", "PostRule", "Match", "GenericByteSequencePattern", "AddressMatch", "AddressableByteSequence", "Pattern", "ExtendedByteSequence", "BytePattern"]
