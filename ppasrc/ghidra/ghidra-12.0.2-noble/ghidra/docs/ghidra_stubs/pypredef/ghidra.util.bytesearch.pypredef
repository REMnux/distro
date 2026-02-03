from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


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

    def apply(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, match: Match):
        """
        Apply the match action to the program at the address.
        
        :param ghidra.program.model.listing.Program program: program in which the match occurred
        :param ghidra.program.model.address.Address addr: where the match occured
        :param Match match: information about the match that occurred
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Action can be constructed from XML
        
        :param ghidra.xml.XmlPullParser parser: XML pull parser to restore action from XML
        """


class SequenceSearchState(java.lang.Comparable[SequenceSearchState]):
    """
    SeqenceSearchState holds the state of a search for a DittedBitSequence within a byte
    sequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: SequenceSearchState):
        """
        Construct a sub sequence state with a parent sequence
        
        :param SequenceSearchState parent: parent SequenceSearchState
        """

    def addSequence(self, pat: DittedBitSequence, pos: typing.Union[jpype.JInt, int]):
        """
        Add a pattern to this search sequence.  The last pattern added is the successful
        match pattern.
        
        :param DittedBitSequence pat: pattern to add
        :param jpype.JInt or int pos: position within the current set of patterns to add this pattern
        """

    @typing.overload
    def apply(self, buffer: jpype.JArray[jpype.JByte], match: java.util.ArrayList[Match]):
        """
        Search for patterns in a byte array.  All matches are returned.
        
        :param jpype.JArray[jpype.JByte] buffer: is the array of bytes to search
        :param java.util.ArrayList[Match] match: is populated with a Match object for each pattern and position that matches
        """

    @typing.overload
    def apply(self, in_: java.io.InputStream, match: java.util.ArrayList[Match], monitor: ghidra.util.task.TaskMonitor):
        """
        Search for pattern in the stream -in-.
        
        :param java.io.InputStream in: - The stream to scan for matches
        :param java.util.ArrayList[Match] match: - Any matches are appended as Match records to this ArrayList
        :param ghidra.util.task.TaskMonitor monitor: - if non-null, check for user cancel, and maintain progress info
        :raises IOException:
        """

    @typing.overload
    def apply(self, in_: java.io.InputStream, maxBytes: typing.Union[jpype.JLong, int], match: java.util.ArrayList[Match], monitor: ghidra.util.task.TaskMonitor):
        """
        Search for pattern in the stream -in-.
        
        :param java.io.InputStream in: - The stream to scan for matches
        :param jpype.JLong or int maxBytes: - The maximum number of bytes to scan forward in this stream
        :param java.util.ArrayList[Match] match: - Any matches are appended as Match records to this ArrayList
        :param ghidra.util.task.TaskMonitor monitor: - if non-null, check for user cancel, and maintain progress info
        :raises IOException:
        """

    @staticmethod
    def buildStateMachine(patterns: java.util.ArrayList[DittedBitSequence]) -> SequenceSearchState:
        """
        Build a search state machine from a list of DittedBitSequences
        
        :param java.util.ArrayList[DittedBitSequence] patterns: bit sequence patterns
        :return: search state the will match the given sequences
        :rtype: SequenceSearchState
        """

    def getMaxSequenceSize(self) -> int:
        """
        
        
        :return: maximum number of bytes that could be matched by this sequence
        :rtype: int
        """

    def sequenceMatch(self, bytearray: jpype.JArray[jpype.JByte], numbytes: typing.Union[jpype.JInt, int], match: java.util.ArrayList[Match]):
        """
        Try to match this Sequence to the byteArray, and add any matches to the match list
        
        :param jpype.JArray[jpype.JByte] bytearray: array of bytes to match
        :param jpype.JInt or int numbytes: retrict number of bytes to allow to match
        :param java.util.ArrayList[Match] match: list of matches, the result
        """

    def sortSequences(self):
        """
        Sort the sequences that have been added
        """

    @property
    def maxSequenceSize(self) -> jpype.JInt:
        ...


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

    def __init__(self):
        """
        Construct an empty PatternPairSet.  Use XML to initialize the pattern sets.
        """

    def createFinalPatterns(self, finalpats: java.util.ArrayList[Pattern]):
        ...

    def extractPostPatterns(self, postpats: java.util.ArrayList[Pattern]):
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

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory):
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
    Multi pattern/mask/action memory searcher
    Patterns must be supplied/added, or a pre-initialized searchState supplied
     
    Preload search patterns and actions, then call search method.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str], patternList: java.util.ArrayList[Pattern]):
        """
        Create with pre-created patternList
        
        :param java.lang.String or str searchName: name of search
        :param java.util.ArrayList[Pattern] patternList: - list of patterns(bytes/mask/action)
        """

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str], root: SequenceSearchState):
        """
        Create with an initialized SequenceSearchState
        
        :param java.lang.String or str searchName: name of search
        :param SequenceSearchState root: search state pre-initialized
        """

    @typing.overload
    def __init__(self, searchName: typing.Union[java.lang.String, str]):
        """
        Create with no patternList, must add patterns before searching
        
        :param java.lang.String or str searchName: name of search
        """

    def addPattern(self, pattern: Pattern):
        """
        Add a search pattern
        
        :param Pattern pattern: - pattern(bytes/mask/action)
        """

    def postMatchApply(self, matchactions: jpype.JArray[MatchAction], addr: ghidra.program.model.address.Address):
        """
        Called after any match rules are applied
        Can use for cross post rule matching state application and cleanup.
        
        :param jpype.JArray[MatchAction] matchactions: actions that matched
        :param ghidra.program.model.address.Address addr: adress of match
        """

    def preMatchApply(self, matchactions: jpype.JArray[MatchAction], addr: ghidra.program.model.address.Address):
        """
        Called before any match rules are applied
        
        :param jpype.JArray[MatchAction] matchactions: actions that matched
        :param ghidra.program.model.address.Address addr: address of match
        """

    def search(self, program: ghidra.program.model.listing.Program, searchSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Search initialized memory blocks for all patterns(bytes/mask/action).
        Call associated action for each pattern matched.
        
        :param ghidra.program.model.listing.Program program: to be searched
        :param ghidra.program.model.address.AddressSetView searchSet: set of bytes to restrict search, if null or empty then search all memory blocks
        :param ghidra.util.task.TaskMonitor monitor: allow canceling and reporting of progress
        :raises CancelledException: if canceled
        """

    def setSearchExecutableOnly(self, doExecutableBlocksOnly: typing.Union[jpype.JBoolean, bool]):
        ...


class DummyMatchAction(MatchAction):
    """
    Dummy action attached to a match sequence.  Action is not restored from XML
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DittedBitSequence(java.lang.Object):
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
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dittedBitData: typing.Union[java.lang.String, str]):
        """
        Constructor from a ditted-bit-sequence string where white space is ignored (e.g., "10..11.0");
        
        :param java.lang.String or str dittedBitData: ditted sequence specified as a string
        :raises IllegalArgumentException: if invalid dittedBitData specified
        """

    @typing.overload
    def __init__(self, dittedBitData: typing.Union[java.lang.String, str], hex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor from a ditted-bit string where white space is ignored.  If there are no dits,
        ``hex`` is true, and ``hex`` does not begin with {code 0x}, ``0x`` will be
        prepended to the string before constructing the :obj:`DittedBitSequence`.
        
        :param java.lang.String or str dittedBitData: string of bits and dits or hex numbers and dits (e.g., 0.1..0, 0xAB..)
        :param jpype.JBoolean or bool hex: true to force hex on the sequence
        """

    @typing.overload
    def __init__(self, op2: DittedBitSequence):
        """
        Copy contructor
        
        :param DittedBitSequence op2: is bit sequence being copied
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        """
        Construct a sequence of bytes to search for. No bits are masked off.
        
        :param jpype.JArray[jpype.JByte] bytes: byte values that must match
        """

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte], mask: jpype.JArray[jpype.JByte]):
        """
        Construct a bit pattern to search for consisting of
        0 bits, 1 bits, and don't care bits
        
        :param jpype.JArray[jpype.JByte] bytes: is an array of bytes indicating the 0 and 1 bits that are cared about
        :param jpype.JArray[jpype.JByte] mask: is an array of bytes masking off the bits that should be cared about, a 0 indicates a "don't care"
        """

    @typing.overload
    def __init__(self, s1: DittedBitSequence, s2: DittedBitSequence):
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

    def setIndex(self, index: typing.Union[jpype.JInt, int]):
        """
        Set a an index in a larger sequence, or identifing id on this pattern
        
        :param jpype.JInt or int index: - index in match sequence, or unique id
        """

    def writeBits(self, buf: java.lang.StringBuffer):
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


class GenericMatchAction(DummyMatchAction, typing.Generic[T]):
    """
    Template for generic match action attached to a match sequence.
    Used to store an associated value to the matching sequence.
    The associated value can be retrieved when the sequence is matched.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, matchValue: T):
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
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, alignOffset: typing.Union[jpype.JInt, int], alignmask: typing.Union[jpype.JInt, int]):
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

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Can restore state of instance PostRule from XML
        
        :param ghidra.xml.XmlPullParser parser: XML pull parser
        """


class Match(java.lang.Object):
    """
    Represents a match of a DittedBitSequence at a given offset in a byte sequence.
     
    There is a hidden assumption that the sequence is actually a Pattern
    that might have a ditted-bit-sequence, a set of match actions,
    and post match rules/checks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sequence: DittedBitSequence, offset: typing.Union[jpype.JLong, int]):
        """
        Construct a Match of a DittedBitSequence at an offset within a byte stream.
        Object normally used when a match occurs during a MemoryBytePatternSearch.
        
        :param DittedBitSequence sequence: that matched
        :param jpype.JLong or int offset: from the start of byte stream where the matched occured
        """

    def checkPostRules(self, streamoffset: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check that the possible post rules are satisfied
        
        :param jpype.JLong or int streamoffset: offset within from match location to check postrules.
        :return: true if post rules are satisfied
        :rtype: bool
        """

    def getHexString(self) -> str:
        """
        
        
        :return: ditted bit sequence as a string
        :rtype: str
        """

    def getMarkOffset(self) -> int:
        """
        
        
        :return: the offset of the match within a longer byte sequence
        :rtype: int
        """

    def getMatchActions(self) -> jpype.JArray[MatchAction]:
        """
        
        
        :return: actions associated with this match
        :rtype: jpype.JArray[MatchAction]
        """

    def getMatchStart(self) -> int:
        """
        
        
        :return: offset of match in sequence of bytes
        :rtype: int
        """

    def getNumPostBits(self) -> int:
        """
        If the sequence corresponds to a PatternPair, return the number of postbits
        
        :return: the number of post bits
        :rtype: int
        """

    def getSequence(self) -> DittedBitSequence:
        """
        
        
        :return: the sequence that was matched
        :rtype: DittedBitSequence
        """

    def getSequenceIndex(self) -> int:
        """
        
        
        :return: index of sequence in a possibly longer set of sequences
        :rtype: int
        """

    def getSequenceSize(self) -> int:
        """
        
        
        :return: size in bytes of sequence
        :rtype: int
        """

    @property
    def sequenceIndex(self) -> jpype.JInt:
        ...

    @property
    def markOffset(self) -> jpype.JLong:
        ...

    @property
    def sequence(self) -> DittedBitSequence:
        ...

    @property
    def matchActions(self) -> jpype.JArray[MatchAction]:
        ...

    @property
    def hexString(self) -> java.lang.String:
        ...

    @property
    def sequenceSize(self) -> jpype.JInt:
        ...

    @property
    def numPostBits(self) -> jpype.JInt:
        ...

    @property
    def matchStart(self) -> jpype.JLong:
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
    def __init__(self, bytesSequence: jpype.JArray[jpype.JByte], action: GenericMatchAction[T]):
        """
        Construct a sequence of bytes with no mask, and associated action
        to be called if this pattern matches.
        
        :param jpype.JArray[jpype.JByte] bytesSequence: sequence of bytes to match
        :param GenericMatchAction[T] action: action to apply if the match succeeds
        """

    @typing.overload
    def __init__(self, bytesSequence: jpype.JArray[jpype.JByte], mask: jpype.JArray[jpype.JByte], action: GenericMatchAction[T]):
        """
        Construct a sequence of bytes with a mask, and associated action
        to be called if this pattern matches.
        
        :param jpype.JArray[jpype.JByte] bytesSequence: sequence of bytes to match
        :param jpype.JArray[jpype.JByte] mask: mask, bits that are 1 must match the byteSequence bits
        :param GenericMatchAction[T] action: to apply if the match succeeds
        """


class Pattern(DittedBitSequence):
    """
    Pattern is an association of a DittedBitSequence to match,
    a set of post rules after a match is found that must be satisfied,
    and a set of actions to be taken if the pattern matches.
     
    These patterns can be restored from an XML file.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct an empty pattern.  Use XML to initialize
        """

    @typing.overload
    def __init__(self, seq: DittedBitSequence, offset: typing.Union[jpype.JInt, int], postArray: jpype.JArray[PostRule], matchArray: jpype.JArray[MatchAction]):
        """
        Construct the pattern based on a DittedByteSequence a match offset, post matching rules,
        and a set of actions to take when the match occurs.
        
        :param DittedBitSequence seq: DittedByteSequence
        :param jpype.JInt or int offset: offset from the actual match location to report a match
        :param jpype.JArray[PostRule] postArray: post set of rules to check for the match
        :param jpype.JArray[MatchAction] matchArray: MatchActions to apply when a match occurs
        """

    def getMarkOffset(self) -> int:
        ...

    def getMatchActions(self) -> jpype.JArray[MatchAction]:
        ...

    def getPostRules(self) -> jpype.JArray[PostRule]:
        ...

    @staticmethod
    def readPatterns(file: generic.jar.ResourceFile, patlist: java.util.ArrayList[Pattern], pfactory: PatternFactory):
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
    def readPostPatterns(file: jpype.protocol.SupportsPath, patternList: java.util.ArrayList[Pattern], pfactory: PatternFactory):
        """
        Read just the post patterns from the ``<patternpair>`` tags
        
        :param jpype.protocol.SupportsPath file: is the file to read from
        :param java.util.ArrayList[Pattern] patternList: collects the resulting Pattern objects
        :param PatternFactory pfactory: is the factory for constructing postrules and matchactions
        :raises IOException: 
        :raises SAXException:
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory):
        ...

    @staticmethod
    def restoreXmlAttributes(postrulelist: java.util.ArrayList[PostRule], actionlist: java.util.ArrayList[MatchAction], parser: ghidra.xml.XmlPullParser, pfactory: PatternFactory):
        """
        Restore the PostRule and the MatchAction tags
        
        :param ghidra.xml.XmlPullParser parser: is the parser at the start of tags
        :param PatternFactory pfactory: is the factory for the PostRule and MatchAction objects
        :raises IOException:
        """

    def setMatchActions(self, actions: jpype.JArray[MatchAction]):
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



__all__ = ["PatternFactory", "MatchAction", "SequenceSearchState", "PatternPairSet", "MemoryBytePatternSearcher", "DummyMatchAction", "DittedBitSequence", "GenericMatchAction", "AlignRule", "PostRule", "Match", "GenericByteSequencePattern", "Pattern"]
