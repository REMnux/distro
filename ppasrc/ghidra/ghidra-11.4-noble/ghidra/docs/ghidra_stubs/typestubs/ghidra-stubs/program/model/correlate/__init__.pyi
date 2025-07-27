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
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class Hash(java.lang.Comparable[Hash]):
    """
    This encodes the main hash value for an n-gram, and the number of Instructions hashed
    """

    class_: typing.ClassVar[java.lang.Class]
    SEED: typing.Final = 22222
    ALTERNATE_SEED: typing.Final = 11111

    def __init__(self, val: typing.Union[jpype.JInt, int], sz: typing.Union[jpype.JInt, int]):
        ...


class DisambiguateByParent(DisambiguateStrategy):
    """
    Attempt to disambiguate similar n-grams by looking at the parents of blocks containing the n-grams
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HashStore(java.lang.Object):
    """
    HashStore is a sorted, basic-block aware, store for Instruction "n-grams" to help quickly match similar
    sequences of Instructions between two functions.  The Instructions comprising a single n-gram are hashed
    for quick lookup by the main matching algorithm (HashedFunctionAddressCorrelation).  Hash diversity is
    important to minimize collisions, even though the number of hashes calculated for a single function pair
    match is small.
     
    Hashes are built and sorted respectively using the calcHashes() and insertHashes() methods. The main sort
    is on the number of collisions for a hash (indicating that there are duplicate or near duplicate instruction
    sequences), the hashes with fewer (or no) duplicates come first. The secondary sort is on
    "n", the number of Instructions in the n-gram, which effectively describes the significance of the match, or how
    unlikely the match is to occur at random.  The main matching algorithm effectively creates a HashSort for both
    functions, and then in a loop calls
        hash = getFirstEntry()    on one side to get the most significant possible match
        getEntry(has)             to see if there is a matching n-gram on the other side
        
    If there is a match it is declared to the sort with the matchHash() call, allowing overlapping n-grams to be
    removed and deconflicting information to be updated.  If there is no match, hashes can be removed with the
    removeHash() method to allow new hashes to move to the top of the sort.
     
    The store uses a couple of methods to help deconflict very similar sequences of instructions within the same function.
    Primarily, the sort is basic-block aware.  All n-grams are contained within a single basic block, and when an initial
    match is found, hashes for other n-grams within that block (and its matching block on the other side) are modified
    so that n-grams within that block pair can only match each other.
    """

    @typing.type_check_only
    class HashOrderComparator(java.util.Comparator[HashEntry]):
        """
        Comparator for the main HashStore sort.  Sort first preferring smallest number of duplicate n-grams,
        then subsort on the size (significance) of the n-gram.
        """

        class_: typing.ClassVar[java.lang.Class]


    class NgramMatch(java.lang.Object):
        """
        Class explicitly labeling (one-side of) a matching n-gram pair.
        """

        class_: typing.ClassVar[java.lang.Class]
        block: Block
        startindex: jpype.JInt
        endindex: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, a: ghidra.program.model.listing.Function, mon: ghidra.util.task.TaskMonitor):
        ...

    def calcHashes(self, minLength: typing.Union[jpype.JInt, int], maxLength: typing.Union[jpype.JInt, int], wholeBlock: typing.Union[jpype.JBoolean, bool], matchOnly: typing.Union[jpype.JBoolean, bool], hashCalc: HashCalculator):
        """
        Calculate hashes for all blocks
        
        :param jpype.JInt or int minLength: is the minimum length of an n-gram for these passes
        :param jpype.JInt or int maxLength: is the maximum length of an n-gram for these passes
        :param jpype.JBoolean or bool wholeBlock: if true, allows blocks that are smaller than the minimum length to be considered as 1 n-gram.
        :param jpype.JBoolean or bool matchOnly: if true, only generates n-grams for sequences in previously matched blocks
        :param HashCalculator hashCalc: is the hash function
        :raises MemoryAccessException:
        """

    def clearSort(self):
        """
        Clear the main sort structures, but preserve blocks and instructions
        """

    @staticmethod
    def extendMatch(nGramSize: typing.Union[jpype.JInt, int], srcInstruct: InstructHash, srcMatch: HashStore.NgramMatch, destInstruct: InstructHash, destMatch: HashStore.NgramMatch, hashCalc: HashCalculator):
        """
        Try to extend a match on a pair of n-grams to the Instructions right before and right after the n-gram.
        The match is extended if the Instruction adjacent to the n-gram, and its corresponding pair on the other side,
        hash to the same value using the hash function. The NgramMatch objects are updated to reflect the
        original n-gram match plus any additional extension.
        
        :param jpype.JInt or int nGramSize: is the original size of the matching n-gram.
        :param InstructHash srcInstruct: is the first Instruction in the "source" n-gram
        :param HashStore.NgramMatch srcMatch: is the "source" NgramMatch object to be populate
        :param InstructHash destInstruct: is the first Instruction in the "destination" n-gram
        :param HashStore.NgramMatch destMatch: is the "destination" NgramMatch object to populate
        :param HashCalculator hashCalc: is the hash function object
        :raises MemoryAccessException:
        """

    def getBlock(self, addr: ghidra.program.model.address.Address) -> Block:
        """
        Get the basic-block with the corresponding start Address
        
        :param ghidra.program.model.address.Address addr: is the starting address
        :return: the Block object
        :rtype: Block
        """

    def getEntry(self, hash: Hash) -> HashEntry:
        """
        Get the HashEntry corresponding to a given hash
        
        :param Hash hash: is the Hash to match
        :return: the set of n-grams (HashEntry) matching this hash
        :rtype: HashEntry
        """

    def getFirstEntry(self) -> HashEntry:
        """
        
        
        :return: the first HashEntry in the sort.  The least number of matching n-grams and the biggest n-gram.
        :rtype: HashEntry
        """

    def getMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        
        
        :return: the TaskMonitor for this store
        :rtype: ghidra.util.task.TaskMonitor
        """

    def getTotalInstructions(self) -> int:
        """
        
        
        :return: total number of Instructions in the whole function
        :rtype: int
        """

    def getUnmatchedInstructions(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        """
        
        
        :return: list of unmatched instructions across the whole function
        :rtype: java.util.List[ghidra.program.model.listing.Instruction]
        """

    def insertHashes(self):
        """
        Insert all hashes associated with unknown (i.e not matched) blocks and instructions
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if there are no n-grams left in the sort
        :rtype: bool
        """

    def matchHash(self, match: HashStore.NgramMatch, instResult: java.util.List[ghidra.program.model.listing.Instruction], blockResult: java.util.List[ghidra.program.model.block.CodeBlock]):
        """
        Mark a particular n-gram hash and instruction as having a match.
        Set of instructions covered by n-gram are removed, and data structures are updated
        
        :param HashStore.NgramMatch match: is the n-gram being declared as a match
        :param java.util.List[ghidra.program.model.listing.Instruction] instResult: collects the explicit set of Instructions matched
        :param java.util.List[ghidra.program.model.block.CodeBlock] blockResult: collects the explicit set of CodeBlocks matched
        """

    def numMatchedInstructions(self) -> int:
        """
        
        
        :return: number of instructions that have been matched so far
        :rtype: int
        """

    def removeHash(self, hashEntry: HashEntry):
        """
        Remove a particular HashEntry.  This may affect multiple instructions.
        
        :param HashEntry hashEntry: is the entry
        """

    @property
    def entry(self) -> HashEntry:
        ...

    @property
    def unmatchedInstructions(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        ...

    @property
    def monitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    @property
    def block(self) -> Block:
        ...

    @property
    def firstEntry(self) -> HashEntry:
        ...

    @property
    def totalInstructions(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class Block(java.lang.Object):
    """
    This class holds basic-block information for matching algorithms. It is used as a node to traverse the
    control-flow graph. It serves as a container for hashing information associated with Instructions in the
    block.  It holds disambiguating hashes (calculated primarily from basic-block parent/child relationships)
    to help separate identical or near identical sequences of Instructions within one function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeBlock: ghidra.program.model.block.CodeBlock):
        ...

    def getMatchHash(self) -> int:
        """
        
        
        :return: the main deconfliction hash feed
        :rtype: int
        """

    def hashGram(self, gramSize: typing.Union[jpype.JInt, int], instHash: InstructHash, hashCalc: HashCalculator) -> int:
        """
        Calculate an n-gram hash, given a particular hash function
        
        :param jpype.JInt or int gramSize: is the size of the n-gram
        :param InstructHash instHash: is the first Instruction in the n-gram
        :param HashCalculator hashCalc: is the hash function
        :return: the final 32-bit hash
        :rtype: int
        :raises MemoryAccessException:
        """

    @property
    def matchHash(self) -> jpype.JInt:
        ...


class InstructHash(java.lang.Object):
    """
    This class is the container for hashing information about a particular instruction, including all the
    n-grams it is currently involved in within the HashStore.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, inst: ghidra.program.model.listing.Instruction, bl: Block, ind: typing.Union[jpype.JInt, int]):
        """
        Build an (unmatched) Instruction, associating it with its position in the basic block
        
        :param ghidra.program.model.listing.Instruction inst: is the underlying instruction
        :param Block bl: is the basic-block
        :param jpype.JInt or int ind: is the index within the block
        """

    def allUnknown(self, length: typing.Union[jpype.JInt, int]) -> bool:
        """
        If the -length- instructions, starting with this, are all unmatched, return true;
        
        :param jpype.JInt or int length: is number of instructions to check
        :return: true if all checked instructions are unmatched
        :rtype: bool
        """

    def getBlock(self) -> Block:
        """
        
        
        :return: the containing basic block
        :rtype: Block
        """

    @property
    def block(self) -> Block:
        ...


class DisambiguateByChild(DisambiguateStrategy):
    """
    Attempt to disambiguate similar n-grams by looking at the children of blocks containing the n-grams
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class DisambiguateByParentWithOrder(DisambiguateStrategy):
    """
    Attempt to disambiguate similar n-grams by looking at the parents, AND siblings, of blocks containing the n-grams.
    This addresses switch constructions in particular, where code for individual cases look very similar but can be
    distinguished by the ordering of the cases.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HashCalculator(java.lang.Object):
    """
    Interface for hashing across sequences of Instructions in different ways
    """

    class_: typing.ClassVar[java.lang.Class]

    def calcHash(self, startHash: typing.Union[jpype.JInt, int], inst: ghidra.program.model.listing.Instruction) -> int:
        """
        Calculate a (partial) hash across a single instruction
        
        :param jpype.JInt or int startHash: is initial hash value
        :param ghidra.program.model.listing.Instruction inst: is the instruction to fold into the hash
        :return: the final hash value
        :rtype: int
        :raises MemoryAccessException:
        """


class AllBytesHashCalculator(HashCalculator):
    """
    Hash function hashing all the bytes of an individual Instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HashedFunctionAddressCorrelation(ghidra.program.util.ListingAddressCorrelation):
    """
    Correlator to construct a 1-1 map between the Instructions of two similar Functions. Matching is performed
    via a greedy algorithm that looks for sequences (n-grams) of Instructions that are similar between the two Functions.
    Similarity of two sequences is determined by comparing hashes generated by the HashCalculator object.
     
    1) Potential sequences and their hashes are generated for both functions (see HashStore).
    2) Sequences are pulled from the HashStore based on the uniqueness of a potential match and on the size of the sequence.
    3) If a unique match is found between sequences, it is extended in either direction as far as possible,
        as constrained by HashCalculator and the containing basic-blocks.
    4) The matching Instruction pairs are put in the final map and removed from further sequence lists
        to allow other potential matches to be considered.
    5) Sequences with no corresponding match are also removed from consideration.
    6) Sequences are limited to a single basic-block, and the algorithm is basic-block aware.
        Once a match establishes a correspondence between a pair of basic blocks, the algorithm uses
    7) If a particular sequence has matches that are not unique, the algorithm tries to disambiguate the potential
        matches by looking at parent/child relationships of the containing basic-blocks. (see DisambiguateStrategy)
    8) Multiple passes are attempted, each time the set of potential sequences is completely regenerated,
        varying the range of sequence sizes for which a match is attempted and other hash parameters. This
        allows matches discovered by earlier passes to disambiguate sequences in later passes.
    """

    @typing.type_check_only
    class DisambiguatorEntry(java.lang.Object):
        """
        A helper class for sorting through, disambiguating, sequences with identical hashes
        """

        class_: typing.ClassVar[java.lang.Class]
        hash: Hash
        count: jpype.JInt
        instruct: InstructHash

        def __init__(self, h: Hash, inst: InstructHash):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, leftFunction: ghidra.program.model.listing.Function, rightFunction: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor):
        """
        Correlates addresses between the two specified functions.
        
        :param ghidra.program.model.listing.Function leftFunction: the first function
        :param ghidra.program.model.listing.Function rightFunction: the second function
        :param ghidra.util.task.TaskMonitor monitor: the task monitor that indicates progress and allows the user to cancel.
        :raises CancelledException: if the user cancels
        :raises MemoryAccessException: if either functions memory can't be accessed.
        """

    def getFirstToSecondIterator(self) -> java.util.Iterator[java.util.Map.Entry[ghidra.program.model.address.Address, ghidra.program.model.address.Address]]:
        """
        Gets an iterator of the matching addresses from the first function to the second.
        
        :return: the iterator
        :rtype: java.util.Iterator[java.util.Map.Entry[ghidra.program.model.address.Address, ghidra.program.model.address.Address]]
        """

    def getTotalInstructionsInFirst(self) -> int:
        """
        Gets the total number of instructions that are in the first function.
        
        :return: the first function's instruction count.
        :rtype: int
        """

    def getTotalInstructionsInSecond(self) -> int:
        """
        Gets the total number of instructions that are in the second function.
        
        :return: the second function's instruction count.
        :rtype: int
        """

    def getUnmatchedInstructionsInFirst(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        """
        Determines the number of instructions from the first function that do not match an 
        instruction in the second function.
        
        :return: the number of instructions in the first function without matches.
        :rtype: java.util.List[ghidra.program.model.listing.Instruction]
        """

    def getUnmatchedInstructionsInSecond(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        """
        Determines the number of instructions from the second function that do not match an 
        instruction in the first function.
        
        :return: the number of instructions in the second function without matches.
        :rtype: java.util.List[ghidra.program.model.listing.Instruction]
        """

    def numMatchedInstructionsInFirst(self) -> int:
        """
        Determines the number of instructions from the first function that match an instruction
        in the second function.
        
        :return: the number of instructions in the first function that have matches.
        :rtype: int
        """

    def numMatchedInstructionsInSecond(self) -> int:
        """
        Determines the number of instructions from the second function that match an instruction
        in the first function.
        
        :return: the number of instructions in the second function that have matches.
        :rtype: int
        """

    @property
    def totalInstructionsInSecond(self) -> jpype.JInt:
        ...

    @property
    def unmatchedInstructionsInSecond(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        ...

    @property
    def unmatchedInstructionsInFirst(self) -> java.util.List[ghidra.program.model.listing.Instruction]:
        ...

    @property
    def firstToSecondIterator(self) -> java.util.Iterator[java.util.Map.Entry[ghidra.program.model.address.Address, ghidra.program.model.address.Address]]:
        ...

    @property
    def totalInstructionsInFirst(self) -> jpype.JInt:
        ...


class DisambiguateStrategy(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def calcHashes(self, instHash: InstructHash, matchSize: typing.Union[jpype.JInt, int], store: HashStore) -> java.util.ArrayList[Hash]:
        """
        Generate (possibly multiple) hashes that can be used to disambiguate an n-gram and its block from other
        blocks with similar instructions.  Hashes are attached to the block's disambigHash list.
        
        :param InstructHash instHash: the instruction hash
        :param jpype.JInt or int matchSize: the number of instructions to match
        :param HashStore store: is the HashStore used to store the disambiguating hashes
        :return: the list of disambiguating hashes
        :rtype: java.util.ArrayList[Hash]
        :raises CancelledException: 
        :raises MemoryAccessException:
        """


class HashEntry(java.lang.Object):
    """
    Cross-reference container for different n-grams that share a particular hash
    """

    class_: typing.ClassVar[java.lang.Class]
    instList: java.util.LinkedList[InstructHash]

    def __init__(self, h: Hash):
        ...

    def hasDuplicateBlocks(self) -> bool:
        """
        
        
        :return: true if any two InstructHash for this HashEntry share the same parent Block
        :rtype: bool
        """


class DisambiguateByBytes(DisambiguateStrategy):
    """
    Attempt to disambiguate similar n-grams by hashing over all the bytes in their constituent instructions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MnemonicHashCalculator(HashCalculator):
    """
    Hash function hashing only the mnemonic of an individual Instruction
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["Hash", "DisambiguateByParent", "HashStore", "Block", "InstructHash", "DisambiguateByChild", "DisambiguateByParentWithOrder", "HashCalculator", "AllBytesHashCalculator", "HashedFunctionAddressCorrelation", "DisambiguateStrategy", "HashEntry", "DisambiguateByBytes", "MnemonicHashCalculator"]
