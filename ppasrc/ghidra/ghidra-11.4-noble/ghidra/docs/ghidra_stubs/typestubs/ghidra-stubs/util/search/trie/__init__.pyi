from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.mem
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


P = typing.TypeVar("P")
T = typing.TypeVar("T")


class CaseInsensitiveByteTrieNode(ByteTrieNode[T], typing.Generic[T]):
    """
    Class to represent a (possibly non-terminal!) node within the CaseInsensitiveByteTrie.
    """

    class_: typing.ClassVar[java.lang.Class]


class CaseInsensitiveByteTrie(ByteTrie[T], typing.Generic[T]):
    """
    CaseInsensitiveByteTrie is a byte-based trie specifically designed to implement the Aho-Corasick
    string search algorithm, matching alphabetic characters ignoring case.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ByteTrieIfc(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def add(self, value: jpype.JArray[jpype.JByte], item: T) -> bool:
        """
        Adds a byte sequence to the trie, with corresponding user item.  Returns
        if the add took place, or if this add was essentially a replacement of
        a previously present value (previous user item is lost forever).
        
        :param jpype.JArray[jpype.JByte] value: the byte sequence to insert into the trie
        :param T item: a user item to store in that location
        :return: whether the add took place
        :rtype: bool
        """

    def find(self, value: jpype.JArray[jpype.JByte]) -> ByteTrieNodeIfc[T]:
        """
        Finds a byte sequence in the trie and returns a node interface object for it,
        or null if not present.
        
        :param jpype.JArray[jpype.JByte] value: the byte sequence sought
        :return: the node interface if present, or null
        :rtype: ByteTrieNodeIfc[T]
        """

    def inorder(self, monitor: ghidra.util.task.TaskMonitor, op: Op[T]):
        """
        Visits all the nodes in the trie such that the visitation order is properly
        byte value ordered. The client is responsible for not performing actions on
        non-terminal nodes as necessary.
        
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :param Op[T] op: the operation to perform
        :raises CancelledException: if the user cancels
        """

    def isEmpty(self) -> bool:
        """
        Returns if the trie is empty.
        
        :return: if the trie is empty
        :rtype: bool
        """

    def numberOfNodes(self) -> int:
        """
        Returns the number of nodes in the trie; this is essentially equal
        to the sum of the number of characters in all byte sequences present in
        the trie, minus their shared prefixes.
        
        :return: the number of nodes in the trie
        :rtype: int
        """

    @typing.overload
    def search(self, text: jpype.JArray[jpype.JByte], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[SearchResult[java.lang.Integer, T]]:
        """
        Search an array of bytes using the Aho-Corasick multiple string
        trie search algorithm.
        
        :param jpype.JArray[jpype.JByte] text: the bytes to search
        :return: a list of results (tuple of offset position, text found)
        :rtype: java.util.List[SearchResult[java.lang.Integer, T]]
        :raises CancelledException: if the search is cancelled
        """

    @typing.overload
    def search(self, memory: ghidra.program.model.mem.Memory, view: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[SearchResult[ghidra.program.model.address.Address, T]]:
        """
        Search an array of bytes using the Aho-Corasick multiple string
        trie search algorithm.
        
        :param ghidra.program.model.mem.Memory memory: the memory to search in
        :param ghidra.program.model.address.AddressSetView view: the AddressSetView to restrict the memory search to.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: a list of results (tuple of offset position, text found)
        :rtype: java.util.List[SearchResult[ghidra.program.model.address.Address, T]]
        :raises MemoryAccessException: if an error occurs reading the memory
        :raises CancelledException: if the search is cancelled
        """

    def size(self) -> int:
        """
        Returns the number of byte sequences in the trie.
        
        :return: the number of byte sequences in the trie
        :rtype: int
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class ByteTrieNodeIfc(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    def getItem(self) -> T:
        """
        Returns the user item stored in a terminal node (or null in an
        internal node).
        
        :return: the user item
        :rtype: T
        """

    def getValue(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns a new byte array with the value of the byte sequence represented
        by this node (slow, built from scratch every time).
        
        :return: the byte sequence
        :rtype: jpype.JArray[jpype.JByte]
        """

    def isTerminal(self) -> bool:
        """
        Returns whether this node represents a byte sequence in the trie
        or just an internal node on our way down to one.
        
        :return: whether this node represents a terminal value
        :rtype: bool
        """

    def length(self) -> int:
        """
        Returns the length of the byte sequence represented by this node
        (cached integer, very fast).
        
        :return: the length of the byte sequence
        :rtype: int
        """

    @property
    def item(self) -> T:
        ...

    @property
    def terminal(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...


class SearchResult(java.lang.Object, typing.Generic[P, T]):
    """
    A search result container class used with ByteTrie.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getItem(self) -> T:
        """
        Returns the user item stored in this terminal node at add time.
        
        :return: the user item
        :rtype: T
        """

    def getNode(self) -> ByteTrieNodeIfc[T]:
        """
        Returns the (terminal) node that was encountered in the search
        
        :return: the node
        :rtype: ByteTrieNodeIfc[T]
        """

    def getPosition(self) -> P:
        """
        Returns the position at which the byte sequence was found.  Currently
        ByteTrie will use Integer for search byte arrays, and Address
        for searching Memory in a Program.
        
        :return: the position at which the byte sequence was found
        :rtype: P
        """

    @property
    def node(self) -> ByteTrieNodeIfc[T]:
        ...

    @property
    def item(self) -> T:
        ...

    @property
    def position(self) -> P:
        ...


class ByteTrieNode(ByteTrieNodeIfc[T], typing.Generic[T]):
    """
    Class to represent a (possibly non-terminal!) node within the ByteTrie.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getChild(self, value: typing.Union[jpype.JByte, int]) -> ByteTrieNode[T]:
        """
        Returns the child node (successor in the byte sequence) which
        has byte value, or null if no such child exists.
        
        :param jpype.JByte or int value: the byte value
        :return: the child node if present or null
        :rtype: ByteTrieNode[T]
        """

    def getItem(self) -> T:
        """
        Returns the user item stored in a terminal node (or null in an
        internal node).
        
        :return: the user item
        :rtype: T
        """

    def getValue(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns a new byte array with the value of the byte sequence represented
        by this node (slow, built from scratch every time).
        
        :return: the byte sequence
        :rtype: jpype.JArray[jpype.JByte]
        """

    def isTerminal(self) -> bool:
        """
        Returns whether this node represents a byte sequence in the trie
        or just an internal node on our way down to one.
        
        :return: whether this node represents a terminal value
        :rtype: bool
        """

    def length(self) -> int:
        """
        Returns the length of the byte sequence represented by this node
        (cached integer, very fast).
        
        :return: the length of the byte sequence
        :rtype: int
        """

    @property
    def item(self) -> T:
        ...

    @property
    def terminal(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def child(self) -> ByteTrieNode[T]:
        ...


class ByteTrie(ByteTrieIfc[T], typing.Generic[T]):
    """
    ByteTrie is a byte-based trie specifically designed to implement the Aho-Corasick
    string search algorithm.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def add(self, value: jpype.JArray[jpype.JByte], item: T) -> bool:
        """
        Adds a byte sequence to the trie, with corresponding user item.  Returns
        if the add took place, or if this add was essentially a replacement of
        a previously present value (previous user item is lost forever).
        
        :param jpype.JArray[jpype.JByte] value: the byte sequence to insert into the trie
        :param T item: a user item to store in that location
        :return: whether the add took place
        :rtype: bool
        """

    def find(self, value: jpype.JArray[jpype.JByte]) -> ByteTrieNodeIfc[T]:
        """
        Finds a byte sequence in the trie and returns a node interface object for it,
        or null if not present.
        
        :param jpype.JArray[jpype.JByte] value: the byte sequence sought
        :return: the node interface if present, or null
        :rtype: ByteTrieNodeIfc[T]
        """

    def inorder(self, monitor: ghidra.util.task.TaskMonitor, op: Op[T]):
        """
        Visits all the nodes in the trie such that the visitation order is properly
        ordered (even though the actual algorithm below is a PREORDER traversal).
        The client is responsible for not performing actions on non-terminal nodes
        as necessary.
        
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :param Op[T] op: the operation to perform
        :raises CancelledException: if the user cancels
        """

    def isEmpty(self) -> bool:
        """
        Returns if the trie is empty.
        
        :return: if the trie is empty
        :rtype: bool
        """

    def numberOfNodes(self) -> int:
        """
        Returns the number of nodes in the trie; this is essentially equal
        to the sum of the number of characters in all byte sequences present in
        the trie, minus their shared prefixes.
        
        :return: the number of nodes in the trie
        :rtype: int
        """

    @typing.overload
    def search(self, text: jpype.JArray[jpype.JByte], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[SearchResult[java.lang.Integer, T]]:
        """
        Search an array of bytes using the Aho-Corasick multiple string
        trie search algorithm.
        
        :param jpype.JArray[jpype.JByte] text: the bytes to search
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: a list of search results
        :rtype: java.util.List[SearchResult[java.lang.Integer, T]]
        :raises CancelledException:
        """

    @typing.overload
    def search(self, memory: ghidra.program.model.mem.Memory, view: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[SearchResult[ghidra.program.model.address.Address, T]]:
        """
        Search memory using the Aho-Corasick multiple string
        trie search algorithm.
        
        :param ghidra.program.model.mem.Memory memory: the program memory manager
        :param ghidra.program.model.address.AddressSetView view: the address set view to search
        :param ghidra.util.task.TaskMonitor monitor: a task monitor
        :return: a list of search results
        :rtype: java.util.List[SearchResult[ghidra.program.model.address.Address, T]]
        :raises MemoryAccessException: if bytes are not available
        :raises CancelledException: if the user cancels
        """

    def size(self) -> int:
        """
        Returns the number of byte sequences in the trie.
        
        :return: the number of byte sequences in the trie
        :rtype: int
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class Op(java.lang.Object, typing.Generic[T]):
    """
    Operation interface for clients to visit nodes in a ByteTrie.
    """

    class_: typing.ClassVar[java.lang.Class]

    def op(self, node: ByteTrieNodeIfc[T]):
        """
        Perform an operation on a node.
        
        :param ByteTrieNodeIfc[T] node: the current node
        """



__all__ = ["CaseInsensitiveByteTrieNode", "CaseInsensitiveByteTrie", "ByteTrieIfc", "ByteTrieNodeIfc", "SearchResult", "ByteTrieNode", "ByteTrie", "Op"]
