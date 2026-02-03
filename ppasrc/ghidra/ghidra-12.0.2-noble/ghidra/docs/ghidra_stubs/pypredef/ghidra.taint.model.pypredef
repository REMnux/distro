"""
The Taint domain package
 
 

This package implements the domain of taint analysis. :obj:`ghidra.taint.model.TaintVec` models
an array of bytes, each having a :obj:`ghidra.taint.model.TaintSet`. A
:obj:`ghidra.taint.model.TaintSet` is in turn made of several
:obj:`ghidra.taint.model.TaintMark`s. Each mark is a symbol with optional tags. We use the tags
as a means of handling indirection, so that we don't have to decide up front whether tainted
offsets taint the values read and written from memory. We allow them to be tainted, but add a tag
to the mark, so they can be examined and/or filtered by the user.
 
 

To facilitate storage and presentation of taint, we will need to implement some
(de)serialization. Rather than use Java's notion, we'll just implement toString and a static
parse method for sets and marks.
 
 

We recommend you read the documentation and source from the bottom up:
:obj:`ghidra.taint.model.TaintMark`, :obj:`ghidra.taint.model.TaintSet`,
:obj:`ghidra.taint.model.TaintVec`.
"""
from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


class TaintSet(java.lang.Object):
    """
    An immutable set of multiple taint marks
     
     
    
    A variable in an emulator could be tainted by multiple marks, so we must use vectors of sets, not
    vectors of marks. Please see :meth:`TaintMark.equals(Object) <TaintMark.equals>` regarding the equality of tagged
    marks.
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY: typing.Final[TaintSet]
    """
    The empty set, the default for all state variables
    """


    def getMarks(self) -> java.util.Set[TaintMark]:
        """
        Get the marks in this set
        
        :return: the marks
        :rtype: java.util.Set[TaintMark]
        """

    def isEmpty(self) -> bool:
        """
        Check if this set is empty
        
        :return: the marks
        :rtype: bool
        """

    @staticmethod
    def of(*marks: TaintMark) -> TaintSet:
        """
        Create a taint set of the given marks
        
        :param jpype.JArray[TaintMark] marks: the marks
        :return: the set
        :rtype: TaintSet
        """

    @staticmethod
    def parse(string: typing.Union[java.lang.String, str]) -> TaintSet:
        """
        Parse a set of taint marks
         
         
        
        The form is a semicolon-separated list of taint marks, e.g.,
        "``myVar:tag1,tag2;anotherVar;yetAnother``".
        
        :param java.lang.String or str string: the string to parse
        :return: the resulting set
        :rtype: TaintSet
        """

    def tagged(self, string: typing.Union[java.lang.String, str]) -> TaintSet:
        """
        Construct the taint set formed by tagging each mark in this set
        
        :param java.lang.String or str string: the tag to add to each mark
        :return: the new set
        :rtype: TaintSet
        """

    def toString(self) -> str:
        """
        Convert the set to a string
        
        
        .. seealso::
        
            | :obj:`.parse(String)`
        """

    def union(self, that: TaintSet) -> TaintSet:
        """
        Construct the taint set from the union of marks of this and the given taint set
        
        :param TaintSet that: another taint set
        :return: the union
        :rtype: TaintSet
        """

    @property
    def marks(self) -> java.util.Set[TaintMark]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class TaintVec(java.lang.Object):
    """
    A mutable, but fixed-size, buffer of taint sets
     
     
    
    This is the auxiliary type used by the Taint Analyzer's emulator.
     
     
    
    Regarding serialization, we do not serialize the vector for storage, but only for display. For
    storage, we instead serialize and store each taint set on an address-by-address basis. Thus, we
    do not (yet) have a ``parse(String)`` method.
    """

    class ShiftMode(java.lang.Enum[TaintVec.ShiftMode]):
        """
        Common shifting behaviors
        """

        class_: typing.ClassVar[java.lang.Class]
        UNBOUNDED: typing.Final[TaintVec.ShiftMode]
        """
        No bound is applied to the shift. Values that fall off the edge are dropped. Furthermore,
        if the shift is greater than the length, all the values will fall off the edge and be
        dropped.
         
         
        +---+------+
        | 0 | 1234 |
        | 1 | _123 |
        | 2 | __12 |
        | 3 | ___1 |
        | 4 | ____ |
        +---+------+
        """

        REMAINDER: typing.Final[TaintVec.ShiftMode]
        """
        Only the lowest required bits are taken for the shift amount, i.e., the remainder when
        divided by the length, often a power of 2. Values that fall off the edge are dropped.
         
         
        +---+------+
        | 0 | 1234 |
        | 1 | _123 |
        | 2 | __12 |
        | 3 | ___1 |
        | 4 | 1234 | (Only the lowest 2 bits of the shift amount are considered)
        +---+------+
        """

        CIRCULAR: typing.Final[TaintVec.ShiftMode]
        """
        Only the lowest required bits are taken for the shift amount, i.e., the remainder when
        divided by the length, often a power of 2. (Even if unbounded, a circular shift yields
        the same result.) Values that fall off the edge are cycled to the opposite end.
         
         
        +---+------+
        | 0 | 1234 |
        | 1 | 4123 |
        | 2 | 3412 |
        | 3 | 2341 |
        | 4 | 1234 |
        +---+------+
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TaintVec.ShiftMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[TaintVec.ShiftMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    length: typing.Final[jpype.JInt]

    def __init__(self, length: typing.Union[jpype.JInt, int]):
        """
        Create a new uninitialized taint vector of the given length
        
        :param jpype.JInt or int length: the length
        """

    @staticmethod
    def array(name: typing.Union[java.lang.String, str], start: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> TaintVec:
        """
        Create a taint vector representing a new tainted byte array, where each element is given a
        distinct name
         
         
        
        For example, the parameters ``("arr", 0, 4)`` will produce the vector
        "``[arr_0][arr_1][arr_2][arr_3]``". Each element is a singleton set containing the mark
        for a byte in the tainted array.
        
        :param java.lang.String or str name: the base for naming each element
        :param jpype.JLong or int start: the starting index for naming each element
        :param jpype.JInt or int size: the number of bytes, i.e., the length of the vector
        :return: the new vector
        :rtype: TaintVec
        """

    @staticmethod
    def copies(taint: TaintSet, size: typing.Union[jpype.JInt, int]) -> TaintVec:
        """
        Broadcast the given set into a new vector or the given length
        
        :param TaintSet taint: the taint set
        :param jpype.JInt or int size: the length of the vector
        :return: the new vector
        :rtype: TaintVec
        """

    def copy(self) -> TaintVec:
        """
        Create a copy of this vector
        
        :return: the copy
        :rtype: TaintVec
        """

    def eachUnion(self, set: TaintSet) -> TaintVec:
        """
        Union each element with the given set, forming a new result vector
        
        :param TaintSet set: the taint set
        :return: the result
        :rtype: TaintVec
        """

    @staticmethod
    def empties(size: typing.Union[jpype.JInt, int]) -> TaintVec:
        """
        Create a vector of empty taint sets
        
        :param jpype.JInt or int size: the length of the vector
        :return: the new vector
        :rtype: TaintVec
        """

    def extended(self, length: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool], isSigned: typing.Union[jpype.JBoolean, bool]) -> TaintVec:
        """
        Extend this vector to create a new vector of the given length
         
         
        
        Elements are appended at the most significant end, as specified by the endianness. If signed,
        the appended elements are copies of the most significant element in this vector. Otherwise,
        they are empty taint sets.
        
        :param jpype.JInt or int length: the length of the new vector
        :param jpype.JBoolean or bool isBigEndian: true to append to the lower-indexed end, false to append to the
                    higher-indexed end
        :param jpype.JBoolean or bool isSigned: true to append copies of the most significant element, false to append empty
                    sets
        :return: the new vector
        :rtype: TaintVec
        """

    def get(self, i: typing.Union[jpype.JInt, int]) -> TaintSet:
        """
        Get an element from the vector
        
        :param jpype.JInt or int i: the index
        :return: the taint set
        :rtype: TaintSet
        """

    def getSets(self) -> java.util.List[TaintSet]:
        """
        Get the vector as a list
        
        :return: the list
        :rtype: java.util.List[TaintSet]
        """

    @staticmethod
    def of(*taints: TaintSet) -> TaintVec:
        ...

    @typing.overload
    def set(self, i: typing.Union[jpype.JInt, int], s: TaintSet):
        """
        Set an element in the vector
        
        :param jpype.JInt or int i: the index
        :param TaintSet s: the taint set
        """

    @typing.overload
    def set(self, start: typing.Union[jpype.JInt, int], vec: TaintVec) -> TaintVec:
        """
        Set several elements in the vector
         
         
        
        This is essentially just an array copy. The entire source ``vec`` is copied into this
        vector such that the first element of the source is placed at the start index of the
        destination.
        
        :param jpype.JInt or int start: the starting index
        :param TaintVec vec: the vector of sets
        :return: this vector
        :rtype: TaintVec
        """

    def setArray(self, name: typing.Union[java.lang.String, str], start: typing.Union[jpype.JLong, int]) -> TaintVec:
        """
        Fill this vector as in :meth:`array(String, long, int) <.array>`, modifying it in place
        
        :param java.lang.String or str name: the base for naming each element
        :param jpype.JLong or int start: the starting index for naming each element
        :return: this vector
        :rtype: TaintVec
        """

    def setBlur(self, right: typing.Union[jpype.JBoolean, bool]) -> TaintVec:
        """
        Modify the vector so each element becomes the union of itself and its neighbor
         
         
        
        This should be used to model shift operations. Both the shift direction and the endianness
        must be considered.
        
        :param jpype.JBoolean or bool right: true to cause each greater index to be unioned in place with less-indexed
                    neighbor
        :return: this vector
        :rtype: TaintVec
        """

    def setCascade(self, isBigEndian: typing.Union[jpype.JBoolean, bool]) -> TaintVec:
        """
        Modify the vector so each element becomes the union of itself and all elements of lesser
        significance
         
         
        
        This should be used after :meth:`zipUnion(TaintVec) <.zipUnion>` to model operations with carries.
        
        :param jpype.JBoolean or bool isBigEndian: true if smaller indices have greater significance
        :return: this vector
        :rtype: TaintVec
        """

    def setCopies(self, taint: TaintSet) -> TaintVec:
        """
        Broadcast the given set over this vector, modifying it in place
        
        :param TaintSet taint: the taint set
        :return: this vector
        :rtype: TaintVec
        """

    def setEmpties(self) -> TaintVec:
        """
        Broadcast the empty taint set over this vector, modifying it in place
        
        :return: this vector
        :rtype: TaintVec
        """

    def setShifted(self, right: typing.Union[jpype.JInt, int], mode: TaintVec.ShiftMode) -> TaintVec:
        """
        Shift this vector some number of elements, in place
        
        :param jpype.JInt or int right: the number of elements to shift right, or negative for left
        :param TaintVec.ShiftMode mode: the behavior of the shift
        :return: this vector
        :rtype: TaintVec
        """

    def sub(self, offset: typing.Union[jpype.JInt, int], length: typing.Union[jpype.JInt, int]) -> TaintVec:
        """
        Extract a subpiece of this vector
        
        :param jpype.JInt or int offset: the offset into this vector
        :param jpype.JInt or int length: the number of sets to extract
        :return: the resulting vector
        :rtype: TaintVec
        """

    def tagIndirectRead(self, offset: TaintVec) -> TaintVec:
        """
        Combine this and another taint vector to represent a tainted indirect read
         
         
        
        Because the all bytes of the address offset "affect" the value read, we first union all the
        taint sets of the that offset. We then tag each mark in that union with "``indR``".
        Finally we union that result with each element of this vector (this vector representing the
        bytes read from memory).
        
        :param TaintVec offset: the vector representing the bytes that encode the offset
        :return: the vector representing the tainted bytes read from memory
        :rtype: TaintVec
        """

    def tagIndirectWrite(self, offset: TaintVec) -> TaintVec:
        """
        Combine this and another taint vector to represent a tainted indirect write
         
         
        
        This works the same as :meth:`tagIndirectRead(TaintVec) <.tagIndirectRead>`, except with the tag "``indW``"
        and it occurs before the actual write.
        
        :param TaintVec offset: the vector representing the bytes that encode the offset
        :return: the vector representing the tainted bytes to be written to memory
        :rtype: TaintVec
        """

    def toDisplay(self) -> str:
        """
        Convert the vector to a string suitable for display in the UI
        
        :return: the string
        :rtype: str
        """

    def truncated(self, length: typing.Union[jpype.JInt, int], isBigEndian: typing.Union[jpype.JBoolean, bool]) -> TaintVec:
        """
        Drop all but length elements from this vector, creating a new vector
         
         
        
        Drops the most significant elements of this vector, as specified by the endianness
        
        :param jpype.JInt or int length: the length fo the new vector
        :param jpype.JBoolean or bool isBigEndian: true to drop lower-indexed elements, false to drop higher-indexed elements
        :return: the truncated vector
        :rtype: TaintVec
        """

    def union(self) -> TaintSet:
        """
        Reduce this vector to a single taint set by union
        
        :return: the resulting taint set
        :rtype: TaintSet
        """

    def zipUnion(self, that: TaintVec) -> TaintVec:
        """
        Union each element with its corresponding element from another vector, forming a new result
        vector
        
        :param TaintVec that: the other vector
        :return: the result
        :rtype: TaintVec
        """

    @property
    def sets(self) -> java.util.List[TaintSet]:
        ...


class TaintMark(java.lang.Object):
    """
    A taint mark
     
     
    
    This is essentially a symbol or variable, but we also include an immutable set of tags. A mark is
    the bottom-most component in a :obj:`TaintVec`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], tags: java.util.Set[java.lang.String]):
        """
        Construct a new taint mark
         
         
        
        TODO: Validation that the name and tags do not contain any separators, so that
        :meth:`parse(String) <.parse>` and :meth:`toString() <.toString>` are proper inverses.
        
        :param java.lang.String or str name: the name
        :param java.util.Set[java.lang.String] tags: the tags
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Check if two marks are equal
         
         
        
        Note that we distinguish between a mark without tags and another mark with the same name but
        having tags. Because we use tags to indicate, e.g., indirection, we want to allow a variable
        to be marked as tainted both directly and indirectly. Furthermore, if indirect taints are
        filtered, we would want to ensure such a variable is not removed, since it's also tainted
        directly.
        """

    def getName(self) -> str:
        """
        Get the name of the mark
        
        :return: the name
        :rtype: str
        """

    def getTags(self) -> java.util.Set[java.lang.String]:
        """
        Get the mark's tags
        
        :return: the tags
        :rtype: java.util.Set[java.lang.String]
        """

    @staticmethod
    def parse(string: typing.Union[java.lang.String, str]) -> TaintMark:
        """
        Parse a mark from the given string
         
         
        
        A mark has the form "``name:tag1,tag2,...,tagN``". The tags are optional, so it may also
        take the form "``name``".
        
        :param java.lang.String or str string: the string to parse
        :return: the resulting mark
        :rtype: TaintMark
        """

    def tagged(self, tag: typing.Union[java.lang.String, str]) -> TaintMark:
        """
        Create a new mark with the given tag added
         
         
        
        Tags are a set, so this may return the same mark
        
        :param java.lang.String or str tag: 
        :return: 
        :rtype: TaintMark
        """

    def toString(self) -> str:
        """
        Render the mark as a string
        
        
        .. seealso::
        
            | :obj:`.parse(String)`
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def tags(self) -> java.util.Set[java.lang.String]:
        ...



__all__ = ["TaintSet", "TaintVec", "TaintMark"]
