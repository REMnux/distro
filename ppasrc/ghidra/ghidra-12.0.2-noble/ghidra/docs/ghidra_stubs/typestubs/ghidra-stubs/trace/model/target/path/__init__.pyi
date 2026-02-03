from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore
import java.util.stream # type: ignore


class PathPattern(PathFilter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pattern: KeyPath):
        """
        TODO: This can get more sophisticated if needed, but for now, I don't think we even need
        regular expressions. Either we care about a path element, or we don't.
         
         
        
        This takes a keypath as a means of matching paths. The blank key serves as a wildcard
        accepting all keys in that position, e.g., the following matches all elements within
        ``Processes``:
         
         
        :meth:`PathFilter.parse <PathFilter.parse>`("Processes[]");
         
        
        :param KeyPath pattern: a list of path elements
        """

    def asPath(self) -> KeyPath:
        """
        Return the pattern as a key path of patterns
        
        :return: the list of key patterns
        :rtype: KeyPath
        """

    def countWildcards(self) -> int:
        """
        Count the number of wildcard keys in this pattern
        
        :return: the count
        :rtype: int
        """

    @staticmethod
    def isWildcard(pat: typing.Union[java.lang.String, str]) -> bool:
        ...

    def matchKeys(self, path: KeyPath, matchLength: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        """
        If the given path matches, extract keys where matched by wildcards
         
         
        
        This is essentially the inverse of :meth:`applyKeys(String...) <.applyKeys>`, but can only be asked of
        one pattern. The keys are returned from left to right, in the order matched by the pattern.
        Only those keys matched by a wildcard are included in the result. Indices are extracted with
        the brackets ``[]`` removed.
        
        :param KeyPath path: the path to match
        :param jpype.JBoolean or bool matchLength: true if the path must have the same number of keys as this pattern, or
                    false if the path is allowed to have more keys than this pattern
        :return: the list of matched keys or ``null`` if not matched
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def sanitizeKey(key: typing.Union[java.lang.String, str]) -> str:
        """
        Sanitize the given key.
         
         
        
        Because brackets ``[]`` indicate an index in a path, they cannot themselves be used in an
        index. The first closing bracket seen is taken to end the index. We could support escaping,
        e.g., by "``\[``," but that seems a bit onerous for what little it affords. We also
        should not endeavor to support things like "``Memory[something[with][brackets]]``,"
        because we'd still have an issue if the user's brackets are not balanced. Instead, we'll just
        replace the square brackets with curley braces, unless/until that turns out to be a Bad Idea.
        
        :param java.lang.String or str key: the key to sanitize
        :return: the sanitized key
        :rtype: str
        """

    def toPatternString(self) -> str:
        """
        Convert this pattern to a string.,
         
         
        
        This is the inverse of :meth:`PathFilter.parse(String) <PathFilter.parse>`.
        
        :return: the string
        :rtype: str
        """


class PathMatcher(PathFilter):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    @typing.overload
    def any(patterns: java.util.stream.Stream[PathPattern]) -> PathMatcher:
        ...

    @staticmethod
    @typing.overload
    def any(filters: collections.abc.Sequence) -> PathMatcher:
        ...

    @staticmethod
    @typing.overload
    def any(*filters: PathFilter) -> PathMatcher:
        ...


class KeyPath(java.lang.Comparable[KeyPath], java.lang.Iterable[java.lang.String]):
    """
    An immutable path of keys leading from one object (usually the root) object to another
     
     
    
    Often, the source is the root. These are often taken as a parameter when searching for values. In
    essence, they simply wrap a list of string keys, but it provides convenience methods, sensible
    comparison, and better typing.
    """

    class KeyComparator(java.lang.Enum[KeyPath.KeyComparator], java.util.Comparator[java.lang.String]):
        """
        Comparators for keys, i.e., strings in a path
        """

        class_: typing.ClassVar[java.lang.Class]
        ATTRIBUTE: typing.Final[KeyPath.KeyComparator]
        """
        Sort keys by attribute name, lexicographically.
        """

        ELEMENT: typing.Final[KeyPath.KeyComparator]
        """
        Sort keys by element index.
         
         
        
        Element indices may be multidimensional, in which case the dimensions are separated by
        commas, and sorting prioritizes the left-most dimensions. Where indices (or dimensions
        thereof) appear to be numeric, they are sorted as such. Otherwise, they are sorted
        lexicographically. Numeric types can be encoded in hexadecimal. While decimal is typical
        you may run into difficulties if those numbers are too large, as the implementation must
        assume numeric types are hexadecimal.
        
        
        .. admonition:: Implementation Note
        
            The only way I can think to resolve the numeric encoding issue is to examine
            all keys before even selecting a comparator. As is, a comparator can only see
            two keys at a time, and has no context to what it's actually sorting.
        """

        ELEMENT_DIM: typing.Final[KeyPath.KeyComparator]
        """
        Sort keys by element index, allowing only one dimension.
         
         
        
        Please use :obj:`.ELEMENT`, unless you really know you need this instead.
        """

        CHILD: typing.Final[KeyPath.KeyComparator]
        """
        Sort keys by element or index as appropriate, placing elements first.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> KeyPath.KeyComparator:
            ...

        @staticmethod
        def values() -> jpype.JArray[KeyPath.KeyComparator]:
            ...


    class PathComparator(java.lang.Enum[KeyPath.PathComparator], java.util.Comparator[KeyPath]):
        """
        Comparators for paths
        """

        class_: typing.ClassVar[java.lang.Class]
        KEYED: typing.Final[KeyPath.PathComparator]
        """
        Sort paths by key, prioritizing the left-most, i.e., top-most, keys.
         
         
        
        If one path is a prefix to the other, the prefix is "less than" the other.
        """

        LONGEST_FIRST: typing.Final[KeyPath.PathComparator]
        """
        Sort paths by length, longest first, then as in :obj:`.KEYED`.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> KeyPath.PathComparator:
            ...

        @staticmethod
        def values() -> jpype.JArray[KeyPath.PathComparator]:
            ...


    class PathParser(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, path: java.lang.CharSequence, sepRE: typing.Union[java.lang.String, str]):
            ...

        def parse(self) -> KeyPath:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ROOT: typing.Final[KeyPath]

    def containsWildcard(self) -> bool:
        ...

    def countWildcards(self) -> int:
        ...

    @typing.overload
    def extend(self, sub: KeyPath) -> KeyPath:
        """
        Create a new path by appending the given list of keys
         
         
        
        For example, if this path is "``Processes[2]``" and ``sub`` takes the value
        "``Threads[0]``", the result will be "``Processes[2].Threads[0]``".
        
        :param KeyPath sub: the path to append
        :return: the resulting path
        :rtype: KeyPath
        """

    @typing.overload
    def extend(self, *subKeys: typing.Union[java.lang.String, str]) -> KeyPath:
        """
        Create a new path by appending the given keys
        
        :param jpype.JArray[java.lang.String] subKeys: the keys to append
        :return: the resulting path
        :rtype: KeyPath
        
        .. seealso::
        
            | :obj:`.extend(KeyPath)`
        """

    @typing.overload
    def index(self, index: typing.Union[jpype.JLong, int]) -> KeyPath:
        """
        Create a new path by appending the given element index
         
         
        
        For example, if this path is "``Processes``" and ``index`` takes the value 2, the
        result will be "``Processes[2]``".
        
        :param jpype.JLong or int index: the new final index
        :return: the resulting path
        :rtype: KeyPath
        """

    @typing.overload
    def index(self, index: typing.Union[java.lang.String, str]) -> KeyPath:
        """
        Create a new path by appending the given element index
         
         
        
        This does the same as :meth:`key(String) <.key>` but uses brackets instead. For example, if this
        path is "``Processes[2].Threads[0].Registers``" and ``index`` takes the value
        "``RAX``", the result will be "``Processes[2].Threads[0].Registers[RAX]"``.
        
        :param java.lang.String or str index: the new final index
        :return: the resulting path
        :rtype: KeyPath
        """

    @typing.overload
    def index(self) -> str:
        """
        Get the final index of this path
        
        :return: the final index
        :rtype: str
        :raises IllegalArgumentException: if the final key is not an index, i.e., in brackets
        """

    def isAncestor(self, successor: KeyPath) -> bool:
        """
        Check if this path is an ancestor of the given path
         
         
        
        Equivalently, check if the given path is a successor of this path. A path is considered an
        ancestor of itself. To check for a strict ancestor, use
        ``this.isAncestor(that) && !this.equals(that)``.
        
        :param KeyPath successor: the supposed successor to this path
        :return: true if the given path is in fact a successor
        :rtype: bool
        """

    @staticmethod
    def isIndex(key: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the given key is a bracketed index
        
        :param java.lang.String or str key: the key to check
        :return: true if it is an index
        :rtype: bool
        """

    @staticmethod
    def isName(key: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if the given key is an attribute name, i.e., not an index
        
        :param java.lang.String or str key: the key to check
        :return: true if it is an attribute name
        :rtype: bool
        """

    def isRoot(self) -> bool:
        """
        Assuming the source is the root, check if this path refers to that root
        
        :return: true if the path is empty, false otherwise
        :rtype: bool
        """

    @typing.overload
    def key(self, i: typing.Union[jpype.JInt, int]) -> str:
        ...

    @typing.overload
    def key(self, name: typing.Union[java.lang.String, str]) -> KeyPath:
        """
        Create a new path by appending the given key
         
         
        
        For example, if this path is "``Processes[2]``" and ``name`` takes the value
        "``Threads``", the result will be "``Processes[2].Threads``".
        
        :param java.lang.String or str name: the new final key
        :return: the resulting path
        :rtype: KeyPath
        """

    @typing.overload
    def key(self) -> str:
        """
        Get the final key of this path
        
        :return: the final key
        :rtype: str
        """

    @staticmethod
    def makeIndex(i: typing.Union[jpype.JLong, int]) -> str:
        """
        Encode the given index in decimal, without brackets
        
        :param jpype.JLong or int i: the numeric index
        :return: the encoded index
        :rtype: str
        """

    @staticmethod
    def makeKey(index: typing.Union[java.lang.String, str]) -> str:
        """
        Encode the given index as a key
         
         
        
        When indexing elements, no brackets are needed. The brackets become necessary when used as a
        key, e.g., when specifying an index within a path, or as keys in a map of all children.
        
        :param java.lang.String or str index: the index
        :return: the key, specifying an element.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def of(keyList: java.util.List[java.lang.String]) -> KeyPath:
        """
        Create a path from the given list of keys
        
        :param java.util.List[java.lang.String] keyList: the list of keys from source to destination
        :return: the path
        :rtype: KeyPath
        """

    @staticmethod
    @typing.overload
    def of(keyStream: java.util.stream.Stream[java.lang.String]) -> KeyPath:
        ...

    @staticmethod
    @typing.overload
    def of(*keys: typing.Union[java.lang.String, str]) -> KeyPath:
        """
        Create a path from the given keys
        
        :param jpype.JArray[java.lang.String] keys: the keys from source to destination
        :return: the path
        :rtype: KeyPath
        """

    @typing.overload
    def parent(self) -> KeyPath:
        """
        Create a new path by removing the final key
        
        :return: the resulting path, or null if this path is empty
        :rtype: KeyPath
        """

    @typing.overload
    def parent(self, n: typing.Union[jpype.JInt, int]) -> KeyPath:
        """
        Create a new path by removing the final ``n`` keys
        
        :param jpype.JInt or int n: the number of keys to remove
        :return: the resulting path, or null if fewer than 0 keys would remain
        :rtype: KeyPath
        """

    @staticmethod
    def parse(path: typing.Union[java.lang.String, str]) -> KeyPath:
        """
        Parse a path from the given string
        
        :param java.lang.String or str path: the dot-separated keys from source to destination
        :return: the path
        :rtype: KeyPath
        """

    @staticmethod
    def parseIfIndex(key: typing.Union[java.lang.String, str]) -> str:
        """
        If an index, parse it, otherwise just return the key
        
        :param java.lang.String or str key: the key
        :return: the index or key
        :rtype: str
        """

    @staticmethod
    def parseIndex(key: typing.Union[java.lang.String, str]) -> str:
        """
        Parse an index value from a key
         
         
        
        Where key is the form ``[index]``, this merely returns ``index``.
        
        :param java.lang.String or str key: the key
        :return: the index
        :rtype: str
        :raises IllegalArgumentException: if key is not of the required form
        """

    def relativize(self, successor: KeyPath) -> KeyPath:
        """
        Assuming this is an ancestor of the given successor, compute the relative path from here to
        there
        
        :param KeyPath successor: the successor
        :return: the relative path
        :rtype: KeyPath
        """

    def size(self) -> int:
        ...

    def streamMatchingAncestry(self, filter: PathFilter) -> java.util.stream.Stream[KeyPath]:
        """
        Stream, starting with the longer paths, paths that match the given predicates
        
        :param PathFilter filter: the predicates to filter the ancestor paths
        :return: the stream of matching paths, longest to shortest
        :rtype: java.util.stream.Stream[KeyPath]
        """

    def toList(self) -> java.util.List[java.lang.String]:
        """
        Get the (immutable) list of keys from source to destination
        
        :return: the key list
        :rtype: java.util.List[java.lang.String]
        """

    @property
    def root(self) -> jpype.JBoolean:
        ...

    @property
    def ancestor(self) -> jpype.JBoolean:
        ...


class PathFilter(java.lang.Object):

    class Align(java.lang.Enum[PathFilter.Align]):

        class_: typing.ClassVar[java.lang.Class]
        LEFT: typing.Final[PathFilter.Align]
        RIGHT: typing.Final[PathFilter.Align]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> PathFilter.Align:
            ...

        @staticmethod
        def values() -> jpype.JArray[PathFilter.Align]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[PathFilter]

    def ancestorCouldMatchRight(self, path: KeyPath, strict: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if the given path *could* have a matching ancestor, right to left
         
         
        
        This essentially checks if the given path is a viable postfix to the matcher.
        
        :param KeyPath path: the path (postfix) to check
        :param jpype.JBoolean or bool strict: true to exclude the case where :meth:`matches(KeyPath) <.matches>` would return true
        :return: true if an ancestor could match, false otherwise
        :rtype: bool
        """

    def ancestorMatches(self, path: KeyPath, strict: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if the given path has an ancestor that matches
        
        :param KeyPath path: the path to check
        :param jpype.JBoolean or bool strict: true to exclude the case where :meth:`matches(KeyPath) <.matches>` would return true
        :return: true if an ancestor matches, false otherwise
        :rtype: bool
        """

    @staticmethod
    def anyMatches(pats: java.util.Set[java.lang.String], key: typing.Union[java.lang.String, str]) -> bool:
        ...

    @typing.overload
    def applyIntKeys(self, radix: typing.Union[jpype.JInt, int], align: PathFilter.Align, keys: java.util.List[java.lang.Integer]) -> PathFilter:
        ...

    @typing.overload
    def applyIntKeys(self, radix: typing.Union[jpype.JInt, int], align: PathFilter.Align, *keys: typing.Union[jpype.JInt, int]) -> PathFilter:
        ...

    @typing.overload
    def applyIntKeys(self, *keys: typing.Union[jpype.JInt, int]) -> PathFilter:
        ...

    @typing.overload
    def applyKeys(self, align: PathFilter.Align, keys: java.util.List[java.lang.String]) -> PathFilter:
        """
        Substitute wildcards from left to right for the given list of keys
         
         
        
        Takes each pattern and substitutes its wildcards for the given indices, according to the
        given alignment. This object is unmodified, and the result is returned.
         
         
        
        If there are fewer wildcards in a pattern than given, only the first keys are taken. If there
        are fewer keys than wildcards in a pattern, then the remaining wildcards are left in the
        resulting pattern. In this manner, the left-most wildcards are substituted for the left-most
        indices, or the right-most wildcards are substituted for the right-most indices, depending on
        the alignment.
        
        :param PathFilter.Align align: the end to align
        :param java.util.List[java.lang.String] keys: the keys to substitute
        :return: the pattern or matcher with the applied substitutions
        :rtype: PathFilter
        """

    @typing.overload
    def applyKeys(self, align: PathFilter.Align, *keys: typing.Union[java.lang.String, str]) -> PathFilter:
        ...

    @typing.overload
    def applyKeys(self, *keys: typing.Union[java.lang.String, str]) -> PathFilter:
        ...

    def getNextIndices(self, path: KeyPath) -> java.util.Set[java.lang.String]:
        """
        Assuming a successor of path could match, get the patterns for the next possible index
         
         
        
        If a successor of the given path cannot match this pattern, the empty set is returned. If the
        pattern could accept an index next, get all patterns describing those indices
        
        :param KeyPath path: the ancestor path
        :return: a set of patterns, without brackets ``[]``
        :rtype: java.util.Set[java.lang.String]
        """

    def getNextKeys(self, path: KeyPath) -> java.util.Set[java.lang.String]:
        """
        Get the patterns for the next possible key
         
         
        
        If a successor of the given path cannot match this pattern, the empty set is returned.
        
        :param KeyPath path: the ancestor path
        :return: a set of patterns where indices are enclosed in brackets ``[]``
        :rtype: java.util.Set[java.lang.String]
        """

    def getNextNames(self, path: KeyPath) -> java.util.Set[java.lang.String]:
        """
        Get the patterns for the next possible name
         
         
        
        If a successor of the given path cannot match this pattern, the empty set is returned. If the
        pattern could accept a name next, get all patterns describing those names
        
        :param KeyPath path: the ancestor path
        :return: a set of patterns
        :rtype: java.util.Set[java.lang.String]
        """

    def getPatterns(self) -> java.util.Set[PathPattern]:
        """
        Get the patterns of this predicate
        
        :return: the patterns
        :rtype: java.util.Set[PathPattern]
        """

    def getPrevKeys(self, path: KeyPath) -> java.util.Set[java.lang.String]:
        """
        Get the patterns for the previous possible key (right-to-left matching)
         
         
        
        If an ancestor of the given path cannot match this pattern, the empty set is returned.
        
        :param KeyPath path: the successor path
        :return: a set of patterns where indices are enclosed in brackets ``[]``
        :rtype: java.util.Set[java.lang.String]
        """

    def getSingletonPath(self) -> KeyPath:
        """
        If this predicate is known to match only one path, i.e., no wildcards, get that path
        
        :return: the singleton path, or ``null``
        :rtype: KeyPath
        """

    def getSingletonPattern(self) -> PathPattern:
        """
        If this predicate consists of a single pattern, get that pattern
        
        :return: the singleton pattern, or ``null``
        :rtype: PathPattern
        """

    def isNone(self) -> bool:
        """
        Test if any patterns are contained here
         
         
        
        Note that the presence of a pattern does not guarantee the presence of a matching object.
        However, the absence of any pattern does guarantee no object can match.
        
        :return: true if equivalent to :obj:`.NONE`
        :rtype: bool
        """

    @staticmethod
    def keyMatches(pat: typing.Union[java.lang.String, str], key: typing.Union[java.lang.String, str]) -> bool:
        ...

    def matches(self, path: KeyPath) -> bool:
        """
        Check if the entire path passes
        
        :param KeyPath path: the path to check
        :return: true if it matches, false otherwise
        :rtype: bool
        """

    def or_(self, that: PathFilter) -> PathFilter:
        ...

    @staticmethod
    def parse(pattern: typing.Union[java.lang.String, str]) -> PathPattern:
        ...

    @staticmethod
    @typing.overload
    def pattern(*keyPatterns: typing.Union[java.lang.String, str]) -> PathFilter:
        ...

    @staticmethod
    @typing.overload
    def pattern(keyPatterns: KeyPath) -> PathFilter:
        ...

    def removeRight(self, count: typing.Union[jpype.JInt, int]) -> PathFilter:
        """
        Remove count elements from the right
        
        :param jpype.JInt or int count: the number of elements to remove
        :return: the resulting filter
        :rtype: PathFilter
        """

    def successorCouldMatch(self, path: KeyPath, strict: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Check if the given path *could* have a matching successor
         
         
        
        This essentially checks if the given path is a viable prefix to the matcher.
        
        
        .. admonition:: Implementation Note
        
            this method could become impractical for culling queries if we allow too
            sophisticated of patterns. Notably, to allow an "any number of keys" pattern, e.g.,
            akin to ``/src/**{@literal /}*.c`` in file system path matchers. Anything
            starting with "src" could have a successor that matches.
        
        
        :param KeyPath path: the path (prefix) to check
        :param jpype.JBoolean or bool strict: true to exclude the case where :meth:`matches(KeyPath) <.matches>` would return true
        :return: true if a successor could match, false otherwise
        :rtype: bool
        """

    @property
    def singletonPath(self) -> KeyPath:
        ...

    @property
    def nextNames(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def prevKeys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def nextKeys(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def patterns(self) -> java.util.Set[PathPattern]:
        ...

    @property
    def none(self) -> jpype.JBoolean:
        ...

    @property
    def nextIndices(self) -> java.util.Set[java.lang.String]:
        ...

    @property
    def singletonPattern(self) -> PathPattern:
        ...



__all__ = ["PathPattern", "PathMatcher", "KeyPath", "PathFilter"]
