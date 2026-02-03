from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.pattern
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.app.plugin.processors.sleigh.template
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class SleighSubtableTraversal(VisitorResults):
    """
    A class to traverse SLEIGH constructors in a single table
    
    
    .. seealso::
    
        | :obj:`SleighLanguages.traverseConstructors(SubtableSymbol, SubtableEntryVisitor)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sub: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol):
        """
        Prepare to traverse the constructors of a given table
        
        :param ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol sub: the table
        """

    def traverse(self, visitor: SubtableEntryVisitor) -> int:
        """
        Traverse the constructors in the table
        
        :param SubtableEntryVisitor visitor: a callback for each constructor
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class ConstructorEntryVisitor(VisitorResults):
    """
    An interface for visiting constructors in a SLEIGH language
    
    
    .. seealso::
    
        | :obj:`SleighLanguages.traverseConstructors(SleighLanguage, ConstructorEntryVisitor)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def visit(self, subtable: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol, pattern: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> int:
        """
        Callback to visit a constructor
        
        :param ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol subtable: the table containing the constructor
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pattern: the pattern corresponding to the constructor
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


@typing.type_check_only
class SleighPcodeTraversal(VisitorResults):
    """
    A class to traverse SLEIGH Pcode operations in a language
    """

    @typing.type_check_only
    class OnlyPcodeOpEntryVisitor(VisitorResults):
        """
        An interface for visiting Pcode operations in a constructor
        
        
        .. seealso::
        
            | :obj:`SleighPcodeTraversal.traverse(OnlyPcodeOpEntryVisitor)`NOTE: This is meant for internal use only
        """

        class_: typing.ClassVar[java.lang.Class]

        def visit(self, op: ghidra.app.plugin.processors.sleigh.template.OpTpl) -> int:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, cons: ghidra.app.plugin.processors.sleigh.Constructor):
        """
        Prepare to traverse the Pcode entries of a given constructor
        
        :param ghidra.app.plugin.processors.sleigh.Constructor cons:
        """

    def traverse(self, visitor: SleighPcodeTraversal.OnlyPcodeOpEntryVisitor) -> int:
        """
        Traverse the Pcode operations in the constructor
        
        :param SleighPcodeTraversal.OnlyPcodeOpEntryVisitor visitor: a callback for each Pcode operation
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class InputContextScraper(java.lang.Object):
    """
    A class for scraping input contexts from a SLEIGH language to get all of the valid input contexts
    that affect constructor selection
    """

    @typing.type_check_only
    class GlobalSetScraper(ConstructorEntryVisitor):

        class_: typing.ClassVar[java.lang.Class]

        def getContextMask(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
            ...

        @property
        def contextMask(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
            ...


    @typing.type_check_only
    class ConstraintScraper(ConstructorEntryVisitor):

        class_: typing.ClassVar[java.lang.Class]

        def getInputContexts(self) -> java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock]:
            ...

        @property
        def inputContexts(self) -> java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        ...

    def scrapeInputContexts(self) -> java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock]:
        """
        :return: the set of all valid input contexts that affect constructor selection.
        :rtype: java.util.Set[ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock]
        
         
         
        1. Start with mask of the language's default context
        2. Scrape language for globalset context variables and OR their masks into our
        mask
        3. Flip bits of our mask to get mask of context variables not used as input
        (local/transient)
        4. Check constructor constraints and use mask to get values of relevant input context
        variables
        """


class SubtableEntryVisitor(VisitorResults):
    """
    An interface for visiting constructors in a SLEIGH subtable
    
    
    .. seealso::
    
        | :obj:`SleighLanguages.traverseConstructors(SubtableSymbol, SubtableEntryVisitor)`}
    """

    class_: typing.ClassVar[java.lang.Class]

    def visit(self, pattern: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> int:
        """
        Callback to visit a constructor
        
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pattern: the pattern corresponding to the constructor
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class PcodeOpEntryVisitor(VisitorResults):
    """
    An interface for visiting Pcode operations in a SLEIGH language
    
    
    .. seealso::
    
        | :obj:`SleighLanguages.traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def visit(self, subtable: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol, pattern: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, cons: ghidra.app.plugin.processors.sleigh.Constructor, op: ghidra.app.plugin.processors.sleigh.template.OpTpl) -> int:
        """
        Callback to visit a Pcode operation
        
        :param ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol subtable: the table containing the constructor
        :param ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern pattern: the pattern corresponding to the constructor
        :param ghidra.app.plugin.processors.sleigh.Constructor cons: the constructor generating the Pcode operation
        :param ghidra.app.plugin.processors.sleigh.template.OpTpl op: the Pcode operation
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class SleighLanguages(java.lang.Object):
    """
    A collection of utility functions for traversing constructors and Pcode operations of SLEIGH
    languages
    """

    @typing.type_check_only
    class ConsVisitForPcode(ConstructorEntryVisitor):
        """
        An internal visitor
         
        The :meth:`SleighLanguages.traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor) <SleighLanguages.traverseAllPcodeOps>` method
        uses this visitor to traverse every constructor a given language. For each constructor, it
        then applies another (anonymous) visitor to traverse each Pcode operation in the visited
        constructor. That anonymous visitor wraps the visitor given by the caller.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, visitor: PcodeOpEntryVisitor):
            """
            Prepare to traverse a constructor
            
            :param PcodeOpEntryVisitor visitor: the wrapped Pcode operation visitor to invoke
            """


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def traverseAllPcodeOps(lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, visitor: PcodeOpEntryVisitor) -> int:
        """
        Traverse the Pcode operations of a given SLEIGH language
         
        During traversal, if a "NOP" constructor, i.e., one having no Pcode operations, is
        encountered, the callback is still invoked at least once, with a null Pcode operation. This
        is so NOP constructors are not overlooked by this traversal.
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: the language
        :param PcodeOpEntryVisitor visitor: a callback for each Pcode operation visited
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def traverseConstructors(lang: ghidra.app.plugin.processors.sleigh.SleighLanguage, visitor: ConstructorEntryVisitor) -> int:
        """
        Traverse the constructors of a given SLEIGH language
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: the language
        :param ConstructorEntryVisitor visitor: a callback for each constructor visited
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def traverseConstructors(subtable: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol, visitor: SubtableEntryVisitor) -> int:
        """
        Traverse the constructors of a given table
        
        :param ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol subtable: the table
        :param SubtableEntryVisitor visitor: a callback for each constructor visited
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class SleighConstructorTraversal(VisitorResults):
    """
    A class to traverse SLEIGH constructors in a language
    
    
    .. seealso::
    
        | :obj:`SleighLanguages.traverseConstructors(SleighLanguage, ConstructorEntryVisitor)`
    """

    @typing.type_check_only
    class SubVisitor(SubtableEntryVisitor):
        """
        An internal visitor
         
        The :meth:`SleighConstructorTraversal.traverse(ConstructorEntryVisitor) <SleighConstructorTraversal.traverse>` method iterates
        over each subtable, traversing each with this visitor. This visitor wraps the visitor given
        by the caller.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, lang: ghidra.app.plugin.processors.sleigh.SleighLanguage):
        """
        Prepare to traverse the constructors of a given SLEIGH language
        
        :param ghidra.app.plugin.processors.sleigh.SleighLanguage lang: the language
        """

    def traverse(self, visitor: ConstructorEntryVisitor) -> int:
        """
        Traverse the constructors in the language
        
        :param ConstructorEntryVisitor visitor: a callback for each constructor
        :return: a value from :obj:`VisitorResults`
        :rtype: int
        """


class VisitorResults(java.lang.Object):
    """
    Some constants for controlling traversal
     
    A callback (``visit()``) can return one of these constants to control whether or not
    traversal continues. ``traverse()`` methods will return a value to indicate how traversal
    terminated.
    """

    class_: typing.ClassVar[java.lang.Class]
    CONTINUE: typing.Final = 0
    """
    Continue
     
    From ``visit()``: continue traversal as usual.
    This value is never returned by ``traverse()``.
    """

    FINISHED: typing.Final = 1
    """
    Finish(ed)
     
    From ``visit()``: terminate traversal with a successful result.
    From ``traverse()``: traversal terminated successfully. Either a call to ``visit()``
    returned :obj:`.FINISHED`, or all calls to ``visit()`` returned :obj:`.CONTINUE`.
    """

    TERMINATE: typing.Final = 2
    """
    Terminate(d)
     
    From ``visit()``: terminate traversal with an unsuccessful result.
    From ``traverse()``: traversal terminated unsuccessful. Either a call to ``visit()``
    returned :obj:`.TERMINATE`, or there was an error during traversal.
    """




__all__ = ["SleighSubtableTraversal", "ConstructorEntryVisitor", "SleighPcodeTraversal", "InputContextScraper", "SubtableEntryVisitor", "PcodeOpEntryVisitor", "SleighLanguages", "SleighConstructorTraversal", "VisitorResults"]
