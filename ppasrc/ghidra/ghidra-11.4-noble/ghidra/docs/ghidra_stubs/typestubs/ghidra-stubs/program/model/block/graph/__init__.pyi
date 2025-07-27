from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.graph
import ghidra.program.model.block
import java.lang # type: ignore


class CodeBlockEdge(ghidra.graph.DefaultGEdge[CodeBlockVertex]):
    """
    A simple edge type for representing a link between two 
    :obj:`CodeBlock vertices <CodeBlockVertex>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, start: CodeBlockVertex, end: CodeBlockVertex):
        """
        Constructor.
        
        :param CodeBlockVertex start: the start vertex
        :param CodeBlockVertex end: the end vertex
        """


class CodeBlockVertex(java.lang.Comparable[CodeBlockVertex]):
    """
    A class for representing a code block within a graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, codeBlock: ghidra.program.model.block.CodeBlock):
        """
        Constructor.
        
        :param ghidra.program.model.block.CodeBlock codeBlock: the code block for this vertex
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str]):
        """
        A constructor that allows for the creation of dummy nodes.  This is useful in graphs 
        where multiple entry or exit points need to be parented by a single vertex.
        
        :param java.lang.String or str name: the name of this vertex
        """

    def getCodeBlock(self) -> ghidra.program.model.block.CodeBlock:
        ...

    def getName(self) -> str:
        ...

    def isDummy(self) -> bool:
        """
        Returns true if this vertex is not backed by a code block.
        
        :return: true if this vertex is not backed by a code block.
        :rtype: bool
        """

    @property
    def dummy(self) -> jpype.JBoolean:
        ...

    @property
    def codeBlock(self) -> ghidra.program.model.block.CodeBlock:
        ...

    @property
    def name(self) -> java.lang.String:
        ...



__all__ = ["CodeBlockEdge", "CodeBlockVertex"]
