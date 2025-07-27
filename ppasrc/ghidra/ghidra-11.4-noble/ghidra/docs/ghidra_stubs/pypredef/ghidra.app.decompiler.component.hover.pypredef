from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.decompiler
import ghidra.app.plugin.core.hover
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.data


class DataTypeDecompilerHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, DecompilerHoverService):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getFieldDataType(field: ghidra.app.decompiler.ClangFieldToken) -> ghidra.program.model.data.DataType:
        ...


class FunctionSignatureDecompilerHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, DecompilerHoverService):
    """
    A hover service to show tool tip text for hovering over a function name in the decompiler.
    The tooltip shows the function signature per the listing.
    """

    class_: typing.ClassVar[java.lang.Class]


class ReferenceDecompilerHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over references in the decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class FunctionSignatureDecompilerHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over function names in the decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ScalarValueDecompilerHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over scalar values in the decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DataTypeDecompilerHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over data types in the decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DecompilerHoverService(ghidra.app.services.HoverService):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ScalarValueDecompilerHover(ghidra.app.plugin.core.hover.AbstractScalarOperandHover, DecompilerHoverService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ReferenceDecompilerHover(ghidra.app.plugin.core.hover.AbstractReferenceHover, DecompilerHoverService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["DataTypeDecompilerHover", "FunctionSignatureDecompilerHover", "ReferenceDecompilerHoverPlugin", "FunctionSignatureDecompilerHoverPlugin", "ScalarValueDecompilerHoverPlugin", "DataTypeDecompilerHoverPlugin", "DecompilerHoverService", "ScalarValueDecompilerHover", "ReferenceDecompilerHover"]
