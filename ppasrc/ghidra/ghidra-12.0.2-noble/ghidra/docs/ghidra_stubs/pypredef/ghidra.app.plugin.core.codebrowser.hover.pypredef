from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.plugin.core.hover
import ghidra.app.services
import ghidra.framework.plugintool


class LabelListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over labels in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ReferenceListingHover(ghidra.app.plugin.core.hover.AbstractReferenceHover, ListingHoverService):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, codeFormatSvc: ghidra.app.services.CodeFormatService):
        ...


class ScalarOperandListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over scalar values in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class FunctionSignatureListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for a function signature
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class LabelListingHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ListingHoverService):
    """
    A hover service to show the full namespace path of a symbol along with its symbol type and
    source type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ReferenceListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over references in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def getReferenceHoverService(self) -> ReferenceListingHover:
        ...

    @property
    def referenceHoverService(self) -> ReferenceListingHover:
        ...


class DataTypeListingHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ListingHoverService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class TruncatedTextListingHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ListingHoverService):
    """
    A hover service to show tool tip text for hovering over a truncated field, containing a "...",
    in the listing.
    The tooltip shows the entire text for that field.
    This provides the hover capability for the TruncatedTextHoverPlugin and can
    also be used to directly provide this hover capability to a listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ProgramAddressRelationshipListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over program addresses in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class DataTypeListingHoverPlugin(ghidra.app.plugin.ProgramPlugin):
    """
    A plugin to show tool tip text for hovering over data types in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class TruncatedTextListingHoverPlugin(ghidra.framework.plugintool.Plugin):
    """
    A plugin to show tool tip text for hovering over over-length fields in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class FunctionSignatureListingHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ListingHoverService):
    """
    A Listing hover to show tool tips for function signatures
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ListingHoverService(ghidra.app.services.HoverService):
    ...
    class_: typing.ClassVar[java.lang.Class]


class ProgramAddressRelationshipListingHover(ghidra.app.plugin.core.hover.AbstractConfigurableHover, ListingHoverService):
    """
    A hover service to show tool tip text for hovering over a program address in the listing.
    The tool tip text shows relationships to key topological elements of the program relative to
    the address -- offset from image base, offset from current memory block; if the address is
    within the bounds of a function, the offset from function entry point; if the address is within
    the bounds of defined data, the offset from the start of the data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class ScalarOperandListingHover(ghidra.app.plugin.core.hover.AbstractScalarOperandHover, ListingHoverService):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...



__all__ = ["LabelListingHoverPlugin", "ReferenceListingHover", "ScalarOperandListingHoverPlugin", "FunctionSignatureListingHoverPlugin", "LabelListingHover", "ReferenceListingHoverPlugin", "DataTypeListingHover", "TruncatedTextListingHover", "ProgramAddressRelationshipListingHoverPlugin", "DataTypeListingHoverPlugin", "TruncatedTextListingHoverPlugin", "FunctionSignatureListingHover", "ListingHoverService", "ProgramAddressRelationshipListingHover", "ScalarOperandListingHover"]
