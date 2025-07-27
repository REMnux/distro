from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.context
import ghidra.app.plugin.core.codebrowser
import ghidra.framework.plugintool
import java.lang # type: ignore


class CloneCodeViewerAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], provider: ghidra.app.plugin.core.codebrowser.CodeViewerProvider):
        ...


class ExpandAllDataAction(ghidra.app.context.ProgramLocationContextAction):
    """
    Action for recursively expanding an expandable data element in the listing.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.codebrowser.CodeViewerProvider):
        ...


class ToggleExpandCollapseDataAction(ghidra.app.context.ProgramLocationContextAction):
    """
    Action for toggling the expanded/collapsed state of an single expandable data element.  This
    action works for both top level structures and structures inside other structures.  Also,
    if invoked on any data element inside a structure, it will collapse the immediate parent
    of that element.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.codebrowser.CodeViewerProvider):
        ...


class GotoPreviousFunctionAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...


class GotoNextFunctionAction(ghidra.app.context.NavigatableContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...


class CollapseAllDataAction(ghidra.app.context.ProgramLocationContextAction):
    """
    Action for recursively collapsing an expandable data element in the listing.  This action
    can be invoked on an expandable data element or any sub element and will close the
    outer most data element and all child elements of that structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: ghidra.app.plugin.core.codebrowser.CodeViewerProvider):
        ...



__all__ = ["CloneCodeViewerAction", "ExpandAllDataAction", "ToggleExpandCollapseDataAction", "GotoPreviousFunctionAction", "GotoNextFunctionAction", "CollapseAllDataAction"]
