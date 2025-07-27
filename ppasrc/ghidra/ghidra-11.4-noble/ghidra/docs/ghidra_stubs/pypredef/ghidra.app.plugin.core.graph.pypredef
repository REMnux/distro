from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import ghidra.app.services
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.service.graph
import java.lang # type: ignore


class GraphDisplayBrokerListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def providersChanged(self):
        ...


class AddressBasedGraphDisplayListener(ghidra.service.graph.GraphDisplayListener, ghidra.framework.plugintool.util.PluginEventListener):
    """
    Base class for GraphDisplay listeners whose nodes represent addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, display: ghidra.service.graph.GraphDisplay):
        ...

    def getVertex(self, address: ghidra.program.model.address.Address) -> ghidra.service.graph.AttributedVertex:
        ...

    @property
    def vertex(self) -> ghidra.service.graph.AttributedVertex:
        ...


class GraphDisplayBrokerPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.GraphDisplayBroker, ghidra.framework.options.OptionsChangeListener):

    @typing.type_check_only
    class GraphSelectionAction(docking.action.ToggleDockingAction):
        """
        Action for selecting a :obj:`GraphDisplayProvider` to be the currently active provider
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, owner: typing.Union[java.lang.String, str], provider: ghidra.service.graph.GraphDisplayProvider):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def setDefaultGraphDisplayProvider(self, provider: ghidra.service.graph.GraphDisplayProvider):
        ...



__all__ = ["GraphDisplayBrokerListener", "AddressBasedGraphDisplayListener", "GraphDisplayBrokerPlugin"]
