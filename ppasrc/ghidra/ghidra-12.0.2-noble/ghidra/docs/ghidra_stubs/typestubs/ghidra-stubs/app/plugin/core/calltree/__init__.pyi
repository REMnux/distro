from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.tree
import docking.widgets.tree.tasks
import ghidra.app.plugin
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang # type: ignore
import java.util # type: ignore


class CallNode(docking.widgets.tree.GTreeSlowLoadingNode):
    """
    In general, a CallNode represents a function and its relationship (either a call reference or
    a data reference) to the function of its parent node
    """

    @typing.type_check_only
    class CallNodeComparator(java.util.Comparator[docking.widgets.tree.GTreeNode]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, callTreeOptions: CallTreeOptions):
        ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        Returns a location that represents the caller of the callee.
        
        :return: the location
        :rtype: ghidra.program.util.ProgramLocation
        """

    def getRemoteFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns this node's remote function, where remote is the source function for
        an incoming call or a destination function for an outgoing call.   May return
        null for nodes that do not have functions.
        
        :return: the function or null
        :rtype: ghidra.program.model.listing.Function
        """

    def getSourceAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address that for the caller of the callee.
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def isCallReference(self) -> bool:
        """
        Returns true if the reference associated with this node is a call reference type.
        
        :return: true if the reference associated with this node is a call reference type.
        :rtype: bool
        """

    @property
    def callReference(self) -> jpype.JBoolean:
        ...

    @property
    def sourceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def remoteFunction(self) -> ghidra.program.model.listing.Function:
        ...


class OutgoingCallsRootNode(OutgoingCallNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class IncomingCallNode(CallNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CallTreeOptions(java.lang.Object):
    """
    Settings for the :obj:`CallTreePlugin`.  This class is immutable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def allowsDuplicates(self) -> bool:
        ...

    def allowsNonCallReferences(self) -> bool:
        """
        This value is based on the ``filterReferences`` value.  When filtering references, we 
        only allow call references to be shown.
        
        :return: true if allowing all reference types
        :rtype: bool
        """

    def allowsThunks(self) -> bool:
        ...

    def getRecurseDepth(self) -> int:
        ...

    def showNamespace(self) -> bool:
        ...

    def withFilterDuplicates(self, filter: typing.Union[jpype.JBoolean, bool]) -> CallTreeOptions:
        ...

    def withFilterReferences(self, filter: typing.Union[jpype.JBoolean, bool]) -> CallTreeOptions:
        ...

    def withFilterThunks(self, filter: typing.Union[jpype.JBoolean, bool]) -> CallTreeOptions:
        ...

    def withRecurseDepth(self, depth: typing.Union[jpype.JInt, int]) -> CallTreeOptions:
        ...

    def withShowNamespace(self, show: typing.Union[jpype.JBoolean, bool]) -> CallTreeOptions:
        ...

    @property
    def recurseDepth(self) -> jpype.JInt:
        ...


class CallTreePlugin(ghidra.app.plugin.ProgramPlugin):
    """
    Assuming a function **foo**, this plugin will show:
    1) all callers of **foo** 
    2) all functions which reference **foo**
    3) all callees of **foo**
    4) all functions referenced by **foo**.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...


class OutgoingCallNode(CallNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class CallTreeProvider(ghidra.framework.plugintool.ComponentProviderAdapter):

    @typing.type_check_only
    class ExpandToDepthTask(docking.widgets.tree.tasks.GTreeExpandAllTask):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tree: docking.widgets.tree.GTree, node: docking.widgets.tree.GTreeNode, maxDepth: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class PendingRootNode(docking.widgets.tree.GTreeNode):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EmptyRootNode(docking.widgets.tree.GTreeNode):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateFunctionNodeTask(docking.widgets.tree.GTreeTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: CallTreePlugin, isPrimary: typing.Union[jpype.JBoolean, bool]):
        ...

    def getRecurseDepth(self) -> int:
        ...

    def setIncomingFilter(self, text: typing.Union[java.lang.String, str]):
        ...

    def setOutgoingFilter(self, text: typing.Union[java.lang.String, str]):
        ...

    def setRecurseDepth(self, depth: typing.Union[jpype.JInt, int]):
        ...

    @property
    def recurseDepth(self) -> jpype.JInt:
        ...

    @recurseDepth.setter
    def recurseDepth(self, value: jpype.JInt):
        ...


class ExternalCallNode(CallNode):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DeadEndNode(CallNode):

    class_: typing.ClassVar[java.lang.Class]

    def getRemoteAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def remoteAddress(self) -> ghidra.program.model.address.Address:
        ...


class IncomingCallsRootNode(IncomingCallNode):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["CallNode", "OutgoingCallsRootNode", "IncomingCallNode", "CallTreeOptions", "CallTreePlugin", "OutgoingCallNode", "CallTreeProvider", "ExternalCallNode", "DeadEndNode", "IncomingCallsRootNode"]
