from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.framework.options
import ghidra.graph
import ghidra.graph.viewer
import java.lang # type: ignore
import javax.swing # type: ignore


E = typing.TypeVar("E")
G = typing.TypeVar("G")
V = typing.TypeVar("V")


class VisualGraphFeaturette(java.lang.Object, typing.Generic[V, E, G]):
    """
    An interface that represents a sub-feature of a :obj:`VisualGraphComponentProvider`.  This
    allows the base provider to have a set of features ready to be installed by subclasses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def init(self, provider: ghidra.graph.VisualGraphComponentProvider[V, E, G]):
        """
        Called to initialize this feature when the provider and view are ready
        
        :param ghidra.graph.VisualGraphComponentProvider[V, E, G] provider: the provider associated with this feature
        """

    def providerClosed(self, provider: ghidra.graph.VisualGraphComponentProvider[V, E, G]):
        """
        Called when the client provider is closed
        
        :param ghidra.graph.VisualGraphComponentProvider[V, E, G] provider: the provider
        """

    def providerOpened(self, provider: ghidra.graph.VisualGraphComponentProvider[V, E, G]):
        """
        Called when the client provider is opened
        
        :param ghidra.graph.VisualGraphComponentProvider[V, E, G] provider: the provider
        """

    def readConfigState(self, saveState: ghidra.framework.options.SaveState):
        """
        Called when the client wishes to restore configuration state.  Features can read state
        previously saved from a call to :meth:`writeConfigState(SaveState) <.writeConfigState>`.
        
        :param ghidra.framework.options.SaveState saveState: the container for state information
        """

    def remove(self):
        """
        Called when the provider is being disposed
        """

    def writeConfigState(self, state: ghidra.framework.options.SaveState):
        """
        Called when the client wishes to save configuration state.  Features can add any state
        they wish to be persisted over tool launches.
        
        :param ghidra.framework.options.SaveState state: the container for state information
        """


class VgSatelliteFeaturette(VisualGraphFeaturette[V, E, G], typing.Generic[V, E, G]):
    """
    A sub-feature that provides a satellite viewer to :obj:`VisualGraphComponentProvider`s
     
     
    Note: this class installs actions to manipulate the satellite view.  For these to be 
    correctly enabled, you must produce :obj:`VgActionContext` objects in your
    :meth:`VisualGraphComponentProvider.getActionContext(MouseEvent) <VisualGraphComponentProvider.getActionContext>` method.  Specifically, 
    the context returned must be a type of :obj:`VgActionContext`, with the 
    :meth:`VgActionContext.shouldShowSatelliteActions() <VgActionContext.shouldShowSatelliteActions>` returning true.
    """

    @typing.type_check_only
    class VgUndockedSatelliteProvider(docking.ComponentProvider):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, tool: docking.Tool, component: javax.swing.JComponent, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], windowGroup: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class SatelliteListener(ghidra.graph.viewer.GraphSatelliteListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SatellitePositionAction(docking.action.ToggleDockingAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], posiiton: ghidra.graph.viewer.GraphComponent.SatellitePosition, provider: docking.ComponentProvider):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def deselectAllSatellitePositions(self):
        ...

    def getSatelliteProvider(self) -> docking.ComponentProvider:
        ...

    @property
    def satelliteProvider(self) -> docking.ComponentProvider:
        ...



__all__ = ["VisualGraphFeaturette", "VgSatelliteFeaturette"]
