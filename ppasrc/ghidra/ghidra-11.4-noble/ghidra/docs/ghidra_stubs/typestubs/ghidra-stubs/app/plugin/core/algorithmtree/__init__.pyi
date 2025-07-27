from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.plugintool
import java.lang # type: ignore


class ModuleAlgorithmPlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.BlockModelServiceListener):
    """
    Applies the "module" algorithm to a Folder or Fragment. This algorithm first
    applies the Multiple Entry Point Subroutine model, which generates fragments;
    then the Partitioned Code Subroutine model is applied to the fragments.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def modelAdded(self, modeName: typing.Union[java.lang.String, str], modelType: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.services.BlockModelServiceListener.modelAdded(java.lang.String, int)`
        """

    def modelRemoved(self, modeName: typing.Union[java.lang.String, str], modelType: typing.Union[jpype.JInt, int]):
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.app.services.BlockModelServiceListener.modelRemoved(java.lang.String, int)`
        """



__all__ = ["ModuleAlgorithmPlugin"]
