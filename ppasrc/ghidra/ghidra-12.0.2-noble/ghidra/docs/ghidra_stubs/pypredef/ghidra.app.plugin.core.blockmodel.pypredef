from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin
import ghidra.app.services
import ghidra.framework.options
import ghidra.framework.plugintool
import java.lang # type: ignore


class BlockModelServicePlugin(ghidra.app.plugin.ProgramPlugin, ghidra.app.services.BlockModelService, ghidra.framework.options.OptionsChangeListener):
    """
    Provides a service for tracking the selected basic/subroutine block models for a tool.
    Methods are provided for obtaining an instance of the active or arbitrary block model.
    A new model instance is always provided since the internal cache will quickly become
    stale based upon program changes.  The current model implementations do not handle
    program changes which would invalidate the cached blocks stored within the model.
     
    A single basic/sub model list is maintained since it is possible that some uses
    may utilize either type of block model.
    """

    @typing.type_check_only
    class BlockModelInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def optionsChanged(self, newOptions: ghidra.framework.options.ToolOptions, optionName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Handle an option change
        
        :param ghidra.framework.options.ToolOptions newOptions: options object containing the property that changed
        :param java.lang.String or str optionName: name of option that changed
        :param java.lang.Object oldValue: old value of the option
        :param java.lang.Object newValue: new value of the option
        """



__all__ = ["BlockModelServicePlugin"]
