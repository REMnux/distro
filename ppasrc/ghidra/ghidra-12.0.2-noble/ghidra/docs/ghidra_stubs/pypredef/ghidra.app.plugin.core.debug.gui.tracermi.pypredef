from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.debug.gui
import ghidra.framework.plugintool
import ghidra.trace.model.target.schema
import java.beans # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class RemoteMethodInvocationDialog(ghidra.app.plugin.core.debug.gui.AbstractDebuggerParameterDialog[ghidra.debug.api.tracermi.RemoteParameter]):

    class TraceObjectEditor(java.beans.PropertyEditorSupport):
        """
        TODO: Make this a proper editor which can browse and select objects of a required schema.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, ctx: ghidra.trace.model.target.schema.SchemaContext, title: typing.Union[java.lang.String, str], buttonText: typing.Union[java.lang.String, str], buttonIcon: javax.swing.Icon):
        ...



__all__ = ["RemoteMethodInvocationDialog"]
