from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data
import ghidra.trace.model
import ghidra.trace.model.guest


T = typing.TypeVar("T")


class TraceBasedDataTypeManager(ghidra.program.model.data.ProgramBasedDataTypeManager):
    """
    A data type manager which is part of a :obj:`Trace`
    """

    class_: typing.ClassVar[java.lang.Class]

    def addType(self, dataType: T, handler: ghidra.program.model.data.DataTypeConflictHandler) -> T:
        """
        TODO: Petition to have this replace
        :meth:`TraceBasedDataTypeManager.addDataType(DataType, DataTypeConflictHandler) <TraceBasedDataTypeManager.addDataType>`
         
         
        
        TODO: What happens if handler keeps existing? Does it return existing or null? If it returns
        the existing, then can we still cast to T? If not, then we have to be careful with this
        method. We may need to keep ``addDataType``, and have this one return null when the
        handler keeps the existing one.
        """

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform:
        """
        Get the platform for which this data type manager is provided
        
        :return: the platform
        :rtype: ghidra.trace.model.guest.TracePlatform
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace of which this data type manager is a part
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def replaceType(self, existingDt: ghidra.program.model.data.DataType, replacementDt: T, updateCategoryPath: typing.Union[jpype.JBoolean, bool]) -> T:
        """
        TODO: Petition to have this replace
        :meth:`TraceBasedDataTypeManager.replaceDataType(DataType, DataType, boolean) <TraceBasedDataTypeManager.replaceDataType>`
        """

    def resolveType(self, dataType: T, handler: ghidra.program.model.data.DataTypeConflictHandler) -> T:
        """
        TODO: Petition to have this replace
        :meth:`TraceBasedDataTypeManager.resolve(DataType, DataTypeConflictHandler) <TraceBasedDataTypeManager.resolve>`
         
         
        
        TODO: What happens if handler keeps existing? Does it return existing or null? If it returns
        the existing, then can we still cast to T? If not, then we have to be careful with this
        method. We may need to keep ``resolve``, and have this one return null when the handler
        keeps the existing one.
        """

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform:
        ...



__all__ = ["TraceBasedDataTypeManager"]
