from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import db.util
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class OldStackFrameDB(ghidra.program.model.listing.StackFrame):

    class_: typing.ClassVar[java.lang.Class]

    def clearVariable(self, offset: typing.Union[jpype.JInt, int]):
        """
        Clear the stack variable defined at offset
        
        :param jpype.JInt or int offset: Offset onto the stack to be cleared.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Returns whether some other stack frame is "equivalent to" this one.
        The stack frame is considered equal to another even if they are each
        part of a different function.
        """

    def getFrameSize(self) -> int:
        """
        Get the size of this stack frame in bytes.
        
        :return: stack frame size
        :rtype: int
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Get the function that this stack belongs to.
        
        :return: the function
        :rtype: ghidra.program.model.listing.Function
        """

    def getLocalSize(self) -> int:
        """
        Get the local portion of the stack frame in bytes.
        
        :return: local frame size
        :rtype: int
        """

    def getLocals(self) -> jpype.JArray[ghidra.program.model.listing.Variable]:
        """
        Get all defined local variables.
        
        :return: an array of all local variables
        :rtype: jpype.JArray[ghidra.program.model.listing.Variable]
        """

    def getParameterOffset(self) -> int:
        """
        Get the offset to the start of the parameters.
        
        :return: offset
        :rtype: int
        """

    def getParameterSize(self) -> int:
        """
        Get the parameter portion of the stack frame in bytes.
        
        :return: parameter frame size
        :rtype: int
        """

    def getParameters(self) -> jpype.JArray[ghidra.program.model.listing.Variable]:
        """
        Get all defined parameters.
        
        :return: an array of parameters.
        :rtype: jpype.JArray[ghidra.program.model.listing.Variable]
        """

    def getReturnAddressOffset(self) -> int:
        """
        Get the stack variable containing offset.  This may fall in
        the middle of a defined variable.
        
        :param offset: offset of on stack to get variable.
        """

    def getVariableContaining(self, offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Variable:
        """
        Get the stack variable containing offset.  This may fall in
        the middle of a defined variable.
        
        :param jpype.JInt or int offset: offset of on stack to get variable.
        """

    def growsNegative(self) -> bool:
        """
        A stack that grows negative has local references negative and
        parameter references positive.  A positive growing stack has
        positive locals and negative parameters.
        
        :return: true if the stack grows in a negative direction.
        :rtype: bool
        """

    def setLocalSize(self, size: typing.Union[jpype.JInt, int]):
        """
        Set the size of the local stack in bytes.
        
        :param jpype.JInt or int size: size of local stack
        """

    def setReturnAddressOffset(self, offset: typing.Union[jpype.JInt, int]):
        """
        Set the return address stack size.
        
        :param jpype.JInt or int offset: offset of return address.
        """

    @property
    def returnAddressOffset(self) -> jpype.JInt:
        ...

    @returnAddressOffset.setter
    def returnAddressOffset(self, value: jpype.JInt):
        ...

    @property
    def frameSize(self) -> jpype.JInt:
        ...

    @property
    def localSize(self) -> jpype.JInt:
        ...

    @localSize.setter
    def localSize(self, value: jpype.JInt):
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def parameterSize(self) -> jpype.JInt:
        ...

    @property
    def parameterOffset(self) -> jpype.JInt:
        ...

    @property
    def variableContaining(self) -> ghidra.program.model.listing.Variable:
        ...

    @property
    def parameters(self) -> jpype.JArray[ghidra.program.model.listing.Variable]:
        ...

    @property
    def locals(self) -> jpype.JArray[ghidra.program.model.listing.Variable]:
        ...


@typing.type_check_only
class OldFunctionDBAdapter(java.lang.Object):
    """
    Database adapter for functions.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldRegisterVariableDBAdapter(java.lang.Object):
    """
    Database adapter for register variables.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldFunctionDBAdapterV1(OldFunctionDBAdapter):

    class_: typing.ClassVar[java.lang.Class]

    def translateRecord(self, oldRecord: db.DBRecord) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.function.FunctionDBAdapter.translateRecord(ghidra.framework.store.db.DBRecord)`
        """


class OldFunctionManager(db.util.ErrorHandler):
    """
    This class only exists to support upgrading Ghidra Version 2.1 and earlier.
     
    
    **NOTE: Programmers should not use this class!**
    """

    @typing.type_check_only
    class OldFunctionIteratorDB(java.util.Iterator[OldFunctionDataDB]):
        """
        Function iterator class.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbHandle: db.DBHandle, errHandler: db.util.ErrorHandler, addrMap: ghidra.program.database.map.AddressMap):
        """
        Constructs a new OldFunctionManager.
        
        :param db.DBHandle dbHandle: data base handle
        :param db.util.ErrorHandler errHandler: the error handler
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :raises VersionException: if function manager's version does not match its expected version
        """

    def dispose(self):
        """
        Permanently discards all data resources associated with the old function manager.
        This should be invoked when an upgrade of all function data has been completed.
        
        :raises IOException:
        """

    def upgrade(self, upgradeProgram: ghidra.program.database.ProgramDB, monitor: ghidra.util.task.TaskMonitor):
        """
        Actually does the work of upgrading the old program function manager.
        
        :param ghidra.program.database.ProgramDB upgradeProgram: the program to upgrade
        :param ghidra.util.task.TaskMonitor monitor: the task monitor to allow the user to cancel the upgrade
        :raises CancelledException: if the user cancels the upgrade
        :raises IOException: if an i/o error occurs
        """


@typing.type_check_only
class OldFunctionParameter(ghidra.program.model.listing.ParameterImpl):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldFunctionDataDB(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getBody(self) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getBody()`
        """

    def getComment(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getComment()`
        """

    def getCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getCommentAsArray()`
        """

    def getEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getEntryPoint()`
        """

    def getKey(self) -> int:
        ...

    def getParameters(self) -> jpype.JArray[ghidra.program.model.listing.Parameter]:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getProgram()`
        """

    def getRepeatableComment(self) -> str:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getRepeatableComment()`
        """

    def getRepeatableCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getRepeatableCommentAsArray()`
        """

    def getReturnType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getReturnType()`
        """

    def getStackDepthChange(self) -> int:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getStackPurgeSize()`
        """

    def getStackFrame(self) -> ghidra.program.model.listing.StackFrame:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.model.listing.Function.getStackFrame()`
        """

    def isStackDepthValid(self) -> bool:
        ...

    @property
    def stackFrame(self) -> ghidra.program.model.listing.StackFrame:
        ...

    @property
    def commentAsArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def stackDepthChange(self) -> jpype.JInt:
        ...

    @property
    def repeatableComment(self) -> java.lang.String:
        ...

    @property
    def stackDepthValid(self) -> jpype.JBoolean:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def entryPoint(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def repeatableCommentAsArray(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def parameters(self) -> jpype.JArray[ghidra.program.model.listing.Parameter]:
        ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


@typing.type_check_only
class OldFunctionDBAdapterV0(OldFunctionDBAdapter):
    """
    Database adapter implementation for Functions.
    Handles three tables: Functions, Stack Variables, and Register Variables.
    """

    @typing.type_check_only
    class TranslatedRecordIterator(db.RecordIterator):

        class_: typing.ClassVar[java.lang.Class]

        def delete(self) -> bool:
            ...

        def hasNext(self) -> bool:
            ...

        def hasPrevious(self) -> bool:
            ...

        def next(self) -> db.DBRecord:
            ...

        def previous(self) -> db.DBRecord:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def translateRecord(self, oldRecord: db.DBRecord) -> db.DBRecord:
        """
        
        
        
        .. seealso::
        
            | :obj:`ghidra.program.database.function.FunctionDBAdapter.translateRecord(ghidra.framework.store.db.DBRecord)`
        """


@typing.type_check_only
class OldRegisterVariableDBAdapterV0(OldRegisterVariableDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldStackVariableDBAdapter(java.lang.Object):
    """
    Database adapter for stack variables.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldStackVariableDBAdapterV1(OldStackVariableDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldStackVariableDBAdapterV0(OldStackVariableDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class OldFunctionMapDB(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]



__all__ = ["OldStackFrameDB", "OldFunctionDBAdapter", "OldRegisterVariableDBAdapter", "OldFunctionDBAdapterV1", "OldFunctionManager", "OldFunctionParameter", "OldFunctionDataDB", "OldFunctionDBAdapterV0", "OldRegisterVariableDBAdapterV0", "OldStackVariableDBAdapter", "OldStackVariableDBAdapterV1", "OldStackVariableDBAdapterV0", "OldFunctionMapDB"]
