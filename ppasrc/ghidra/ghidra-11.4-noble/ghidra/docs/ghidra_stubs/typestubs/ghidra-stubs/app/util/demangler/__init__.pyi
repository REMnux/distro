from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.classfinder
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class Demangled(java.lang.Object):
    """
    A unifying top-level interface for all :obj:`DemangledObject`s and :obj:`DemangledType`s
    
     
    This class and its children have many overlapping concepts that we wish to refine at a
    future date.  Below is a listing of known uses:
     
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |                             Method                             |                                             Description                                              |
    +================================================================+======================================================================================================+
    |:meth:`setMangledContext(MangledContext) <.setMangledContext>`  |                                                                                                      |
    |                                                                |Sets the mangled context in use since version 11.3.                                                   |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getMangledContext() <.getMangledContext>`                |                                                                                                      |
    |                                                                |The mangled context in use since version 11.3.                                                        |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getName() <.getName>`                                    |                                                                                                      |
    |                                                                |A 'safe' name that is the :meth:`getDemangledName() <.getDemangledName>`, but with some characters    |
    |                                                                |changed to be valid for use within Ghidra.                                                            |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getDemangledName() <.getDemangledName>`                  |                                                                                                      |
    |                                                                |The unmodified **name** that was set upon this object.                                                |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getNamespaceName() <.getNamespaceName>`                  |                                                                                                      |
    |                                                                |The 'safe' name of this object when it is used as a namespace name.   This usually has                |
    |                                                                |parameter and template information.  Further, some characters within templates and                    |
    |                                                                |function signatures are replaced, such as spaces and namespace separators.                            |
    |                                                                |                                                                                                      |
    |                                                                |                                                                                                      |
    |                                                                |Given this full demangled string: ``Foo::Bar::Baz<int>``, this method will return                     |
    |                                                                |``Baz<int>``.                                                                                         |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getNamespaceString() <.getNamespaceString>`              |                                                                                                      |
    |                                                                |This returns the unmodified name of this item, along with any unmodified parent                       |
    |                                                                |namespace names, all separated by a namespace delimiter.  Unlike                                      |
    |                                                                |:meth:`getNamespaceName() <.getNamespaceName>`, the spaces and internal namespace tokens will not be  |
    |                                                                |replaced.                                                                                             |
    |                                                                |                                                                                                      |
    |                                                                |                                                                                                      |
    |                                                                |Given this full demangled string: ``Foo::Bar::Baz<int>``, this method will return                     |
    |                                                                |``Foo::Bar::Baz<int>``.                                                                               |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getSignature() <.getSignature>`                          |                                                                                                      |
    |                                                                |Returns the complete string form of this object, with most known attributes.  For                     |
    |                                                                |functions, this will be a complete signature.                                                         |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    |:meth:`getOriginalDemangled() <.getOriginalDemangled>`          |                                                                                                      |
    |                                                                |The original unmodified demangled string.  This is the full demangled string returned                 |
    |                                                                |from the demangling service.                                                                          |
    |                                                                |                                                                                                      |
    +----------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDemangledName(self) -> str:
        """
        Returns the unmodified demangled name of this object. This name may contain whitespace
        and other characters not supported for symbol or data type creation.  See :meth:`getName() <.getName>`
        for the same name modified for use within Ghidra.
        
        :return: name of this DemangledObject
        :rtype: str
        """

    def getMangledContext(self) -> MangledContext:
        """
        Returns the mangled context
         
        
        This method currently has a ``default`` implementation so not to break existing
        class implementations.  However, at some point the ``default`` tag and implementation,
        which returns null, will be removed.  Thus, all implementers need to implement this method
        before the removal of the ``default``
        
        :return: the context or null if no context
        :rtype: MangledContext
        
        .. versionadded:: 11.3
        """

    def getMangledString(self) -> str:
        """
        Returns the original mangled string
        
        :return: the string
        :rtype: str
        """

    def getName(self) -> str:
        """
        Returns the demangled name of this object.
        NOTE: unsupported symbol characters, like whitespace, will be converted to an underscore.
        
        :return: name of this DemangledObject with unsupported characters converted to underscore
        :rtype: str
        
        .. seealso::
        
            | :obj:`.getDemangledName()`
        """

    def getNamespace(self) -> Demangled:
        """
        Returns the namespace containing this demangled object
        
        :return: the namespace containing this demangled object
        :rtype: Demangled
        """

    def getNamespaceName(self) -> str:
        """
        Returns this object's namespace name without the fully-qualified parent path. The
        value returned here may have had some special characters replaced, such as ' ' replaced
        with '_' and '::' replaced with '--'.
        
        :return: the name
        :rtype: str
        """

    def getNamespaceString(self) -> str:
        """
        Returns a representation of this object as fully-qualified namespace.  The
        value returned here may have had some special characters replaced, such as ' ' replaced
        with '_' and '::' replaced with '--'.
        
        :return: the full namespace
        :rtype: str
        """

    def getOriginalDemangled(self) -> str:
        """
        Returns the original demangled string returned by the demangling service
        
        :return: the original demangled string
        :rtype: str
        """

    def getSignature(self) -> str:
        """
        Generates a complete representation of this object to include all know attributes of this
        object
        
        :return: the signature
        :rtype: str
        """

    def setMangledContext(self, mangledContextArg: MangledContext):
        """
        Sets the mangled context
         
        
        This method currently has a ``default`` implementation so not to break existing
        class implementations.  However, at some point the ``default`` tag and implementation,
        which is empty, will be removed.  Thus, all implementers need to implement this method
        before the removal of the ``default``
        
        :param MangledContext mangledContextArg: the mangled context
        
        .. versionadded:: 11.3
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name for this object
        
        :param java.lang.String or str name: the name
        """

    def setNamespace(self, ns: Demangled):
        """
        Sets the namespace of this demangled object
        
        :param Demangled ns: the namespace
        """

    @property
    def originalDemangled(self) -> java.lang.String:
        ...

    @property
    def demangledName(self) -> java.lang.String:
        ...

    @property
    def signature(self) -> java.lang.String:
        ...

    @property
    def mangledString(self) -> java.lang.String:
        ...

    @property
    def namespace(self) -> Demangled:
        ...

    @namespace.setter
    def namespace(self, value: Demangled):
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @name.setter
    def name(self, value: java.lang.String):
        ...

    @property
    def namespaceString(self) -> java.lang.String:
        ...

    @property
    def namespaceName(self) -> java.lang.String:
        ...

    @property
    def mangledContext(self) -> MangledContext:
        ...

    @mangledContext.setter
    def mangledContext(self, value: MangledContext):
        ...


class DemangledThunk(DemangledObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], thunkedFunctionObject: DemangledFunction):
        ...

    def setCovariantReturnThunk(self):
        ...

    def setSignaturePrefix(self, prefix: typing.Union[java.lang.String, str]):
        ...


class DemangledList(java.util.ArrayList[Demangled], Demangled):
    """
    An convenience :obj:`Demangled` object that holds a :obj:`List` of other 
    :obj:`Demangled` objects
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, demangledList: java.util.List[Demangled]):
        """
        Creates a :obj:`DemangledList` and adds the given :obj:`List` to it
        
        :param java.util.List[Demangled] demangledList: The :obj:`List` of :obj:`Demangled` objects to add
        """

    def containsNull(self) -> bool:
        """
        :return: true if this contains any ``null`` elements; otherwise, false
        :rtype: bool
        """


class DemangledString(DemangledObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], string: typing.Union[java.lang.String, str], length: typing.Union[jpype.JInt, int], unicode: typing.Union[jpype.JBoolean, bool]):
        """
        Construct demangled string.
        
        :param java.lang.String or str mangled: the source mangled string
        :param java.lang.String or str originalDemangled: the original demangled string
        :param java.lang.String or str name: name associated with this object
        :param java.lang.String or str string: string text associated with this object or null.  This is used to establish
        label and plate comment if specified.  If null, name will be used as symbol name.
        :param jpype.JInt or int length: length of string or -1.  Actual string data type applied currently
        assumes null terminated string.
        :param jpype.JBoolean or bool unicode: true if string is a Unicode string.
        """

    def getLength(self) -> int:
        """
        Returns the length in bytes of the demangled string.
        
        :return: the length in bytes of the demangled string
        :rtype: int
        """

    def getString(self) -> str:
        """
        Returns the demangled string.
        
        :return: the demangled string
        :rtype: str
        """

    def isUnicode(self) -> bool:
        """
        Returns true if the demangled string is unicode.
        
        :return: true if the demangled string is unicode
        :rtype: bool
        """

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def unicode(self) -> jpype.JBoolean:
        ...


class DemangledFunction(DemangledObject):
    """
    A class to represent a demangled function.
    """

    class_: typing.ClassVar[java.lang.Class]
    VOLATILE: typing.Final = "volatile"
    CONST: typing.Final = "const"
    PTR64: typing.Final = "__ptr64"
    UNALIGNED: typing.Final = "__unaligned"
    RESTRICT: typing.Final = "__restrict"

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Create a :obj:`DemangledFunction` instance which is marked with a 
        signature :obj:`SourceType` of :obj:`SourceType.ANALYSIS` which will be used
        when function signatures are applied to a program.  This source type may be changed
        if needed using :meth:`setSignatureSourceType(SourceType) <.setSignatureSourceType>`.  
        The function name and namespace is always applied using a symbol source
        of :obj:`SourceType.ANALYSIS`.
        
        :param java.lang.String or str mangled: original mangled symbol name
        :param java.lang.String or str originalDemangled: demangled function signature generally used when generating comments
        :param java.lang.String or str name: demangled function name
        """

    def addParameter(self, parameter: DemangledParameter):
        ...

    def addParameters(self, params: java.util.List[DemangledParameter]):
        ...

    def getCallingConvention(self) -> str:
        """
        Returns the calling convention or null, if unspecified.
        
        :return: the calling convention or null, if unspecified
        :rtype: str
        """

    def getParameterString(self) -> str:
        ...

    def getParameters(self) -> java.util.List[DemangledParameter]:
        ...

    def getReturnType(self) -> DemangledDataType:
        """
        Returns the return type or null, if unspecified.
        
        :return: the return type or null, if unspecified
        :rtype: DemangledDataType
        """

    def getSignatureSourceType(self) -> ghidra.program.model.symbol.SourceType:
        """
        Get the signature source type which is used when applying the function signature
        to a program. A value of :obj:`SourceType.DEFAULT` indicates that 
        function return and parameters should not be applied.
        
        :return: signature source type
        :rtype: ghidra.program.model.symbol.SourceType
        """

    def getTemplate(self) -> DemangledTemplate:
        ...

    def isTrailingConst(self) -> bool:
        ...

    def isTrailingPointer64(self) -> bool:
        ...

    def isTrailingRestrict(self) -> bool:
        ...

    def isTrailingUnaligned(self) -> bool:
        ...

    def isTrailingVolatile(self) -> bool:
        ...

    def isTypeCast(self) -> bool:
        ...

    def setCallingConvention(self, callingConvention: typing.Union[java.lang.String, str]):
        """
        Sets the function calling convention. For example, "__cdecl".
        
        :param java.lang.String or str callingConvention: the function calling convention
        """

    def setOverloadedOperator(self, isOverloadedOperator: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether this demangled function represents
        an overloaded operator. For example, "operator+()".
        
        :param jpype.JBoolean or bool isOverloadedOperator: true if overloaded operator
        """

    def setReturnType(self, returnType: DemangledDataType):
        """
        Sets the function return type.
        
        :param DemangledDataType returnType: the function return type
        """

    def setSignatureSourceType(self, signatureSourceType: ghidra.program.model.symbol.SourceType):
        """
        Set signature :obj:`SourceType` of :obj:`SourceType.ANALYSIS` which will be used
        when function signatures are applied to a program.  Specifying :obj:`SourceType.DEFAULT` 
        will prevent function return and parameters from being applied but will still apply
        calling convention name if specified.
        
        :param ghidra.program.model.symbol.SourceType signatureSourceType: signature source type
        """

    def setTemplate(self, template: DemangledTemplate):
        ...

    def setTemplatedConstructorType(self, type: typing.Union[java.lang.String, str]):
        """
        Special constructor where it has a templated type before the parameter list
        
        :param java.lang.String or str type: the type
        """

    def setThrowAttribute(self, throwAttribute: typing.Union[java.lang.String, str]):
        ...

    def setTrailingConst(self):
        ...

    def setTrailingPointer64(self):
        ...

    def setTrailingRestrict(self):
        ...

    def setTrailingUnaligned(self):
        ...

    def setTrailingVolatile(self):
        ...

    def setTypeCast(self):
        ...

    @property
    def template(self) -> DemangledTemplate:
        ...

    @template.setter
    def template(self, value: DemangledTemplate):
        ...

    @property
    def trailingVolatile(self) -> jpype.JBoolean:
        ...

    @property
    def callingConvention(self) -> java.lang.String:
        ...

    @callingConvention.setter
    def callingConvention(self, value: java.lang.String):
        ...

    @property
    def trailingPointer64(self) -> jpype.JBoolean:
        ...

    @property
    def trailingRestrict(self) -> jpype.JBoolean:
        ...

    @property
    def typeCast(self) -> jpype.JBoolean:
        ...

    @property
    def trailingConst(self) -> jpype.JBoolean:
        ...

    @property
    def trailingUnaligned(self) -> jpype.JBoolean:
        ...

    @property
    def parameterString(self) -> java.lang.String:
        ...

    @property
    def parameters(self) -> java.util.List[DemangledParameter]:
        ...

    @property
    def returnType(self) -> DemangledDataType:
        ...

    @returnType.setter
    def returnType(self, value: DemangledDataType):
        ...

    @property
    def signatureSourceType(self) -> ghidra.program.model.symbol.SourceType:
        ...

    @signatureSourceType.setter
    def signatureSourceType(self, value: ghidra.program.model.symbol.SourceType):
        ...


class MangledContext(java.lang.Object):
    """
    A simple class to contain the context of a mangled symbol for demangling
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, options: DemanglerOptions, mangled: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address):
        """
        Constructor for mangled context
        
        :param ghidra.program.model.listing.Program program: the program; can be null
        :param DemanglerOptions options: the demangler options
        :param java.lang.String or str mangled: the mangled string
        :param ghidra.program.model.address.Address address: the address; can be null
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address
        
        :return: the address; can be null
        :rtype: ghidra.program.model.address.Address
        """

    def getMangled(self) -> str:
        """
        Returns the mangled string
        
        :return: the mangled string
        :rtype: str
        """

    def getOptions(self) -> DemanglerOptions:
        """
        Returns the demangler options
        
        :return: the options
        :rtype: DemanglerOptions
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program
        
        :return: the program; can be null
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def mangled(self) -> java.lang.String:
        ...

    @property
    def options(self) -> DemanglerOptions:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class AbstractDemangledFunctionDefinitionDataType(DemangledDataType):
    """
    Parent base class for types that represent things that refer to functions
    """

    class_: typing.ClassVar[java.lang.Class]

    def addParameter(self, parameter: DemangledDataType):
        """
        Adds a parameters to the end of the parameter list for this demangled function
        
        :param DemangledDataType parameter: the new parameter to add
        """

    def getCallingConvention(self) -> str:
        """
        Returns the calling convention or null, if unspecified
        
        :return: the calling convention or null, if unspecified
        :rtype: str
        """

    def getParameters(self) -> java.util.List[DemangledDataType]:
        """
        Returns a list of the parameters for this demangled functions.
        
        :return: a list of the parameters for this demangled functions
        :rtype: java.util.List[DemangledDataType]
        """

    def getReturnType(self) -> DemangledDataType:
        """
        Returns the return type
        
        :return: the return type
        :rtype: DemangledDataType
        """

    def isConstPointer(self) -> bool:
        ...

    def isTrailingPointer64(self) -> bool:
        ...

    def isTrailingRestrict(self) -> bool:
        ...

    def isTrailingUnaligned(self) -> bool:
        ...

    def setCallingConvention(self, callingConvention: typing.Union[java.lang.String, str]):
        """
        Sets the function calling convention. For example, "__cdecl"
        
        :param java.lang.String or str callingConvention: the function calling convention
        """

    def setConstPointer(self):
        ...

    def setModifier(self, modifier: typing.Union[java.lang.String, str]):
        """
        Sets the function __ modifier. For example, "namespace::".
        
        :param java.lang.String or str modifier: the function modifier
        """

    def setReturnType(self, returnType: DemangledDataType):
        """
        Sets the return type
        
        :param DemangledDataType returnType: the return type
        """

    def setTrailingPointer64(self):
        ...

    def setTrailingRestrict(self):
        ...

    def setTrailingUnaligned(self):
        ...

    def toSignature(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    @property
    def constPointer(self) -> jpype.JBoolean:
        ...

    @property
    def callingConvention(self) -> java.lang.String:
        ...

    @callingConvention.setter
    def callingConvention(self, value: java.lang.String):
        ...

    @property
    def trailingPointer64(self) -> jpype.JBoolean:
        ...

    @property
    def trailingUnaligned(self) -> jpype.JBoolean:
        ...

    @property
    def parameters(self) -> java.util.List[DemangledDataType]:
        ...

    @property
    def trailingRestrict(self) -> jpype.JBoolean:
        ...

    @property
    def returnType(self) -> DemangledDataType:
        ...

    @returnType.setter
    def returnType(self, value: DemangledDataType):
        ...


class DemangledObject(Demangled):
    """
    A class to represent a demangled object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def applyPlateCommentOnly(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> bool:
        """
        
        
        :param ghidra.program.model.listing.Program program: The program for which to apply the comment
        :param ghidra.program.model.address.Address address: The address for the comment
        :return: ``true`` if a comment was applied
        :rtype: bool
        :raises java.lang.Exception: if the symbol could not be demangled or if the address is invalid
        """

    def applyTo(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, options: DemanglerOptions, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Apply this demangled object detail to the specified program.
         
        
        NOTE: An open Program transaction must be established prior to invoking this method.
        
        :param ghidra.program.model.listing.Program program: program to which demangled data should be applied.
        :param ghidra.program.model.address.Address address: address which corresponds to this demangled object
        :param DemanglerOptions options: options which control how demangled data is applied
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if successfully applied, else false
        :rtype: bool
        :raises java.lang.Exception: if an error occurs during the apply operation
        """

    def applyUsingContext(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Apply this demangled object detail to the specified program.  This method only works
        if the :obj:`MangledContext` was set with the appropriate constructor or with the
        :meth:`setMangledContext(MangledContext) <.setMangledContext>` method
         
        
        NOTE: An open Program transaction must be established prior to invoking this method.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :return: true if successfully applied, else false
        :rtype: bool
        :raises java.lang.Exception: if an error occurs during the apply operation or if the context is null
        """

    @staticmethod
    def createNamespace(program: ghidra.program.model.listing.Program, typeNamespace: Demangled, parentNamespace: ghidra.program.model.symbol.Namespace, functionPermitted: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Namespace:
        """
        Get or create the specified typeNamespace.  The returned namespace may only be a partial
        namespace if errors occurred.  The caller should check the returned namespace and adjust
        any symbol creation accordingly.
        
        :param ghidra.program.model.listing.Program program: the program
        :param Demangled typeNamespace: demangled namespace
        :param ghidra.program.model.symbol.Namespace parentNamespace: root namespace to be used (e.g., library, global, etc.)
        :param jpype.JBoolean or bool functionPermitted: if true an existing function may be used as a namespace
        :return: namespace or partial namespace if error occurs
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def demangledNameSuccessfully(self) -> bool:
        """
        Returns the success state of converting a mangled String into a demangled String
        
        :return: true succeeded creating demangled String
        :rtype: bool
        """

    def getBasedName(self) -> str:
        ...

    def getErrorMessage(self) -> str:
        """
        Returns the error message that can be set when an error is encountered, but which is made
        available to the calling method to get details of the error beyond boolean value that is
        returned by :meth:`applyTo(Program, Address, DemanglerOptions,TaskMonitor) <.applyTo>`.
        
        :return: a message pertaining to issues encountered in the apply methods.  Can be null
        :rtype: str
        """

    def getMemberScope(self) -> str:
        ...

    def getRawDemangled(self) -> str:
        """
        Returns the raw demangled string.  This is the value returned from the demangler before any 
        simplifications or transformations have been made.
        
        :return: the string
        :rtype: str
        """

    def getSignature(self, format: typing.Union[jpype.JBoolean, bool]) -> str:
        """
        Returns a complete signature for the demangled symbol.
         
        For example:
                    "unsigned long foo"
                    "unsigned char * ClassA::getFoo(float, short *)"
                    "void * getBar(int **, MyStruct &)"
         
        **Note: based on the underlying mangling scheme, the
        return type may or may not be specified in the signature.**
        
        :param jpype.JBoolean or bool format: true if signature should be pretty printed
        :return: a complete signature for the demangled symbol
        :rtype: str
        """

    def getSpecialPrefix(self) -> str:
        ...

    def getStorageClass(self) -> str:
        ...

    def getVisibility(self) -> str:
        ...

    def isConst(self) -> bool:
        ...

    def isPointer64(self) -> bool:
        ...

    def isRestrict(self) -> bool:
        ...

    def isStatic(self) -> bool:
        ...

    def isThunk(self) -> bool:
        ...

    def isUnaligned(self) -> bool:
        ...

    def isVirtual(self) -> bool:
        ...

    def isVolatile(self) -> bool:
        ...

    def setBackupPlateComment(self, plateComment: typing.Union[java.lang.String, str]):
        """
        Sets the plate comment to be used if the :meth:`getOriginalDemangled() <.getOriginalDemangled>` string is not
        available
        
        :param java.lang.String or str plateComment: the plate comment text
        """

    def setBasedName(self, basedName: typing.Union[java.lang.String, str]):
        ...

    def setConst(self, isConst: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMemberScope(self, memberScope: typing.Union[java.lang.String, str]):
        ...

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name of the demangled object
        
        :param java.lang.String or str name: the new name
        """

    def setOriginalDemangled(self, originalDemangled: typing.Union[java.lang.String, str]):
        """
        Sets the original demangled string.  This is useful for clients that reuse constructed
        demangled objects for special case constructs.
         
        
        Note: this method is not on the interface
        
        :param java.lang.String or str originalDemangled: the new original demangled string
        """

    def setPointer64(self, isPointer64: typing.Union[jpype.JBoolean, bool]):
        ...

    def setRawDemangledString(self, s: typing.Union[java.lang.String, str]):
        """
        Sets the raw demangled string.  This is the value returned from the demangler before any 
        simplifications or transformations have been made.
        
        :param java.lang.String or str s: the string
        """

    def setRestrict(self):
        ...

    def setSpecialPrefix(self, special: typing.Union[java.lang.String, str]):
        ...

    def setStatic(self, isStatic: typing.Union[jpype.JBoolean, bool]):
        ...

    def setStorageClass(self, storageClass: typing.Union[java.lang.String, str]):
        ...

    def setThunk(self, isThunk: typing.Union[jpype.JBoolean, bool]):
        ...

    def setUnaligned(self):
        ...

    def setVirtual(self, isVirtual: typing.Union[jpype.JBoolean, bool]):
        ...

    def setVisibilty(self, visibility: typing.Union[java.lang.String, str]):
        ...

    def setVolatile(self, isVolatile: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def virtual(self) -> jpype.JBoolean:
        ...

    @virtual.setter
    def virtual(self, value: jpype.JBoolean):
        ...

    @property
    def rawDemangled(self) -> java.lang.String:
        ...

    @property
    def static(self) -> jpype.JBoolean:
        ...

    @static.setter
    def static(self, value: jpype.JBoolean):
        ...

    @property
    def const(self) -> jpype.JBoolean:
        ...

    @const.setter
    def const(self, value: jpype.JBoolean):
        ...

    @property
    def visibility(self) -> java.lang.String:
        ...

    @property
    def signature(self) -> java.lang.String:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...

    @volatile.setter
    def volatile(self, value: jpype.JBoolean):
        ...

    @property
    def unaligned(self) -> jpype.JBoolean:
        ...

    @property
    def restrict(self) -> jpype.JBoolean:
        ...

    @property
    def thunk(self) -> jpype.JBoolean:
        ...

    @thunk.setter
    def thunk(self, value: jpype.JBoolean):
        ...

    @property
    def basedName(self) -> java.lang.String:
        ...

    @basedName.setter
    def basedName(self, value: java.lang.String):
        ...

    @property
    def storageClass(self) -> java.lang.String:
        ...

    @storageClass.setter
    def storageClass(self, value: java.lang.String):
        ...

    @property
    def pointer64(self) -> jpype.JBoolean:
        ...

    @pointer64.setter
    def pointer64(self, value: jpype.JBoolean):
        ...

    @property
    def memberScope(self) -> java.lang.String:
        ...

    @memberScope.setter
    def memberScope(self, value: java.lang.String):
        ...

    @property
    def specialPrefix(self) -> java.lang.String:
        ...

    @specialPrefix.setter
    def specialPrefix(self, value: java.lang.String):
        ...


class DemangledVariable(DemangledObject):
    """
    An interface to represent a demangled global variable.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...

    def getDataType(self) -> DemangledDataType:
        """
        Returns the data type of this variable.
        
        :return: the data type of this variable
        :rtype: DemangledDataType
        """

    def setDatatype(self, datatype: DemangledDataType):
        ...

    @property
    def dataType(self) -> DemangledDataType:
        ...


class DemangledLabel(DemangledObject):
    """
    A class to represent a :obj:`DemangledObject` that should get represented as a Ghidra label
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Creates a new :obj:`DemangledLabel`
        
        :param java.lang.String or str mangled: The mangled string
        :param java.lang.String or str originalDemangled: The natively demangled string
        :param java.lang.String or str name: The label name
        """


class DemangledFunctionPointer(AbstractDemangledFunctionDefinitionDataType):
    """
    A class to represent a demangled function pointer
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str]):
        ...

    def setDisplayDefaultFunctionPointerSyntax(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Signals whether to display function pointer syntax when there is no function name, which 
        is '``(*)``', such as found in this example '``void (*)()``'.  the default is true
        
        :param jpype.JBoolean or bool b: true to display nameless function pointer syntax; false to not display
        """


class DemangledParameter(java.lang.Object):
    """
    A class to represent a demangled function parameter.
     
    
    This extends :obj:`DemangledDataType` in order to associate an optional parameter label with
    its data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, type: DemangledDataType):
        """
        Creates a new :obj:`DemangledParameter` with the given type and no label
        
        :param DemangledDataType type: The parameter type
        """

    def getLabel(self) -> str:
        """
        :return: the parameter's label (could be null)
        :rtype: str
        """

    def getType(self) -> DemangledDataType:
        """
        :return: the parameter's type
        :rtype: DemangledDataType
        """

    def setLabel(self, label: typing.Union[java.lang.String, str]):
        """
        Sets the parameter's label
        
        :param java.lang.String or str label: The label (null for no label)
        """

    @property
    def label(self) -> java.lang.String:
        ...

    @label.setter
    def label(self, value: java.lang.String):
        ...

    @property
    def type(self) -> DemangledDataType:
        ...


class DemanglerOptions(java.lang.Object):
    """
    A simple class to contain the various settings for demangling
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, copy: DemanglerOptions):
        ...

    def applyCallingConvention(self) -> bool:
        """
        Checks if the apply function signature calling convention option is currently set
        
        :return: true if set to apply calling conventions
        :rtype: bool
        """

    def applySignature(self) -> bool:
        """
        Checks if the apply signature option is currently set
        
        :return: true if set to apply function signatures that are demangled
        :rtype: bool
        """

    def demangleOnlyKnownPatterns(self) -> bool:
        """
        Checks if the option to only demangle known mangled patterns is set
        
        :return: true if only known mangled patterns will be demangled
        :rtype: bool
        """

    def doDisassembly(self) -> bool:
        """
        Checks if the option to perform disassembly for known data structures (like functions) when
        demangling is set
        
        :return: true if the option is set
        :rtype: bool
        """

    def setApplyCallingConvention(self, applyCallingConvention: typing.Union[jpype.JBoolean, bool]):
        """
        Set the option to apply function signature calling conventions
        
        :param jpype.JBoolean or bool applyCallingConvention: true to apply calling conventions
        """

    def setApplySignature(self, applySignature: typing.Union[jpype.JBoolean, bool]):
        """
        Set the option to apply function signatures that are demangled
        
        :param jpype.JBoolean or bool applySignature: true to apply function signatures that are demangled
        """

    def setDemangleOnlyKnownPatterns(self, demangleOnlyKnownPatterns: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the option to only demangle known mangled patterns. Setting this to false causes
        most symbols to be demangled, which may result in some symbols getting demangled that were
        not actually mangled symbols.
        
         
        Generally, a demangler will report an error if a symbol fails to demangle.   Hence,
        clients can use this flag to prevent such errors, signalling to the demangler to only
        attempt those symbols that have a known start pattern.  If the known start pattern list
        becomes comprehensive, then this flag can go away.
        
        :param jpype.JBoolean or bool demangleOnlyKnownPatterns: true to only demangle known mangled patterns
        """

    def setDoDisassembly(self, doDisassembly: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the option to perform disassembly for known data structures (like functions) when
        demangling
        
        :param jpype.JBoolean or bool doDisassembly: true to perform disassembly when demangling
        """


class Demangler(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL DEMANGLER CLASSES MUST END IN "Demangler".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def canDemangle(self, program: ghidra.program.model.listing.Program) -> bool:
        ...

    def createDefaultOptions(self) -> DemanglerOptions:
        """
        Creates default options for this particular demangler
        
        :return: the options
        :rtype: DemanglerOptions
        """

    def createMangledContext(self, mangled: typing.Union[java.lang.String, str], options: DemanglerOptions, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> MangledContext:
        """
        Creates a mangled context
        
        :param java.lang.String or str mangled: the mangled name
        :param DemanglerOptions options: the demangler options; if null, the default options are created
        :param ghidra.program.model.listing.Program program: the program; can be null
        :param ghidra.program.model.address.Address address: the address for the name in the program; can be null
        :return: the mangled context
        :rtype: MangledContext
        """

    @typing.overload
    def demangle(self, mangled: typing.Union[java.lang.String, str]) -> DemangledObject:
        """
        Attempts to demangle the given string using a context
        (:meth:`createMangledContext(String, DemanglerOptions, Program, Address) <.createMangledContext>` with
        default options (:meth:`createDefaultOptions() <.createDefaultOptions>`.
        
        :param java.lang.String or str mangled: the mangled string
        :return: the result; ``null`` is possible if the mangled string is not supported
        :rtype: DemangledObject
        :raises DemangledException: if the string cannot be demangled
        """

    @typing.overload
    @deprecated("Use demangle(String) or demangle(MangledContext).")
    def demangle(self, mangled: typing.Union[java.lang.String, str], options: DemanglerOptions) -> DemangledObject:
        """
        Attempts to demangle the given string using the given options
        
        :param java.lang.String or str mangled: the mangled string
        :param DemanglerOptions options: the options
        :return: the result; ``null`` is possible if the mangled string is not supported
        :rtype: DemangledObject
        :raises DemangledException: if the string cannot be demangled
        
        .. deprecated::
        
        Use :meth:`demangle(String) <.demangle>` or :meth:`demangle(MangledContext) <.demangle>`.
        """

    @typing.overload
    def demangle(self, context: MangledContext) -> DemangledObject:
        """
        Attempts to demangle the string of the mangled context and sets the mangled context on
        the :obj:`DemangledObject`
        
        :param MangledContext context: the mangled context
        :return: the result; ``null`` is possible if the mangled string is not supported
        :rtype: DemangledObject
        :raises DemangledException: if the string cannot be demangled
        """


class DemangledUnknown(DemangledObject):
    """
    An interface to represent an unknown entity that we are demangling.  We want to
    represent it in some sort of demangled form in a plate comment, but we do not
    know what to lay down yet, or we haven't yet engineered the item that can be
    laid down.  If the entity has a variable name, then we would probably make it a
    DemangledVariable instead of a DemangledUnknown.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...


class DemangledFunctionIndirect(AbstractDemangledFunctionDefinitionDataType):
    """
    A class to represent a demangled function indirect.  A function indirect is
    similar to a function pointer or a function reference except that it does
    not have the start (*) for a pointer or ampersand (&) for a reference, but
    is still an indirect definition (not a regular function definition).  The
    function indirect is prevalent in the Microsoft model, if not other models.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str]):
        ...


class DemangledLambda(DemangledFunction):
    """
    Represents a demangled lambda function
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...


class CharacterIterator(java.lang.Object):
    """
    A class for bidirectional iteration over a string.
     
    Iterators maintain a current character index, whose valid range is from
    0 to string.length()-1.
     
    The current index can be retrieved by calling getIndex() and set directly
    by calling setIndex().
     
    The methods previous() and next() are used for iteration. They return DONE if
    they would move outside the range from 0 to string.length()-1.
    """

    class_: typing.ClassVar[java.lang.Class]
    DONE: typing.Final = '\uffff'
    """
    Constant that is returned when the iterator has reached either the end
    or the beginning of the text. The value is '\\uFFFF', the "not a
    character" value which should not occur in any valid Unicode string.
    """


    def __init__(self, str: typing.Union[java.lang.String, str]):
        """
        Constructs a new character iterator using str.
        
        :param java.lang.String or str str: the string to iterate
        """

    def find(self, c: typing.Union[jpype.JChar, int, str]) -> int:
        """
        Looks for the next occurrence of 'c' starting
        at the current index. Returns the character
        position in the underlying string or -1 if 'c'
        is not found.
        """

    def getAndIncrement(self) -> str:
        """
        Returns the character at the current index and then increments the index by one.  
        If the resulting index is greater or equal
        to the end index, the current index is reset to the end index and
        a value of DONE is returned.
        
        :return: the character at the new position or DONE
        :rtype: str
        """

    def getIndex(self) -> int:
        """
        Returns the current index.
        
        :return: the current index.
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Returns the length of the iterator.
        
        :return: the length of the iterator
        :rtype: int
        """

    def getString(self) -> str:
        """
        Returns the underlying string.
        
        :return: the underlying string
        :rtype: str
        """

    def hasNext(self) -> bool:
        """
        Returns true if there are more characters to read.
        
        :return: true if there are more characters to read
        :rtype: bool
        """

    def next(self) -> str:
        """
        Increments the current index by one and returns the character
        at the new index.  If the resulting index is greater or equal
        to the end index, the current index is reset to the end index and
        a value of DONE is returned.
        
        :return: the character at the new position or DONE
        :rtype: str
        """

    def nextInteger(self) -> int:
        """
        Returns the next integer. The radix must be 10 (decimal).
        For example, given "...12fred..". If current index is pointing
        to the '1', then this value will return 12.
        
        :return: the next base-10 integer.
        :rtype: int
        """

    def nextString(self, len: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the next ascii string of the specified length starting
        at the current index.
        
        :param jpype.JInt or int len: the length of the string to read
        :return: the next ascii string
        :rtype: str
        """

    @typing.overload
    def peek(self) -> str:
        """
        Returns the next character without incrementing the current index.
        
        :return: the next character without incrementing the current index
        :rtype: str
        """

    @typing.overload
    def peek(self, lookAhead: typing.Union[jpype.JInt, int]) -> str:
        """
        Peeks at the character current index + lookAhead.
        Returns DONE if the computed position is out of range.
        
        :param jpype.JInt or int lookAhead: number of characters to look ahead
        :return: the character at index+lookAhead
        :rtype: str
        """

    def previous(self) -> str:
        """
        Decrements the current index by one and returns the character
        at the new index. If the current index is 0, the index
        remains at 0 and a value of DONE is returned.
        
        :return: the character at the new position or DONE
        :rtype: str
        """

    def setIndex(self, index: typing.Union[jpype.JInt, int]):
        """
        Sets the position to the specified position in the text.
        
        :param jpype.JInt or int index: the position within the text.
        """

    @property
    def string(self) -> java.lang.String:
        ...

    @property
    def andIncrement(self) -> jpype.JChar:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @index.setter
    def index(self, value: jpype.JInt):
        ...


class DemangledAddressTable(DemangledObject):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], calculateLength: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param java.lang.String or str mangled: the source mangled string
        :param java.lang.String or str originalDemangled: the original demangled string
        :param java.lang.String or str name: the name of the address table
        :param jpype.JBoolean or bool calculateLength: true if the length of this address table should be calculated at
                analysis time
        """

    def getLength(self) -> int:
        """
        Returns the length of the address table.
        -1 indicates the length is unknown.
        
        :return: the length of the address table
        :rtype: int
        """

    @property
    def length(self) -> jpype.JInt:
        ...


class DemangledNamespaceNode(Demangled):
    """
    Represents a plain namespace node that is not a type or method
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str mangled: as a refined a piece of the (larger) original mangled stream as the user
        can provide, though many times the larger piece is all that the user can provide
        :param java.lang.String or str originalDemangled: the original demangled string to match mangled string with the
        same caveats
        :param java.lang.String or str name: the name of the namespace node
        """


class DemangledException(java.lang.Exception):
    """
    A class to handle exceptions that occur demangling.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, cause: java.lang.Exception):
        """
        Use this constructor to indicate a demangler exception
        due to an exception thrown during the demangling process.
        
        :param java.lang.Exception cause: the exception thrown during the demangling process
        """

    @typing.overload
    def __init__(self, message: typing.Union[java.lang.String, str]):
        """
        Use this constructor to indicate a demangler exception
        due to some general invalid or unsupported mangled string
        characteristic. For example, unrecognized datatype.
        
        :param java.lang.String or str message: the invalid or unsupported mangled message
        """

    @typing.overload
    def __init__(self, invalidMangledName: typing.Union[jpype.JBoolean, bool]):
        """
        Use this constructor to indicate the demangler failed
        because the string to demangle does not appear to represent
        a valid mangled name.
        
        :param jpype.JBoolean or bool invalidMangledName: true to indicate the string to 
        demangle does not appear to represent a valid mangled name
        """

    def isInvalidMangledName(self) -> bool:
        """
        Returns true if the string to demangle does not appear to represent
        a valid mangled name
        
        :return: true if the string to demangle does not appear to represent
        a valid mangled name
        :rtype: bool
        """

    @property
    def invalidMangledName(self) -> jpype.JBoolean:
        ...


class DemangledDataType(DemangledType):
    """
    A class to represent a demangled data type.
    """

    class_: typing.ClassVar[java.lang.Class]
    SPACE: typing.Final = ' '
    UNSIGNED: typing.Final = "unsigned"
    SIGNED: typing.Final = "signed"
    ARR_NOTATION: typing.Final = "[]"
    REF_NOTATION: typing.Final = "&"
    RIGHT_REF_NOTATION: typing.Final = "&&"
    PTR_NOTATION: typing.Final = "*"
    VOLATILE: typing.Final = "volatile"
    COMPLEX: typing.Final = "complex"
    CLASS: typing.Final = "class"
    ENUM: typing.Final = "enum"
    STRUCT: typing.Final = "struct"
    UNION: typing.Final = "union"
    CONST: typing.Final = "const"
    COCLASS: typing.Final = "coclass"
    COINTERFACE: typing.Final = "cointerface"
    VARARGS: typing.Final = "..."
    VOID: typing.Final = "void"
    BOOL: typing.Final = "bool"
    CHAR: typing.Final = "char"
    WCHAR_T: typing.Final = "wchar_t"
    WCHAR16: typing.Final = "char16_t"
    WCHAR32: typing.Final = "char32_t"
    CHAR8_T: typing.Final = "char8_t"
    SHORT: typing.Final = "short"
    INT: typing.Final = "int"
    INT0_T: typing.Final = "int0_t"
    LONG: typing.Final = "long"
    LONG_LONG: typing.Final = "long long"
    FLOAT: typing.Final = "float"
    FLOAT2: typing.Final = "float2"
    DOUBLE: typing.Final = "double"
    INT8: typing.Final = "__int8"
    INT16: typing.Final = "__int16"
    INT32: typing.Final = "__int32"
    INT64: typing.Final = "__int64"
    INT128: typing.Final = "__int128"
    FLOAT128: typing.Final = "__float128"
    LONG_DOUBLE: typing.Final = "long double"
    PTR64: typing.Final = "__ptr64"
    STRING: typing.Final = "string"
    UNDEFINED: typing.Final = "undefined"
    UNALIGNED: typing.Final = "__unaligned"
    RESTRICT: typing.Final = "__restrict"
    PRIMITIVES: typing.Final[jpype.JArray[java.lang.String]]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originaDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...

    def getArrayDimensions(self) -> int:
        ...

    def getBasedName(self) -> str:
        ...

    def getDataType(self, dataTypeManager: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Converts this demangled datatype into the corresponding Ghidra datatype
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: the manager to search and whose data organization should be used
        :return: the Ghidra datatype corresponding to the demangled datatype
        :rtype: ghidra.program.model.data.DataType
        """

    def getMemberScope(self) -> str:
        ...

    def getPointerLevels(self) -> int:
        ...

    def incrementPointerLevels(self):
        ...

    def isArray(self) -> bool:
        ...

    def isClass(self) -> bool:
        ...

    def isCoclass(self) -> bool:
        ...

    def isCointerface(self) -> bool:
        ...

    def isComplex(self) -> bool:
        ...

    def isEnum(self) -> bool:
        ...

    def isLValueReference(self) -> bool:
        ...

    def isPointer(self) -> bool:
        ...

    def isPointer64(self) -> bool:
        ...

    def isPrimitive(self) -> bool:
        ...

    def isRValueReference(self) -> bool:
        ...

    def isReference(self) -> bool:
        ...

    def isRestrict(self) -> bool:
        ...

    def isSigned(self) -> bool:
        ...

    def isStruct(self) -> bool:
        ...

    def isTemplate(self) -> bool:
        ...

    def isUnaligned(self) -> bool:
        ...

    def isUnion(self) -> bool:
        ...

    def isUnsigned(self) -> bool:
        ...

    def isVarArgs(self) -> bool:
        ...

    def isVoid(self) -> bool:
        ...

    def setArray(self, dimensions: typing.Union[jpype.JInt, int]):
        ...

    def setBasedName(self, basedName: typing.Union[java.lang.String, str]):
        ...

    def setClass(self):
        ...

    def setCoclass(self):
        ...

    def setCointerface(self):
        ...

    def setComplex(self):
        ...

    def setEnum(self):
        ...

    @typing.overload
    def setEnumType(self, enumType: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def setEnumType(self) -> str:
        ...

    def setLValueReference(self):
        ...

    def setMemberScope(self, memberScope: typing.Union[java.lang.String, str]):
        ...

    def setPointer64(self):
        ...

    def setRValueReference(self):
        """
        rvalue reference; C++11
        """

    def setReference(self):
        ...

    def setRestrict(self):
        ...

    def setSigned(self):
        ...

    def setStruct(self):
        ...

    def setTemplate(self):
        ...

    def setUnaligned(self):
        ...

    def setUnion(self):
        ...

    def setUnsigned(self):
        ...

    def setVarArgs(self):
        ...

    @property
    def template(self) -> jpype.JBoolean:
        ...

    @property
    def struct(self) -> jpype.JBoolean:
        ...

    @property
    def primitive(self) -> jpype.JBoolean:
        ...

    @property
    def pointerLevels(self) -> jpype.JInt:
        ...

    @property
    def restrict(self) -> jpype.JBoolean:
        ...

    @property
    def reference(self) -> jpype.JBoolean:
        ...

    @property
    def lValueReference(self) -> jpype.JBoolean:
        ...

    @property
    def coclass(self) -> jpype.JBoolean:
        ...

    @property
    def memberScope(self) -> java.lang.String:
        ...

    @memberScope.setter
    def memberScope(self, value: java.lang.String):
        ...

    @property
    def array(self) -> jpype.JBoolean:
        ...

    @property
    def complex(self) -> jpype.JBoolean:
        ...

    @property
    def pointer(self) -> jpype.JBoolean:
        ...

    @property
    def void(self) -> jpype.JBoolean:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def class_(self) -> jpype.JBoolean:
        ...

    @property
    def signed(self) -> jpype.JBoolean:
        ...

    @property
    def arrayDimensions(self) -> jpype.JInt:
        ...

    @property
    def union(self) -> jpype.JBoolean:
        ...

    @property
    def unaligned(self) -> jpype.JBoolean:
        ...

    @property
    def enum(self) -> jpype.JBoolean:
        ...

    @property
    def basedName(self) -> java.lang.String:
        ...

    @basedName.setter
    def basedName(self, value: java.lang.String):
        ...

    @property
    def varArgs(self) -> jpype.JBoolean:
        ...

    @property
    def pointer64(self) -> jpype.JBoolean:
        ...

    @property
    def cointerface(self) -> jpype.JBoolean:
        ...

    @property
    def rValueReference(self) -> jpype.JBoolean:
        ...

    @property
    def unsigned(self) -> jpype.JBoolean:
        ...


class DemangledTemplate(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addParameter(self, parameter: DemangledDataType):
        ...

    def getDataType(self, defaultPointerSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        ...

    def getParameters(self) -> java.util.List[DemangledDataType]:
        ...

    def toTemplate(self) -> str:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def parameters(self) -> java.util.List[DemangledDataType]:
        ...


class DemangledStructure(DemangledDataType):
    """
    A class to represent a demangled structure
    """

    class Field(java.lang.Record):
        """
        A field of a :obj:`DemangledStructure`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], type: DemangledDataType):
            ...

        def description(self) -> str:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> DemangledDataType:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], categoryPath: typing.Union[java.lang.String, str], packed: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a new :obj:`DemangledStructure`
        
        :param java.lang.String or str mangled: The mangled string
        :param java.lang.String or str originalDemangled: The natively demangled string
        :param java.lang.String or str name: The structure name
        :param java.lang.String or str categoryPath: The structure category path
        :param jpype.JBoolean or bool packed: True if the structure should be packed; otherwise, false
        """

    @typing.overload
    def addField(self, name: typing.Union[java.lang.String, str], type: DemangledDataType):
        """
        Adds a new field to the structure. The field will not have a description.
        
        :param java.lang.String or str name: The field name
        :param DemangledDataType type: The field :obj:`type <DemangledDataType>`
        """

    @typing.overload
    def addField(self, name: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], type: DemangledDataType):
        """
        Adds a new field to the structure
        
        :param java.lang.String or str name: The field name
        :param java.lang.String or str description: The field description
        :param DemangledDataType type: The field :obj:`type <DemangledDataType>`
        """

    def getFields(self) -> java.util.List[DemangledStructure.Field]:
        """
        Gets the :obj:`List` of :obj:`Field`s
        
        :return: The :obj:`List` of :obj:`Field`s
        :rtype: java.util.List[DemangledStructure.Field]
        """

    @property
    def fields(self) -> java.util.List[DemangledStructure.Field]:
        ...


class DemanglerUtil(java.lang.Object):
    """
    Demangler Utility class.  For version 11.3, we have migrated to a new Demangler API that
    requires a :obj:`MangledContext` be passed to the demangler.  This provides more information
    for properly demangling symbols.
     
    
    Two methods below have been deprecated, as they do not provide enough information to produce
    the :obj:`MangledContext`.  A new method @link demangle(Program, String, Address) is provided
    to permit proper operation using a completed context.  Moreover, this new method returns all
    results instead of the first one found, as is how the deprecated methods work.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    @deprecated("see above")
    def demangle(mangled: typing.Union[java.lang.String, str]) -> DemangledObject:
        """
        Deprecated.  Use :meth:`demangle(Program, String, Address) <.demangle>`. See class header for more
        details.
        
        Locates all available demanglers, then it attempts to demangle.  This method will
        query all demanglers regardless of architecture.
        
         
        This method will use only the default options for demangling.  If you need to
        specify options, then you will have to call each specific demangler directly, creating
        the options and mangled context specifically needed for each demangler.   See
        :meth:`Demangler.createMangledContext(String, DemanglerOptions, Program, Address) <Demangler.createMangledContext>` and
        :meth:`Demangler.createDefaultOptions() <Demangler.createDefaultOptions>`.
        
        :param java.lang.String or str mangled: the mangled name
        :return: the demangled object or null
        :rtype: DemangledObject
        
        .. deprecated::
        
        see above
        """

    @staticmethod
    @typing.overload
    @deprecated("see above")
    def demangle(program: ghidra.program.model.listing.Program, mangled: typing.Union[java.lang.String, str]) -> DemangledObject:
        """
        Deprecated.  Use :meth:`demangle(Program, String, Address) <.demangle>`. See class header for more
        details.
        
         
        Locates all available demanglers and checks to see if the supplied program is
        supported, then it attempts to demangle.
        
         
        This method will use only the default options for demangling.  If you need to
        specify options, then you will have to call each specific demangler directly, creating
        the options and mangled context specifically needed for each demangler.   See
        :meth:`Demangler.createMangledContext(String, DemanglerOptions, Program, Address) <Demangler.createMangledContext>` and
        :meth:`Demangler.createDefaultOptions() <Demangler.createDefaultOptions>`.
        
        :param ghidra.program.model.listing.Program program: the program containing the mangled name
        :param java.lang.String or str mangled: the mangled name
        :return: the demangled object or null
        :rtype: DemangledObject
        
        .. deprecated::
        
        see above
        """

    @staticmethod
    @typing.overload
    def demangle(program: ghidra.program.model.listing.Program, mangled: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address) -> java.util.List[DemangledObject]:
        """
        Locates all available demanglers and checks to see if the supplied program is
        supported, then it attempts to demangle.  Returns a list of :obj:`DemangledObject` of
        successful demanglings
        
         
        This method will use only the default options for demangling.  If you need to
        specify options, then you will have to call each specific demangler directly, creating
        the options and mangled context specifically needed for each demangler.   See
        :meth:`Demangler.createMangledContext(String, DemanglerOptions, Program, Address) <Demangler.createMangledContext>` and
        :meth:`Demangler.createDefaultOptions() <Demangler.createDefaultOptions>`.
        
        :param ghidra.program.model.listing.Program program: the program containing the mangled name; can be null
        :param java.lang.String or str mangled: the mangled name
        :param ghidra.program.model.address.Address address: the address of the mangled name; can be null
        :return: the list of :obj:`DemangledObject`
        :rtype: java.util.List[DemangledObject]
        """

    @staticmethod
    def stripSuperfluousSignatureSpaces(str: typing.Union[java.lang.String, str]) -> str:
        """
        Remove superfluous function signature spaces from specified string
        
        :param java.lang.String or str str: string
        :return: string with unwanted spaces removed
        :rtype: str
        """


class DemangledFunctionReference(AbstractDemangledFunctionDefinitionDataType):
    """
    A class to represent a demangled function reference
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str]):
        ...


class DemangledType(Demangled):
    """
    Represents a demangled string.  This class is really just a placeholder for demangled 
    information.  See :obj:`DemangledObject` for a class that represents software concepts that
    can be applied to a program.   The :obj:`DemangledObject` may use instances of this class
    to compose its internal state for namespace information, return types and parameters.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mangled: typing.Union[java.lang.String, str], originalDemangled: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...

    def getTemplate(self) -> DemangledTemplate:
        ...

    def isConst(self) -> bool:
        ...

    def isVolatile(self) -> bool:
        ...

    def setConst(self):
        ...

    def setTemplate(self, template: DemangledTemplate):
        ...

    def setVolatile(self):
        ...

    @property
    def template(self) -> DemangledTemplate:
        ...

    @template.setter
    def template(self, value: DemangledTemplate):
        ...

    @property
    def const(self) -> jpype.JBoolean:
        ...

    @property
    def volatile(self) -> jpype.JBoolean:
        ...



__all__ = ["Demangled", "DemangledThunk", "DemangledList", "DemangledString", "DemangledFunction", "MangledContext", "AbstractDemangledFunctionDefinitionDataType", "DemangledObject", "DemangledVariable", "DemangledLabel", "DemangledFunctionPointer", "DemangledParameter", "DemanglerOptions", "Demangler", "DemangledUnknown", "DemangledFunctionIndirect", "DemangledLambda", "CharacterIterator", "DemangledAddressTable", "DemangledNamespaceNode", "DemangledException", "DemangledDataType", "DemangledTemplate", "DemangledStructure", "DemanglerUtil", "DemangledFunctionReference", "DemangledType"]
