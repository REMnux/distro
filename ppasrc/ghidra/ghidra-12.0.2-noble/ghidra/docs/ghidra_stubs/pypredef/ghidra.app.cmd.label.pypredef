from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.demangler
import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang # type: ignore


class SetLabelPrimaryCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to make a label the primary label at an address.  Only really
    makes sense if there is more than one label at the address - otherwise
    the label will already be primary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace):
        """
        Constructs a new command for setting the primary state of a label.
        
        :param ghidra.program.model.address.Address addr: the address of the label to make primary.
        :param java.lang.String or str name: the name of the label to make primary.
        :param ghidra.program.model.symbol.Namespace namespace: the parent namespace of the label to make primary.
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get transformed symbol
        
        :return: symbol (may be null if command did not execute successfully)
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...


class CreateNamespacesCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    This class attempts to create a namespace for each token in the provided
    string.  Thus, when providing a namespace string, do not include the name
    of anything other than namespaces, such as the name of a symbol.
     
    
     
    .. _examples:
    
    
    Example strings:
     
    * global:obj:`:: <Namespace.DELIMITER>`child1:obj:`:: <Namespace.DELIMITER>`child2
    * child1
    
     
    
     
    .. _assumptions:
    
    
    To view the assumptions for creating namespaces from a path string, see
    the :obj:`NamespaceUtils` class.
    
    
    .. versionadded:: Tracker Id 619
    
    .. seealso::
    
        | :obj:`NamespaceUtils`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, namespacesString: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Takes a namespace string that will be parsed and the results of which
        will be used for creating the namespaces if they do not exist.
         
        
        Calling this constructor is equivalent to calling:
         
        Command command = new CreateNamespacesCmd( namespaceString, null );
         
        
        :param java.lang.String or str namespacesString: The string to be parsed.
        :param ghidra.program.model.symbol.SourceType source: the source of the namespace
        
        .. seealso::
        
            | `example format <examples_>`_
        
            | `assumptions <assumptions_>`_
        """

    @typing.overload
    def __init__(self, namespacesString: typing.Union[java.lang.String, str], parentNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType):
        """
        Takes a namespace string that will be parsed and the results of which
        will be used for creating the namespaces if they do not exist.
        
        :param java.lang.String or str namespacesString: The string to be parsed.
        :param ghidra.program.model.symbol.Namespace parentNamespace: The namespace to be used as the starting parent
                of the namespaces that will be created.
        :param ghidra.program.model.symbol.SourceType source: the source of the namespace
        :raises NullPointerException: if ``namespaceString`` is ``null``.
        
        .. seealso::
        
            | `example format <examples_>`_
        
            | `assumptions <assumptions_>`_
        """

    def getNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the newly created namespace or null if one was not created.
        
        :return: the newly created namespace or null if one was not created.
        :rtype: ghidra.program.model.symbol.Namespace
        """

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...


class DemanglerCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, mangled: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, mangled: typing.Union[java.lang.String, str], options: ghidra.app.util.demangler.DemanglerOptions):
        ...

    def getDemangledObject(self) -> ghidra.app.util.demangler.DemangledObject:
        ...

    def getResult(self) -> str:
        ...

    @property
    def result(self) -> java.lang.String:
        ...

    @property
    def demangledObject(self) -> ghidra.app.util.demangler.DemangledObject:
        ...


@deprecated("The need for this class is now unnecessary since duplicate labels are permitted")
class AddUniqueLabelCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to add a label. If the label already
    exists somewhere else, the address is appended to make
    it unique.
    
    
    .. deprecated::
    
    The need for this class is now unnecessary since duplicate labels are permitted
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a label.
        
        :param ghidra.program.model.address.Address address: address where the label is to be added.
        :param java.lang.String or str name: name of the new label. A null name will cause a default label
        be added.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace of the label. (i.e. the namespace this label is associated with)
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol
        """

    def getNewSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the newly created symbol.
        
        :return: the newly created symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @property
    def newSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...


class AddLabelCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to add a label.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a label.
        
        :param ghidra.program.model.address.Address addr: address where the label is to be added.
        :param java.lang.String or str name: name of the new label. A null name will cause a default label
        be added.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace of the label. (i.e. the namespace this label is associated with)
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], useLocalNamespace: typing.Union[jpype.JBoolean, bool], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a label.
        
        :param ghidra.program.model.address.Address addr: address where the label is to be added.
        :param java.lang.String or str name: name of the new label. A null name will cause a default label
        be added.
        :param jpype.JBoolean or bool useLocalNamespace: If true, the namespace will be that of the lowest level namespace
        for the indicated address. If false, the global namespace is used for the namespace.
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol: Symbol.DEFAULT, Symbol.IMPORTED, Symbol.ANALYSIS, or Symbol.USER_DEFINED.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for adding a label.
        
        :param ghidra.program.model.address.Address addr: address where the label is to be added.
        :param java.lang.String or str name: name of the new label. A null name will cause a default label be added.
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol
        """

    def getLabelAddr(self) -> ghidra.program.model.address.Address:
        ...

    def getLabelName(self) -> str:
        ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    def setLabelAddr(self, addr: ghidra.program.model.address.Address):
        ...

    def setLabelName(self, name: typing.Union[java.lang.String, str]):
        ...

    def setNamespace(self, namespace: ghidra.program.model.symbol.Namespace):
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def labelAddr(self) -> ghidra.program.model.address.Address:
        ...

    @labelAddr.setter
    def labelAddr(self, value: ghidra.program.model.address.Address):
        ...

    @property
    def labelName(self) -> java.lang.String:
        ...

    @labelName.setter
    def labelName(self, value: java.lang.String):
        ...


class DeleteLabelCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to delete a label
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], scope: ghidra.program.model.symbol.Namespace):
        """
        Constructs a new command for deleting a label or function variable.
        
        :param ghidra.program.model.address.Address addr: address of the label to be deleted.
        :param java.lang.String or str name: name of the label to be deleted.
        :param ghidra.program.model.symbol.Namespace scope: the scope of the label to delete. (i.e. the namespace the label to delete is associated with)
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]):
        """
        Constructs a new command for deleting a global symbol
        
        :param ghidra.program.model.address.Address addr: address of the label to be deleted.
        :param java.lang.String or str name: name of the label to be deleted.
        """


class RenameLabelCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for renaming labels. Handles converting back and forth between default and named labels 
    as well.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, oldName: typing.Union[java.lang.String, str], newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for renaming **global** labels.
        
        :param ghidra.program.model.address.Address addr: Address of label to be renamed
        :param java.lang.String or str oldName: the name of the label to be renamed; may be null if the existing label is a 
        dynamic label
        :param java.lang.String or str newName: the new name for the label
        :param ghidra.program.model.symbol.SourceType source: the source of this symbol
        """

    @typing.overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, newName: typing.Union[java.lang.String, str], source: ghidra.program.model.symbol.SourceType):
        """
        Constructor renaming an existing symbol, but not changing its namespace
        
        :param ghidra.program.model.symbol.Symbol symbol: the existing symbol; may not be null
        :param java.lang.String or str newName: the new symbol name
        :param ghidra.program.model.symbol.SourceType source: the desired symbol source
        """

    @typing.overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, newName: typing.Union[java.lang.String, str], newNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType):
        """
        Constructor renaming an existing symbol and changing its namespace.  If you do not need
        to change the namespace, then call :meth:`RenameLabelCmd(Symbol, String, SourceType) <.RenameLabelCmd>`.
        
        :param ghidra.program.model.symbol.Symbol symbol: the existing symbol; may not be null
        :param java.lang.String or str newName: the new symbol name
        :param ghidra.program.model.symbol.Namespace newNamespace: the new symbol namespace
        :param ghidra.program.model.symbol.SourceType source: the desired symbol source
        """


class ExternalEntryCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command for setting/unsetting an external entry point.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, isEntry: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a new command for setting/unsetting an external entry point
        
        :param ghidra.program.model.address.Address addr: address to set or unset as an external entry point.
        :param jpype.JBoolean or bool isEntry: true if the address is to be an entry. Otherwise, false.
        """


class PinSymbolCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], pin: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["SetLabelPrimaryCmd", "CreateNamespacesCmd", "DemanglerCmd", "AddUniqueLabelCmd", "AddLabelCmd", "DeleteLabelCmd", "RenameLabelCmd", "ExternalEntryCmd", "PinSymbolCmd"]
