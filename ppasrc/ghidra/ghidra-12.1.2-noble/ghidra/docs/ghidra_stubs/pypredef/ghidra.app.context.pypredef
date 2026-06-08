from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.nav
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class ProgramSymbolActionContext(ProgramActionContext, ProgramLocationSupplierContext):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, symbols: java.util.List[ghidra.program.model.symbol.Symbol], sourceComponent: java.awt.Component) -> None:
        ...

    def getFirstSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    def getSymbolCount(self) -> int:
        ...

    def getSymbols(self) -> java.lang.Iterable[ghidra.program.model.symbol.Symbol]:
        ...

    @property
    def firstSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def symbolCount(self) -> jpype.JInt:
        ...

    @property
    def symbols(self) -> java.lang.Iterable[ghidra.program.model.symbol.Symbol]:
        ...


class ListingActionContext(NavigatableActionContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, location: ghidra.program.util.ProgramLocation) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection) -> None:
        ...


class ProgramLocationActionContext(ProgramActionContext, FunctionSupplierContext, ProgramLocationSupplierContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, sourceComponent: java.awt.Component, location: ghidra.program.util.ProgramLocation) -> None:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: address corresponding to the action's program location or null
        if program location is null.
        :rtype: ghidra.program.model.address.Address
        """

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit containing the action's program location or null
        
        :return: the code unit containing the action's program location or null
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    def getHighlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        
        
        :return: Returns the program selection.
        :rtype: ghidra.program.util.ProgramSelection
        """

    def hasHighlight(self) -> bool:
        ...

    def hasSelection(self) -> bool:
        ...

    @property
    def highlight(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection:
        ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...


class DataLocationListContext(java.lang.Object):
    """
    Context mix-in interface that ActionContexts can implement if they can provide a list of
    :obj:`Data` object's :obj:`ProgramLocation`'s.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCount(self) -> int:
        """
        Returns the number of :obj:`Data` objects for the current action context.
        
        :return: the number of :obj:`Data` objects for the current action context.
        :rtype: int
        """

    @typing.overload
    def getDataLocationList(self) -> java.util.List[ghidra.program.util.ProgramLocation]:
        """
        Returns a list of the locations of the current :obj:`Data` objects in the current action context.
        
        :return: a list of the locations of the current :obj:`Data` objects in the current action context.
        :rtype: java.util.List[ghidra.program.util.ProgramLocation]
        """

    @typing.overload
    def getDataLocationList(self, filter: java.util.function.Predicate[ghidra.program.model.listing.Data]) -> java.util.List[ghidra.program.util.ProgramLocation]:
        """
        Returns a list of the locations of the current :obj:`Data` objects in the current action context that pass the given filter.
        
        :param java.util.function.Predicate[ghidra.program.model.listing.Data] filter: a filter to apply to the current context's Data list, ``null``
        implies all elements match.
        :return: a list of the locations of the current :obj:`Data` objects in the current action context that pass the given filter.
        :rtype: java.util.List[ghidra.program.util.ProgramLocation]
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program for the current action context.
        
        :return: the program for the current action context.
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def count(self) -> jpype.JInt:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def dataLocationList(self) -> java.util.List[ghidra.program.util.ProgramLocation]:
        ...


class NavigationActionContext(docking.ActionContext):
    """
    An interface that signals the client supports navigation. 
     
     
    Note: the :obj:`NavigatableActionContext` is tied to :obj:`ProgramLocationActionContext`
    which has more baggage than just 'navigation'.
    """

    class_: typing.ClassVar[java.lang.Class]


class NavigatableContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]) -> None:
        """
        Constructor for actions that can work on any Navigatable
        
        :param java.lang.String or str name: the action's name
        :param java.lang.String or str owner: the action's owner
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], supportsRestrictedAddressSetContext: typing.Union[jpype.JBoolean, bool]) -> None:
        """
        Constructor for specifying if that the context works on :obj:`RestrictedAddressSetContext`
        
        :param java.lang.String or str name: the action's name
        :param java.lang.String or str owner: the action's owner
        :param jpype.JBoolean or bool supportsRestrictedAddressSetContext: true if this action can work on
        :obj:`RestrictedAddressSetContext`
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], type: docking.action.KeyBindingType) -> None:
        """
        Constructor when using a non-standard :obj:`KeyBindingType`
        
        :param java.lang.String or str name: the action's name
        :param java.lang.String or str owner: the action's owner
        :param docking.action.KeyBindingType type: the KeybindingType
        """


class ProgramContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]) -> None:
        ...


class NavigatableActionContext(ProgramLocationActionContext, NavigationActionContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, location: ghidra.program.util.ProgramLocation) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection) -> None:
        ...

    def getNavigatable(self) -> ghidra.app.nav.Navigatable:
        ...

    def isActiveProgram(self) -> bool:
        """
        Overridden to signal that this navigatable's program may not be the same as the globally 
        active program.  This is done to signal that this navigatable can supply default context.
        
        :return: false
        :rtype: bool
        """

    @property
    def navigatable(self) -> ghidra.app.nav.Navigatable:
        ...

    @property
    def activeProgram(self) -> jpype.JBoolean:
        ...


class ProgramActionContext(docking.DefaultActionContext):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, sourceComponent: java.awt.Component) -> None:
        ...

    @typing.overload
    def __init__(self, provider: docking.ComponentProvider, program: ghidra.program.model.listing.Program, sourceComponent: java.awt.Component, contextObject: java.lang.Object) -> None:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def isActiveProgram(self) -> bool:
        """
        Returns true if the program in this context is the globally active program in the tool.  This
        is generally true for all context.  Some context providers may be working with a different
        program than the active program or they may be using the active program with restricted 
        address views.  In this latter case, this method should return false.
        
        :return: true if the program is the active program; false means the program may not be the 
                active program
        :rtype: bool
        """

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def activeProgram(self) -> jpype.JBoolean:
        ...


class RestrictedAddressSetContext(java.lang.Object):
    """
    Marker interface for :obj:`Navigatable` contexts that don't support navigating to the entire
    program. Typically, these are used by providers that show only one function at a time such
    as the Decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramLocationContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]) -> None:
        ...


class FunctionSupplierContext(docking.ActionContext):
    """
    A "mix-in" interface that specific implementers of :obj:`ActionContext` may also implement if
    they can supply functions in their action context. Actions that want to work on functions
    can look for this interface, which can be used in a variety of contexts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFunctions(self) -> java.util.Set[ghidra.program.model.listing.Function]:
        """
        Returns the set of functions that this context object can supply.
        
        :return: the set of functions that this context object can supply
        :rtype: java.util.Set[ghidra.program.model.listing.Function]
        """

    def hasFunctions(self) -> bool:
        """
        Returns true if this context can supply one or more functions.
        
        :return: true if this context can supply one or more functions
        :rtype: bool
        """

    @property
    def functions(self) -> java.util.Set[ghidra.program.model.listing.Function]:
        ...


class ProgramSymbolContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], kbType: docking.action.KeyBindingType) -> None:
        ...


class ListingContextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], kbType: docking.action.KeyBindingType) -> None:
        ...


class ProgramLocationSupplierContext(docking.ActionContext):
    """
    A "mix-in" interface that specific implementers of :obj:`ActionContext` may also implement if
    they can supply a program location in their action context. Actions that want to work on 
    locations can look for this interface, which can be used in a variety of contexts.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        :return: the program location
        :rtype: ghidra.program.util.ProgramLocation
        """

    @property
    def location(self) -> ghidra.program.util.ProgramLocation:
        ...



__all__ = ["ProgramSymbolActionContext", "ListingActionContext", "ProgramLocationActionContext", "DataLocationListContext", "NavigationActionContext", "NavigatableContextAction", "ProgramContextAction", "NavigatableActionContext", "ProgramActionContext", "RestrictedAddressSetContext", "ProgramLocationContextAction", "FunctionSupplierContext", "ProgramSymbolContextAction", "ListingContextAction", "ProgramLocationSupplierContext"]
