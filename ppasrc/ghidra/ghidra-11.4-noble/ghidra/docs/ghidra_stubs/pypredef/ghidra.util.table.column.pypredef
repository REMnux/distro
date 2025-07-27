from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.docking.settings
import ghidra.util.exception
import ghidra.util.table
import java.lang # type: ignore
import javax.swing.table # type: ignore


T = typing.TypeVar("T")


class AbstractGhidraColumnRenderer(ghidra.util.table.GhidraTableCellRenderer, GColumnRenderer[T], typing.Generic[T]):
    """
    A convenience base class that combines the :obj:`GhidraTableCellRenderer` with the 
    :obj:`GColumnRenderer` interface
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractGColumnRenderer(docking.widgets.table.GTableCellRenderer, GColumnRenderer[T], typing.Generic[T]):
    """
    A convenience base class that combines the :obj:`GTableCellRenderer` with the 
    :obj:`GColumnRenderer` interface.
     
     
    Table columns that wish to provider a renderer will have to implement the 
    :obj:`GColumnRenderer` interface.  Rather then implement that interface and extend
    the :obj:`GTableCellRenderer`, clients can simply extends this class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GColumnRenderer(javax.swing.table.TableCellRenderer, typing.Generic[T]):
    """
    An interface for the :obj:`DynamicTableColumn`.  This allows the filtering system to stay
    in sync with the rendering system by using the display text to filter.
     
     
    Table filtering in :obj:`GTable`s typically works with the following setup:
     
    1. The table has a text field that allows for quick filtering across all visible 
    columns.  The specifics of how the text filter works are defined by the
    :obj:`RowFilterTransformer`, which is controlled by the user via the button at the right
    of the filter field.  (In the absence of this button, filters are typically a 'contains'
    filter.)
    
    The default transformer turns items to strings by, in order,:
        
        1. checking the column renderer's 
        :meth:`getFilterString(Object, Settings) <.getFilterString>`,if a column renderer is installed
        
        2. checking to see if the column value is an instance of :obj:`DisplayStringProvider`
        3. checking to see if the column value is a :obj:`JLabel`
        4. calling toString() on the object
        
    
    2. 
    The table has the ability to perform advanced filtering based upon specific columns.  Each
    column's type is used to find dynamically discovered:obj:`ColumnConstraint`s.  These
    constraints dictate how a given column can be filtered.  The user will create filters
    using these constraints in the:obj:`ColumnFilterDialog` by pressing the 
    button at the far right of the filter text field.
    
    The way the constraints are used in the filtering system, in conjunction with 
    this renderer, is defined by the:obj:`ColumnConstraintFilterMode` via
    :meth:`getColumnConstraintFilterMode() <.getColumnConstraintFilterMode>`.
    
    3. 
        Any custom filters, defined by individual clients (this is outside the scope of the
        default filtering system)
    
    
     
     
    **Note: The default filtering behavior of this class is to only filter on the aforementioned
        filter text field.  That is, column constraints will not be enabled by default. To
        change this, change the value returned by :meth:`getColumnConstraintFilterMode() <.getColumnConstraintFilterMode>`.**
    """

    class ColumnConstraintFilterMode(java.lang.Enum[GColumnRenderer.ColumnConstraintFilterMode]):
        """
        An enum that signals how the advanced column filtering should work.   (This does not affect
        the normal table filtering that happens via the filter text field).
        """

        class_: typing.ClassVar[java.lang.Class]
        ALLOW_RENDERER_STRING_FILTER_ONLY: typing.Final[GColumnRenderer.ColumnConstraintFilterMode]
        """
        Use only :meth:`GColumnRenderer.getFilterString(Object, Settings) <GColumnRenderer.getFilterString>` value; no constraints
        """

        ALLOW_CONSTRAINTS_FILTER_ONLY: typing.Final[GColumnRenderer.ColumnConstraintFilterMode]
        """
        Use only column constraints when filtering
        """

        ALLOW_ALL_FILTERS: typing.Final[GColumnRenderer.ColumnConstraintFilterMode]
        """
        Use both the rendered filter String and any found column constraints
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GColumnRenderer.ColumnConstraintFilterMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[GColumnRenderer.ColumnConstraintFilterMode]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def createWrapperTypeException(self) -> ghidra.util.exception.AssertException:
        """
        A convenience method for primitive-based/wrapper-based renderers to signal that they
        should not be using text to filter.  
         
         
        The basic wrapper types, like Number, and some others, like :obj:`Date`, have special
        built-in filtering capabilities.  Columns whose column type is one of the wrapper classes
        will not have their :meth:`getFilterString(Object, Settings) <.getFilterString>` methods called.  They can
        stub out those methods by throwing the exception returned by this method.
        
        :return: the new exception
        :rtype: ghidra.util.exception.AssertException
        
        .. seealso::
        
            | :obj:`AbstractWrapperTypeColumnRenderer`
        """

    def getColumnConstraintFilterMode(self) -> GColumnRenderer.ColumnConstraintFilterMode:
        """
        Returns the current mode of how column constraints will be used to filter this column
         
         
        This method is typically not overridden.  This is only needed in rare cases, such as
        when a column uses a renderer, but does *not* want this column to be filtered using
        a String column constraint.   Or, if a column uses a renderer and wants that text to 
        be available as a filter, along with any other column constraints.
        
        :return: the mode
        :rtype: GColumnRenderer.ColumnConstraintFilterMode
        """

    def getFilterString(self, t: T, settings: ghidra.docking.settings.Settings) -> str:
        """
        Returns a string that is suitable for use when filtering.  The returned String should 
        be an unformatted (e.g., no HTML markup, icons, etc) version of what is on the screen.
        If the String returned here does not match what the user sees (that which is rendered),
        then the filtering action may confuse the user.
        
        :param T t: the column type instance
        :param ghidra.docking.settings.Settings settings: any settings the converter may need to convert the type
        :return: the unformatted String version of what is rendered in the table cell on screen
        :rtype: str
        """

    @property
    def columnConstraintFilterMode(self) -> GColumnRenderer.ColumnConstraintFilterMode:
        ...


class DefaultTimestampRenderer(AbstractGColumnRenderer[java.util.Date]):
    """
    A renderer for clients that wish to display a :obj:`Date` as a timestamp with the
    date and time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class AbstractWrapperTypeColumnRenderer(GColumnRenderer[T], typing.Generic[T]):
    """
    A convenience interface of :obj:`GColumnRenderer` for primitive-based/wrapper-based 
    renderers.   This class implements :meth:`getFilterString(Object, Settings) <.getFilterString>` to 
    throw an exception, as it should not be called for primitive types.
     
     
    The basic wrapper types, like Number, and some others, like :obj:`Date`, have special
    built-in filtering capabilities.  Columns whose column type is one of the wrapper classes
    will not have their :meth:`getFilterString(Object, Settings) <.getFilterString>` methods called.  They can
    stub out those methods by throwing the exception returned by this method.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["AbstractGhidraColumnRenderer", "AbstractGColumnRenderer", "GColumnRenderer", "DefaultTimestampRenderer", "AbstractWrapperTypeColumnRenderer"]
