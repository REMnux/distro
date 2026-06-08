from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore


class ThreeColumnLayout(java.awt.LayoutManager):
    """
    LayoutManger for arranging components into exactly three columns.  The first and last column
    are statically sized to be the max preferred width of those columns.  The middle column's width
    will vary as the panel is resized.
     
    
    This layout works well for a panel that has rows of labels followed by a field and followed by
    a trailing component like a button group.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap1: typing.Union[jpype.JInt, int], hgap2: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgaps: jpype.JArray[jpype.JInt], minPreferredWidths: jpype.JArray[jpype.JInt]) -> None:
        ...


class PairLayout(java.awt.LayoutManager):
    """
    LayoutManger for arranging components into exactly two columns.  The right column and the 
    left column may have differing widths.  Also, each row is the same height, 
    which is the largest of all rows.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        ...

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new PairLayout.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        """

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int], minimumRightColumnWidth: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new PairLayout.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        :param jpype.JInt or int minimumRightColumnWidth: specifies the minimum width of the second column.
        """


class StretchLayout(java.awt.LayoutManager, java.io.Serializable):
    """
    A layout manager that gives the affect of CENTER in BorderLayout.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class MiddleLayout(java.awt.LayoutManager, java.io.Serializable):
    """
    Puts the first child of the given component in the middle of the component, both vertically
    and horizontally.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class RightSidedSquishyBuddyLayout(java.awt.LayoutManager, java.io.Serializable):
    """
    Layout for two components laid out horizontally where the first component gets its preferred width
    and the second component gets the remaining space up to its preferred width.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, hGap: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, hGap: typing.Union[jpype.JInt, int], rightAlign: typing.Union[jpype.JBoolean, bool]) -> None:
        ...


class VariableHeightPairLayout(java.awt.LayoutManager):
    """
    LayoutManger for arranging components into exactly two columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        """
        Constructor for PairLayout.
        """

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new PairLayout.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        """

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int], preferredWidth2: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new PairLayout.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        :param jpype.JInt or int preferredWidth2: specifies the preferred width of the second column.
        """


class AbstractLayoutManager(java.awt.LayoutManager):
    """
    An abstract :obj:`LayoutManager` that stubs out typically unused methods and defaults the 
    minimum size to the preferred size.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class ColumnLayout(java.awt.LayoutManager):
    """
    This layout arranges components in columns, putting as many components as possible in a
    column and using as many columns as necessary.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hgap: typing.Union[jpype.JInt, int], vgap: typing.Union[jpype.JInt, int], preferredNumCols: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new ColumnLayout
        
        :param jpype.JInt or int hgap: the gap (in pixels) between columns
        :param jpype.JInt or int vgap: the gap (in pixels) between rows
        :param jpype.JInt or int preferredNumCols: the preferred number of columns to use in the layout.
        """


class VariableRowHeightGridLayout(java.awt.LayoutManager):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, columnCount: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int], columnCount: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructs a new PairLayout.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        :param jpype.JInt or int columnCount: the number of columns in this grid
        """


class HorizontalLayout(java.awt.LayoutManager):
    """
    LayoutManager for arranging components in a single row.  All components
    retain their preferred widths, but are sized to the same height.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hgap: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructor for HorizontalLayout.
        
        :param jpype.JInt or int hgap: gap (in pixels) between components.
        """


class MaximizeSpecificColumnGridLayout(java.awt.LayoutManager):
    """
    ``MaximizeSpecificColumnGridLayout`` is a row oriented grid type of layout.
    It lays out rows of information in a table format using a specific number of columns. 
    Components are added left to right and top to bottom. The table will try to give each column
    the width that is necessary to display the longest item in that column. The columns with the 
    widest desired component size will get reduced first if there isn't enough room. 
    The maximizeColumn(int) method allows you to indicate that you want to try to keep the size
    of a column at the preferred size of the widest component in that column as the parent 
    container component is resized. Any column that has been maximized won't shrink until the 
    non-maximized windows are reduced to a width of zero.
    The intent is that all non-maximized columns will shrink from largest to smallest so that
    they all will become zero width together at which point the maximized columns will begin 
    shrinking in a similar manner.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, columnCount: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructor with no gap between rows or columns.
        
        :param jpype.JInt or int columnCount: the number of columns in this grid
        """

    @typing.overload
    def __init__(self, vgap: typing.Union[jpype.JInt, int], hgap: typing.Union[jpype.JInt, int], columnCount: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructor.
        
        :param jpype.JInt or int vgap: the gap (in pixels) between rows.
        :param jpype.JInt or int hgap: the gap (in pixels) between the two columns.
        :param jpype.JInt or int columnCount: the number of columns in this grid
        """

    def maximizeColumn(self, column: typing.Union[jpype.JInt, int]) -> None:
        """
        Allows you to indicate that you want to try to keep the size of a column at the preferred 
        size of the widest component in that column as the parent container component is resized. 
        Any column that has been maximized won't shrink until the non-maximized windows are reduced 
        to a width of zero.
        
        :param jpype.JInt or int column: the number (0 based) of the column to keep maximized.
        """


class VerticalLayout(java.awt.LayoutManager):
    """
    LayoutManager for arranging components in a single column.  All components
    retain their preferred heights, but are sized to the same width.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, vgap: typing.Union[jpype.JInt, int]) -> None:
        """
        Constructor for VerticalLayout.
        
        :param jpype.JInt or int vgap: gap (in pixels) between components.
        """


class TwoColumnPairLayout(java.awt.LayoutManager):
    """
    LayoutManger for arranging components into exactly two columns.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self) -> None:
        """
        Constructor for PairLayout.
        """

    @typing.overload
    def __init__(self, verticalGap: typing.Union[jpype.JInt, int], columnGap: typing.Union[jpype.JInt, int], pairGap: typing.Union[jpype.JInt, int], preferredValueColumnWidth: typing.Union[jpype.JInt, int]) -> None:
        ...


class ProportionalHorizontalLayout(java.awt.LayoutManager2):

    class Proportion(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, p: typing.Union[jpype.JDouble, float]) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...



__all__ = ["ThreeColumnLayout", "PairLayout", "StretchLayout", "MiddleLayout", "RightSidedSquishyBuddyLayout", "VariableHeightPairLayout", "AbstractLayoutManager", "ColumnLayout", "VariableRowHeightGridLayout", "HorizontalLayout", "MaximizeSpecificColumnGridLayout", "VerticalLayout", "TwoColumnPairLayout", "ProportionalHorizontalLayout"]
