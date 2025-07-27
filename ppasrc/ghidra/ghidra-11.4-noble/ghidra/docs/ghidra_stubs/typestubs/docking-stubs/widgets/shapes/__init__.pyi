from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.lang # type: ignore


class Location(java.lang.Enum[Location]):
    """
    Specifies location and metrics for :obj:`PopupWindowPlacer`.
    """

    class_: typing.ClassVar[java.lang.Class]
    LEFT: typing.Final[Location]
    RIGHT: typing.Final[Location]
    TOP: typing.Final[Location]
    BOTTOM: typing.Final[Location]
    CENTER: typing.Final[Location]

    def clockwise(self) -> Location:
        ...

    def counterClockwise(self) -> Location:
        ...

    def isCenter(self) -> bool:
        ...

    def isGreater(self) -> bool:
        ...

    def isHorizontal(self) -> bool:
        ...

    def isLesser(self) -> bool:
        ...

    def isVertical(self) -> bool:
        ...

    def match(self) -> Location:
        ...

    def validMinor(self, minor: Location) -> bool:
        """
        Assumes "this" is a major axis, and tells whether the minor axis argument is valid for
        the major value.  Cannot have both major and minor be the same horizontal/vertical bearing.
        Note that :obj:`.CENTER` can be horizontal or vertical, so this method should not count
        this value as a bad minor value, as it also represents a good value.
        
        :param Location minor: the minor value to check
        :return: true if valid.
        :rtype: bool
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Location:
        ...

    @staticmethod
    def values() -> jpype.JArray[Location]:
        ...

    @property
    def horizontal(self) -> jpype.JBoolean:
        ...

    @property
    def lesser(self) -> jpype.JBoolean:
        ...

    @property
    def center(self) -> jpype.JBoolean:
        ...

    @property
    def vertical(self) -> jpype.JBoolean:
        ...

    @property
    def greater(self) -> jpype.JBoolean:
        ...


class PopupWindowPlacerBuilder(java.lang.Object):
    """
    This class builds a PopWindowPlacer that can have subsequent PopWindowPlacers.
     
    
    General categories of placers available are **edge** placers, **overlapped-corner**
    placers, and a clean-up **assert** placer.  Additionally, there are **rotational** placers
    that are composed of edge placers.
     
    
     
    
     
     
     
     
    ############
    Edge Placers
    ############
    
      
     
    
    The **edge** placers are the leftEdge, rightEdge, topEdge, and bottomEdge methods that take
    Location arguments that one can think of as "cells" for optimal placement, but which have some
    flexibility in making the placement.  One such cell is the TOP Location of the rightEdge,
    specified by ``rightEdge(Location.TOP)``.  If the placement does not quite fit this
    cell because the optimal placement extend above the top of the screen, the placement may be
    shifted down by a  allowed amount so that it still fits.  If more than the allowed amount is
    needed, the placement fails.
     
    
    Each edge placer takes a variable number of Location arguments.  These arguments work in the
    same way for each method, though some arguments are not valid for some edges; for instance,
    ``Location.TOP`` is only valid for left and right edges.
     
     
    ******************************
    Two or More Location Arguments
    ******************************
    
     
     
    
    When two or more arguments are used, the first argument specifies the nominal placement cell
    and the second argument specifies how far the solution is allowed to shift.  If a solution is
    not found and if there are more than two arguments, another placement attempt is made where
    the second argument specifies the nominal placement cell and the third argument specifies how
    far the solution is allowed to shift. To specify a "no-shift" solution, one specifies the same
    placement cell twice (e.g., ``rightEdge(Location.TOP, Location.TOP)``).
     
     
    *********************
    One Location Argument
    *********************
    
     
     
    
    When one argument is used, the solution is the same as when two arguments are specified except
    that the second argument is automatically set to the nearest neighboring cell.  Thus,
    ``rightEdge(Location.TOP)`` is the same as
    ``rightEdge(Location.TOP, Location.CENTER)``.  When the single argument is
    ``Location.CENTER``, two attempts are built, the first being the BOTTOM or RIGHT cell
    and the second being the TOP or LEFT cell.
     
     
    ************
    No Arguments
    ************
    
     
     
    
    When no arguments are specified, two arguments to the underlying placer are automatically set
    to BOTTOM or RIGHT for the first and TOP or LEFT for the second.
     
     
    ********
    Examples
    ********
    
     
     
    
    Builds a placer that first attempts a placement at the bottom of the right edge with no
    shift, then tries the top of the right edge with no shift, then top center with no shift:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .rightEdge(Location.BOTTOM,Location.BOTTOM)
                .rightEdge(Location.TOP, Location.TOP)
                .topEdge(Location.CENTER, Location.CENTER)
                .build();
    Builds a placer that attempts a placement on the right edge from bottom to top, followed by
    the top edge from center to right, then center to left:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .rightEdge()
                .topEdge(Location.CENTER);
                .build();
     
    
     
    
     
    
     
     
    ##################
    Rotational Placers
    ##################
    
     
     
    
    There are clockwise and counter-clockwise rotational placers that built up from edge placers.
    These are:
     
        rotateClockwise(Location major, Location minor)
        rotateCounterClockwise(Location major, Location minor)
        thenRotateClockwise()
        thenRotateCounterClockwise()
    The first two of these take two Location arguments the specify the starting cell.  For instance,
    ``rotateClockwise(Location.BOTTOM, Location.RIGHT)``.  This specifies a set of edge
    placers that attempt placement starting from the specified cell, and making attempt in a
    clockwise fashion until the starting cell is revisited, at which time the attempt fails if a
    viable placement has not been found.  The ``rotateCounterClockwise`` placer works the
    same, but in a counter-clockwise fashion.  The ``thenRotateClockwise`` and
    ``thenRotateCounterClockwise`` placers are the same as the previous two placers
    except that they start at the "beginning" cell where the most previous placer had left off.  If
    there was not a previous placer, then the BOTTOM RIGHT cell is chosen as the starting cell.
     
    
     
    
     
    
     
     
    #########################
    Overlapping Corner Placer
    #########################
    
     
     
    
    There is one corner placer, ``leastOverlapCorner()``.  This placer tries to make a
    placement at each of the corners of the context area and shifts into the context region as much
    as necessary to fit the screen bounds.  The corner that overlaps the context area the least is
    chosen as the solution placement corner.  In case of a tie (e.g., no overlap on some corners),
    the placement order chosen in this preference order: bottom right, bottom left, top right, and
    top left.  Unless ill-constructed (sized of context area, screen, and pop-up dimension), this
    placer should always find a solution.
     
    
     
    
     
    
     
     
    #############
    Assert Placer
    #############
    
     
     
    
    The ``throwsAssertException()`` placer is available, which automatically throws an
    AssertException.  This placer is only intended to be used by the client in such as case when
    it is believed that a placement should have already been found, such as after the
    ``leastOverlapCorner()`` placer.  This just throws an exception instead of returning
    the ``null`` return value that would be returned from previous placement attempts.
     
    
     
    
     
    
     
     
    ################
    Composite Placer
    ################
    
     
     
    
    Builds a placer that first attempts a placement at the right edge from bottom to top, then
    left edge from bottom to top, then top edge from right to left, then bottom edge from right to
    left, followed by a least-overlap-corner solution, followed by a failure assert:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .rightEdge()
                .leftEdge()
                .topEdge()
                .bottomEdge()
                .leastOverlapCorner()
                .throwsAssertException()
                .build();
     
    
    Builds a placer that first attempts each of the four major corners in a specific order, with no
    shifting, followed by an assertion failure:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .rightEdge(Location.BOTTOM, Location.BOTTOM)
                .leftEdge(Location.TOP, Location.TOP)
                .rightEdge(Location.TOP, Location.TOP)
                .leftEdge(Location.BOTTOM, Location.BOTTOM)
                .throwsAssertException()
                .build();
     
    
    Builds a placer that attempt to make a placement at the bottom right corner, first shifting up
    to the center location then shifting left to the center location, then failing only with a
    null return:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .rightEdge(Location.BOTTOM)
                .bottomEdge(Location.RIGHT)
                .build();
     
    
    Builds a placer that attempts a placement at the top, left corner, the tries to make a placement
    in a clockwise fashion, followed by a failure assert:
     
        PopupWindowPlacer placer =
            new PopupWindowPlacerBuilder()
                .topEdge(Location.LEFT, Location.LEFT)
                .thenRotateClockwise()
                .throwsAssertException()
                .build();
    
    
    .. seealso::
    
        | :obj:`PopupWindowPlacer`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def bottomEdge(self, *minors: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement at the bottom
        edge of the inner bounds (context) without exceeding outer bounds (screen), using
        an ordered, preferred placements on that edge.  Invalid values will error.
        
        :param jpype.JArray[Location] minors: the ordered, preferred placements on the edge. If not specified, goes from
        greater-valued end of the edge to the lesser-valued end of the edge.
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def build(self) -> PopupWindowPlacer:
        """
        Builds the final PopupWindowPlacer.
        
        :return: the PopupWindowPlacer
        :rtype: PopupWindowPlacer
        """

    def edge(self, major: Location, *minors: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement on the major
        edge of the inner bounds (context) without exceeding outer bounds (screen), using
        an ordered, preferred placements on that edge.  Invalid values will error.
        
        :param Location major: the major edge of the context area
        :param jpype.JArray[Location] minors: the ordered, preferred placements on the edge. If not specified, goes from
        greater-valued end of the edge to the lesser-valued end of the edge.
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def leastOverlapCorner(self) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement that is
        allowed to overlap the inner bounds, but with the least overlap area.  Tie-breaker
        order is first in this order: Bottom Right, Bottom Left, Top Right, Top  Left.
         
        
        Should never return null, except if using impractical parameters, such as using
        outer bounds that are smaller than inner bounds.
        
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def leftEdge(self, *minors: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement at the left
        edge of the inner bounds (context) without exceeding outer bounds (screen), using
        an ordered, preferred placements on that edge.  Invalid values will error.
        
        :param jpype.JArray[Location] minors: the ordered, preferred placements on the edge. If not specified, goes from
        greater-valued end of the edge to the lesser-valued end of the edge.
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def rightEdge(self, *minors: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement at the right
        edge of the inner bounds (context) without exceeding outer bounds (screen), using
        an ordered, preferred placements on that edge.  Invalid values will error.
        
        :param jpype.JArray[Location] minors: the ordered, preferred placements on the edge. If not specified, goes from
        greater-valued end of the edge to the lesser-valued end of the edge.
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def rotateClockwise(self, majorBegin: Location, minorBegin: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
        a point specified by ``majorBegin`` and ``minorBegin`` and continues
        clockwise to find a solution.
        
        :param Location majorBegin: the major coordinate location of the starting point
        :param Location minorBegin: the minor coordinate location of the starting point
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def rotateCounterClockwise(self, majorBegin: Location, minorBegin: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
        a point specified by ``majorBegin`` and ``minorBegin`` and continues
        counter-clockwise to find a solution.
        
        :param Location majorBegin: the major coordinate location of the starting point
        :param Location minorBegin: the minor coordinate location of the starting point
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def thenRotateClockwise(self) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
        the last-used ``majorBegin`` and ``minorBegin`` and continues clockwise
        to find a solution.  If there was no last-used location set, then BOTTOM, RIGHT is used.
        
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def thenRotateCounterClockwise(self) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement by starting at
        the last-used ``majorBegin`` and ``minorBegin`` and continues counter-clockwise
        to find a solution.  If there was no last-used location set, then RIGHT, BOTTOM is used.
        
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def throwsAssertException(self) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer that throws an AssertException because no solution has
        been found by the time this placer is tried.  This is intended to be used when the coder
        has already guaranteed that there is a solution (i.e., the :meth:`leastOverlapCorner() <.leastOverlapCorner>`
        placer has been used and the pop-up area will fit within the outer bounds).
        
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def topEdge(self, *minors: Location) -> PopupWindowPlacerBuilder:
        """
        Set the next PopupWindowPlacer to be one that tries to make the placement at the top
        edge of the inner bounds (context) without exceeding outer bounds (screen), using
        an ordered, preferred placements on that edge.  Invalid values will error.
        
        :param jpype.JArray[Location] minors: the ordered, preferred placements on the edge. If not specified, goes from
        greater-valued end of the edge to the lesser-valued end of the edge.
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """

    def useRectangle(self, r: java.awt.Rectangle) -> PopupWindowPlacerBuilder:
        """
        A method that allows clients to specify an exact rectangle to be used.  This method can be
        used to hardcode a rectangle to use when the placement algorithm specified earlier in the 
        builder chain has failed.
        
        :param java.awt.Rectangle r: the rectangle
        :return: this builder
        :rtype: PopupWindowPlacerBuilder
        """


class PopupWindowPlacer(java.lang.Object):
    """
    This class places a rectangle on the boundary of an inner bounds area, such that it is not
    placed outside of an outer boundary.  It takes the concept of trying to make the placement at
    the closest distance, but preferring certain sides or angles of approach in iterating a
    solution. However, we reduce this concept down to a very simple form where iteration is not
    needed because we are basing the algorithm on a geometric model that has explicit solutions
    (for example, instead of picking a starting point around the perimeter and rotating
    counter-clockwise to find a fit, or, for example, creating a grid of placements and choosing
    the one that is closest but yet has preferences on one side or another).  From the geometric
    model, we can, instead, calculate the first location that will fit with a preferred boundary
    location, such as fit on the right side of the context area, near the bottom.  We could have
    chosen to iterate through the areas in a counter-clockwise fashion, but by using a builder
    model, we give the user more control of the order of choice.
    For example, the user might first prefer the right side near the bottom, then the left side near
    the bottom, followed by the top near the right, and then the bottom near the right.
     
    
    This first drawing shows the overall context of the inner bounds within an outer bounds along
    with a good placement and a bad placement that violates the outer bounds.
     
    
            +-----------------------------------------------+
            |                                        outer  |
            |                                               |
            |                                               |
            |      +------------------+                     |
            |      |       good       |                     |
            |      |     placement    |                     |
            |      |                  |                     |
            |      +------------------+---------+           |
            |                         |         |           |
            |                         |  inner  |           |
            |                         |         |           |
            |                         +---------+------------------+
            |                                   |       bad |      |
            |                                   |     placement    |
            +-----------------------------------+-----------+      |
                                                +------------------+
    
     
    
    The next two drawings show the LEFT and RIGHT edges with nominal locations of TOP, CENTER, and
    BOTTOM placements and the TOP and BOTTOM edges with nominal location of LEFT, CENTER, and
    RIGHT placements.  There are a total of eight of these locations ("cells") around the inner
    bounds.
     
    
                LEFT                            RIGHT
            +---------------+               +---------------+
            |               |               |               |
            |      TOP      |               |      TOP      |
            |               |               |               |
            +---------------X---------------X---------------+
            |               |               |               |
            |    CENTER     X     inner     X    CENTER     |
            |               |               |               |
            +---------------X---------------X---------------+
            |               |               |               |
            |    BOTTOM     |               |    BOTTOM     |
            |               |               |               |
            +---------------+               +---------------+
    
    
            +---------------+---------------+---------------+
            |               |               |               |
            |     LEFT      |    CENTER     |     RIGHT     | TOP
            |               |               |               |
            +---------------X-------X-------X---------------+
                            |               |
                            |     inner     |
                            |               |
            +---------------X-------X-------X---------------+
            |               |               |               |
            |     LEFT      |    CENTER     |     RIGHT     | BOTTOM
            |               |               |               |
            +---------------+---------------+---------------+
    
     
     
    
    These cells are shown in their nominal placement locations (where they touch the inner bounds,
    marked with an X).  However we will shift these locations by particular amounts so that these
    locations still fit within the outer bounds.  For instance, if we allow the BOTTOM cell
    on the LEFT edge to be shifted up far enough such that it fits the lower edge of the outer
    bounds, we limit this shift if it reaches the nominal placement of another specified cell
    (CENTER or TOP) on that edge.  If a solution is not found before the limit is reached, the
    placement fails.
     
    
    If the chosen cell is a CENTER cell, then it could shift up or down, depending on the
    circumstances and the parameters applied.
     
    
    These placements and shifts are controlled by specifying the **major** and **minorBegin**
    and **minorEnd** :obj:`Locations <Location>`.  The major Location specifies the **edge**
    for an :obj:`EdgePopupPlacer` and the minorBegin Location specifies the placement **cell**
    on this edge and the minorEnds specifies the last cell (amount of shift allowed), starting
    from the minorBegin Location.  For a CENTER minorBegin Location, the minorEnd cell may be
    any of the three allowed Locations on that major edge as well as null, representing that a
    shift is allowed in either direction.  When the minorEnd Location is set to the minorBegin
    Location, then no shift is permitted.
     
    
    Combinations of these placement attempts can be put together to create more complex strategies.
    See :obj:`PopupWindowPlacerBuilder` for examples of these.
     
    
    There are also :obj:`LeastOverlapCornerPopupWindowPlacer` and
    :obj:`ThrowsAssertExceptionPlacer`, for instance, that do not follow the same cell scheme.
    The first of these tries to make the placement at each of the corners of the inner
    bounds, but shifts these placements to fit the outer bounds in such a way that the inner
    bounds area may be occluded.  The placement on the corner which overlaps the least amount of
    the inner bounds area is chosen.  The second of these placers automatically throws an
    :obj:`AssertException`.  It is intended to be used in a builder model in which a sequence of
    placement attempts are made until good solution is found or until a null value is returned.
    This last placer, when chosen, serves as an assert condition, which is helpful
    in circumstances where the developer believes such an assertion is not possible,
    such as when allowing an overlapping placement solution.
    
    
    .. seealso::
    
        | :obj:`PopupWindowPlacerBuilder`
    """

    @typing.type_check_only
    class EdgePopupPlacer(PopupWindowPlacer):
        """
        Placer that attempts a placement on the ``major`` edge of the inner bounds, with
        ``minorBegin`` specifying the preferred cell location at which to start the
        placement attempt and ``minorEnd`` specifying that limit on the amount of shift
        that is made in an attempt to make the placement fit within the outer bounds.  The inner
        bounds is not allowed to be violated.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, major: Location, minorBegin: Location, minorEnd: Location):
            ...


    @typing.type_check_only
    class LeastOverlapCornerPopupWindowPlacer(PopupWindowPlacer):
        """
        Placer picks corner with toBePlaced as the least overlap with innerBounds. In the case of a
        tie, the tie-breaker is first in this order: Bottom Right, Bottom Left, Top Right, Top  Left.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ThrowsAssertExceptionPlacer(PopupWindowPlacer):
        """
        Set the next PopupWindowPlacer that throws an AssertException because no solution has
        been found by the time this placer is tried.  This is intended to be used when the client
        has already guaranteed that there is a solution (i.e., this placer is been used and the
        pop-up area will fit within the outer bounds).
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PositionableDimension(java.awt.Dimension):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dimension: java.awt.Dimension):
            ...


    @typing.type_check_only
    class HorizontalMajorDimension(PopupWindowPlacer.PositionableDimension):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dimension: java.awt.Dimension):
            ...


    @typing.type_check_only
    class VerticalMajorDimension(PopupWindowPlacer.PositionableDimension):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dimension: java.awt.Dimension):
            ...


    @typing.type_check_only
    class PositionableRectangle(java.awt.Rectangle):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, rectangle: java.awt.Rectangle):
            ...

        def set(self, majorCoordinate: typing.Union[jpype.JInt, int], minorCoordinate: typing.Union[jpype.JInt, int], dimension: PopupWindowPlacer.PositionableDimension):
            ...


    @typing.type_check_only
    class HorizontalMajorRectangle(PopupWindowPlacer.PositionableRectangle):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, rectangle: java.awt.Rectangle):
            ...


    @typing.type_check_only
    class VerticalMajorRectangle(PopupWindowPlacer.PositionableRectangle):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, rectangle: java.awt.Rectangle):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor only for classes that do not use placement preferences
        """

    @typing.overload
    def __init__(self, major: Location, minorBegin: Location, minorEnd: Location):
        """
        Constructor only for classes that specify major edge and minor begin and end location
        on that edge.
        
        :param Location major: edge
        :param Location minorBegin: start location on edge
        :param Location minorEnd: end location on edge
        
        .. seealso::
        
            | :obj:`PopupWindowPlacerBuilder`
        """

    def getPlacement(self, toBePlaced: java.awt.Dimension, innerBounds: java.awt.Rectangle, outerBounds: java.awt.Rectangle) -> java.awt.Rectangle:
        """
        Returns the placement Rectangle of toBePlaced Dimension for this PopupWindowPlacer. If it
        cannot find a solution, it tries the  :obj:`.next` PopupWindowPlacer and so forth until
        there are no others available, upon which null is returned if there is no solution.
        
        :param java.awt.Dimension toBePlaced: the Dimension
        :param java.awt.Rectangle innerBounds: the inner bounds Rectangle
        :param java.awt.Rectangle outerBounds: the out bounds in which the final result must fit
        :return: the placement Rectangle or null if extends outside the outerBounds
        :rtype: java.awt.Rectangle
        """



__all__ = ["Location", "PopupWindowPlacerBuilder", "PopupWindowPlacer"]
