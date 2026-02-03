from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.listener
import docking.widgets.fieldpanel.support
import ghidra.app.decompiler
import ghidra.program.model.listing
import java.awt # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class DecompilerMarginProvider(java.lang.Object):
    """
    A provider of a margin Swing component
     
     
    
    To add a margin to the decompiler, a client must implement this interface to provide the
    component that is actually added to the UI. For a reference implementation, see
    :obj:`LineNumberDecompilerMarginProvider`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getComponent(self) -> java.awt.Component:
        """
        Get the Swing component implementing the actual margin, often ``this``
        
        :return: the component
        :rtype: java.awt.Component
        """

    def setOptions(self, options: ghidra.app.decompiler.DecompileOptions):
        """
        Set the options for the margin
         
         
        
        This is called at least once when the provider is added to the margin service. See
        :meth:`DecompilerMarginService.addMarginProvider(DecompilerMarginProvider) <DecompilerMarginService.addMarginProvider>`. It subsequently
        called whenever a decompiler option changes. To receive other options, the provider will need
        to listen using its own mechanism.
         
         
        
        A call to this method should cause the component to be repainted. Implementors may choose to
        repaint only when certain options change.
        """

    def setProgram(self, program: ghidra.program.model.listing.Program, model: docking.widgets.fieldpanel.LayoutModel, pixmap: LayoutPixelIndexMap):
        """
        Called whenever the program, function, or layout changes
         
         
        
        The implementation should keep a reference at least to the ``model`` and the
        ``pixmap`` for later use during painting. The model provides access to the lines of
        decompiler C code. Each layout corresponds to a single line of C code. For example, the first
        line of code is rendered by the layout at index 0. The tenth is rendered by the layout at
        index 9. Rarely, a line may be wrapped by the renderer, leading to a non-uniform layout. The
        ``pixmap`` can map from a pixel's vertical position to the layout index at the same
        position in the main panel. It accounts for scrolling an non-uniformity. It is safe to assume
        the layouts render contiguous lines of C code. The recommended strategy for painting is thus:
         
         
        1. Compute the visible part of the margin needing repainting. See
        :meth:`JComponent.getVisibleRect() <JComponent.getVisibleRect>`
        2. Compute the layout indices for the vertical bounds of that part. See
        :meth:`LayoutPixelIndexMap.getIndex(int) <LayoutPixelIndexMap.getIndex>`
        3. Iterate over the layouts within those bounds, inclusively.
        4. Compute the vertical position of each layout and paint something appropriate for its
        corresponding line. See:meth:`LayoutPixelIndexMap.getPixel(BigInteger) <LayoutPixelIndexMap.getPixel>`
        
         
         
        
        A call to this method should cause the component to be repainted.
        
        :param ghidra.program.model.listing.Program program: the program for the current function
        :param docking.widgets.fieldpanel.LayoutModel model: the line/token model
        :param LayoutPixelIndexMap pixmap: a map from pixels' y coordinates to layout index, i.e, line number
        """

    @property
    def component(self) -> java.awt.Component:
        ...


class VerticalLayoutPixelIndexMap(LayoutPixelIndexMap):
    """
    An implementation of :obj:`LayoutPixelIndexMap` for vertical coordinates
     
     
    
    This class implements :meth:`getIndex(int) <.getIndex>` in log time and :meth:`getPixel(BigInteger) <.getPixel>` in
    constant time.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def layoutsChanged(self, layouts: java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]):
        ...


class LayoutPixelIndexMap(java.lang.Object):
    """
    A mapping from pixel coordinate to layout index
     
     
    
    At the moment, the only implementation provides a map from vertical position to layout. While
    this does not have to be the case, the documentation will presume the y coordinate.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getIndex(self, pixel: typing.Union[jpype.JInt, int]) -> java.math.BigInteger:
        """
        Get the index of the layout at the given position
         
         
        
        Get the index of the layout occupying the line of pixels in the main panel having the given y
        coordinate. In essence, this maps from vertical position, relative to the main panel's
        viewport, to layout index. This accounts for scrolling and non-uniform height among the
        layouts.
        
        
        .. admonition:: Implementation Note
        
            Clients should avoid frequent calls to this method. Even though it can be
            implemented easily in log time, an invocation for every pixel or line of pixels
            painted could still be unnecessarily expensive. It should only be necessary to call
            this once or twice per repaint. See
            :meth:`DecompilerMarginProvider.setProgram(Program, LayoutModel, LayoutPixelIndexMap) <DecompilerMarginProvider.setProgram>`.
        
        
        :param jpype.JInt or int pixel: the vertical position of the pixel, relative to the main panel's viewport
        :return: the index of the layout
        :rtype: java.math.BigInteger
        """

    def getPixel(self, index: java.math.BigInteger) -> int:
        """
        Get the top of the layout with the given index
         
         
        
        Gets the minimum y coordinate of any pixel occupied by the layout having the given index. In
        essence, this maps from layout index to vertical position, relative to the main panel's
        viewport. This accounts for scrolling and non-uniform height among the layouts.
        
        :param java.math.BigInteger index: the index of the layout
        :return: the top of the layout, relative to the main panel's viewport
        :rtype: int
        """

    @property
    def index(self) -> java.math.BigInteger:
        ...

    @property
    def pixel(self) -> jpype.JInt:
        ...


class LineNumberDecompilerMarginProvider(javax.swing.JPanel, DecompilerMarginProvider, docking.widgets.fieldpanel.listener.LayoutModelListener):
    """
    The built-in provider for the Decompiler's line number margin
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["DecompilerMarginProvider", "VerticalLayoutPixelIndexMap", "LayoutPixelIndexMap", "LineNumberDecompilerMarginProvider"]
