from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import java.awt.event # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class FieldListener(java.lang.Object):
    """
    Listener interface for objects that are notified when a change is made to a Field, or Fields
    were added or removed from a set of Fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dataChanged(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Notifies the listener the data in the models has changed within the given
        index range.
        
        :param jpype.JInt or int min: the minimum index affected by the data change.
        :param jpype.JInt or int max: the maximum index affected by the data change.
        """

    def indexSetChanged(self):
        """
        Notifies the listener when the set of indexes changes - either the number
        of indexes or the fundamental data types associated with thos indexes.
        """

    def widthChanged(self, width: typing.Union[jpype.JInt, int]):
        """
        Notifies the listener that the width of this field has changed.
        
        :param jpype.JInt or int width: the new widht of the field.
        """


class IndexMapper(java.lang.Object):
    """
    Interface for mapping indexes when the LayoutModel changes. In other words, if the mapping
    of layout indexes to some data model changes and you want the :obj:`FieldPanel` to continue
    to display the same model data on the screen, the IndexMapper can be used to convert old
    indexes to new indexes.
    """

    class_: typing.ClassVar[java.lang.Class]
    IDENTITY_MAPPER: typing.Final[IndexMapper]

    def map(self, value: java.math.BigInteger) -> java.math.BigInteger:
        """
        Maps an index from one address mapping to another. This method will return
        :obj:`BigInteger.ZERO` if there no mapping.
        
        :param java.math.BigInteger value: the index value to map from an old index map to a new index map
        :return: the mapped index
        :rtype: java.math.BigInteger
        """


class FieldMouseListener(java.lang.Object):
    """
    Listener interface for mouse pressed events in the field panel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def buttonPressed(self, location: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, ev: java.awt.event.MouseEvent):
        """
        Called whenever the mouse button is pressed.
        
        :param docking.widgets.fieldpanel.support.FieldLocation location: the field location of the mouse pointer
        :param docking.widgets.fieldpanel.field.Field field: the Field object that was clicked on
        :param java.awt.event.MouseEvent ev: the mouse event that generated this call.
        """


class FieldSelectionListener(java.lang.Object):
    """
    Listener interface for when the selection changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectionChanged(self, selection: docking.widgets.fieldpanel.support.FieldSelection, trigger: docking.widgets.EventTrigger):
        """
        Called whenever the FieldViewer selection changes.
        
        :param docking.widgets.fieldpanel.support.FieldSelection selection: the new selection.
        :param docking.widgets.EventTrigger trigger: indicates the cause of the selection changing
        """


class LayoutListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def layoutsChanged(self, layouts: java.util.List[docking.widgets.fieldpanel.support.AnchoredLayout]):
        ...


class FieldInputListener(java.lang.Object):
    """
    Interface implemented by objects that want to be notified when key events occur
    in the FieldPanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def keyPressed(self, ev: java.awt.event.KeyEvent, index: java.math.BigInteger, fieldNum: typing.Union[jpype.JInt, int], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], field: docking.widgets.fieldpanel.field.Field):
        """
        Called when the FieldPanel receives a KeyEvent that it doesn't handle.
        
        :param java.awt.event.KeyEvent ev: The KeyEvent generated when the user presses a key.
        :param java.math.BigInteger index: the index of the layout the cursor was on when the key was pressed.
        :param jpype.JInt or int fieldNum: the field index of the field the cursor was on when the key was
        pressed.
        :param jpype.JInt or int row: the row in the field the cursor was on when the key was pressed.
        :param jpype.JInt or int col: the col in the field the cursor was on when the key was pressed.
        :param docking.widgets.fieldpanel.field.Field field: current field the cursor was on when the key was pressed.
        """


class ViewListener(java.lang.Object):
    """
    Listener interface for notification when the top of screen position changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    def viewChanged(self, fp: docking.widgets.fieldpanel.FieldPanel, index: java.math.BigInteger, xOffset: typing.Union[jpype.JInt, int], yOffset: typing.Union[jpype.JInt, int]):
        """
        Notifies the listener that the top of the screen has changed position.
        
        :param docking.widgets.fieldpanel.FieldPanel fp: the field panel whose view changed.
        :param java.math.BigInteger index: the index of the layout at the top of the screen.
        :param jpype.JInt or int xOffset: the x coordinate of the layout displayed at the left of the
        screen.
        :param jpype.JInt or int yOffset: the y coordinate of the layout displayed at the top of the
        screen.
        """


class LayoutModelListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def dataChanged(self, start: java.math.BigInteger, end: java.math.BigInteger):
        """
        Called when the data at an index or range of indexes changes.
        
        :param java.math.BigInteger start: the starting index for the region of data changes.
        :param java.math.BigInteger end: the ending index (inclusive) for the region of data changes.
        """

    def modelSizeChanged(self, indexMapper: IndexMapper):
        """
        Called whenever the number of indexes changed
        
        :param IndexMapper indexMapper: Maps indexes from before the model size change to indexes after
        the model size changed.
        """


class FieldLocationListener(java.lang.Object):
    """
    Listener interface for field location changes
    """

    class_: typing.ClassVar[java.lang.Class]

    def fieldLocationChanged(self, location: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, trigger: docking.widgets.EventTrigger):
        """
        Called whenever the cursor position changes.
        
        :param docking.widgets.fieldpanel.support.FieldLocation location: the new field location.
        :param docking.widgets.fieldpanel.field.Field field: the Field object containing the location.
        :param docking.widgets.EventTrigger trigger: the type of the location change
        """


class FieldOverlayListener(java.lang.Object):
    """
    Interface implemented by objects that want to be notified when an overlay
    is removed from the FieldPanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fieldOverlayRemoved(self, comp: javax.swing.JComponent):
        """
        Called when the an existing component is removed from the FieldPanel.
        
        :param javax.swing.JComponent comp: the overlay component that was removed.
        """



__all__ = ["FieldListener", "IndexMapper", "FieldMouseListener", "FieldSelectionListener", "LayoutListener", "FieldInputListener", "ViewListener", "LayoutModelListener", "FieldLocationListener", "FieldOverlayListener"]
