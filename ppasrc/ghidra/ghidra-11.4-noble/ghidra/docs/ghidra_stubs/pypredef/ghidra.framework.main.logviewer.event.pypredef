from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class MouseWheelAction(java.awt.event.MouseWheelListener):
    """
    Invoked when the user scrolls the mouse wheel either up or down. In this case we need to 
    fire off an event telling the viewport (or any other subscribers) that a scroll needs to 
    happen.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class PageUpAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the page up key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class ArrowUpAction(javax.swing.AbstractAction):
    """
    The up arrow should move the selection up one row. Just fire off an event to tell the
    viewer to decrement the selection, which may involve an adjustment to the viewport.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class PageUpSelectionAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the page up key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class PageDownSelectionAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the page down key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class FVEvent(java.lang.Object):
    """
    Custom events to be used in conjunction with the :obj:`FVEventListener` module. Users should
    construct an event, then fire it using :meth:`FVEventListener.send(FVEvent) <FVEventListener.send>`.
     
    Two items are passed along with each event:
        - The :obj:`.eventType` attribute specifies the event that is being fired.
        - The :obj:`.arg` is a generic object and can be populated with whatever is appropriate for the
    associated event. It's up to the receiver to understand how to parse it.
    """

    class EventType(java.lang.Enum[FVEvent.EventType]):

        class_: typing.ClassVar[java.lang.Class]
        COPY_SELECTION: typing.Final[FVEvent.EventType]
        DECREMENT_SELECTION: typing.Final[FVEvent.EventType]
        DECREMENT_AND_ADD_SELECTION: typing.Final[FVEvent.EventType]
        FILE_CHANGED: typing.Final[FVEvent.EventType]
        INCREMENT_SELECTION: typing.Final[FVEvent.EventType]
        INCREMENT_AND_ADD_SELECTION: typing.Final[FVEvent.EventType]
        OPEN_FILE_LOCATION: typing.Final[FVEvent.EventType]
        RELOAD_FILE: typing.Final[FVEvent.EventType]
        SLIDER_CHANGED: typing.Final[FVEvent.EventType]
        SCROLL_LOCK_OFF: typing.Final[FVEvent.EventType]
        SCROLL_LOCK_ON: typing.Final[FVEvent.EventType]
        VIEWPORT_UPDATE: typing.Final[FVEvent.EventType]
        VIEWPORT_UP: typing.Final[FVEvent.EventType]
        VIEWPORT_DOWN: typing.Final[FVEvent.EventType]
        VIEWPORT_PAGE_UP: typing.Final[FVEvent.EventType]
        VIEWPORT_PAGE_DOWN: typing.Final[FVEvent.EventType]
        SCROLL_HOME: typing.Final[FVEvent.EventType]
        SCROLL_END: typing.Final[FVEvent.EventType]
        SCROLL_END_2: typing.Final[FVEvent.EventType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FVEvent.EventType:
            ...

        @staticmethod
        def values() -> jpype.JArray[FVEvent.EventType]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    eventType: FVEvent.EventType
    arg: java.lang.Object

    def __init__(self, eventType: FVEvent.EventType, arg: java.lang.Object):
        """
        
        
        :param FVEvent.EventType eventType: 
        :param java.lang.Object arg:
        """


class FVEventListener(java.util.Observable):
    """
    Extension of the Java :obj:`Observer` class that allows clients to send :obj:`FVEvent`
    messages to subscribers.
    
     
    Note: this 'listener' class serves as an event 'hub', where clients can push events to this
    class and register to receive events from this class.   The events given to this listener are
    heterogeneous and serve as a general message passing system for this API.   This class should
    be replaced by simple object communication by using normal method calls.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def send(self, evt: FVEvent):
        """
        Fires off the given :obj:`FVEvent` using the appropriate :obj:`Observer` methods.
        
        :param FVEvent evt:
        """


class EndAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the 'end' key; this moves the viewport
    to the bottom of the file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class ArrowDownSelectionAction(javax.swing.AbstractAction):
    """
    The down arrow should move the selection down one row. Just fire off an event to tell the
    viewer to increment the selection, which may involve an adjustment to the viewport.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class PageDownAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the page down key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class HomeAction(javax.swing.AbstractAction):
    """
    Handles the actions required when the user presses the 'home' key; this moves the viewport
    to the top of the file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class ArrowDownAction(javax.swing.AbstractAction):
    """
    The down arrow should move the selection down one row. Just fire off an event to tell the
    viewer to increment the selection, which may involve an adjustment to the viewport.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...


class ArrowUpSelectionAction(javax.swing.AbstractAction):
    """
    The up arrow should move the selection up one row. Just fire off an event to tell the
    viewer to decrement the selection, which may involve an adjustment to the viewport.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: FVEventListener):
        ...



__all__ = ["MouseWheelAction", "PageUpAction", "ArrowUpAction", "PageUpSelectionAction", "PageDownSelectionAction", "FVEvent", "FVEventListener", "EndAction", "ArrowDownSelectionAction", "PageDownAction", "HomeAction", "ArrowDownAction", "ArrowUpSelectionAction"]
