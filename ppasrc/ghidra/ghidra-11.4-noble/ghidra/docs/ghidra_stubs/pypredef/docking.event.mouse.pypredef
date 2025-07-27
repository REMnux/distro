from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore


class GMouseListenerAdapter(java.awt.event.MouseAdapter):
    """
    A mouse listener implementation designed to provide consistent handling of triggers for
    popups and double-clicking.
     
    
    Notes:
     
    * Popup triggers always supersedes double-click actions.
    * The stage an action triggers (pressed/released/clicked) is platform dependent.
    * Each of the methods mentioned below will be called as appropriate.
    * You can override any of these methods to be called for each trigger.
    * Normally popups are handled by the framework via custom actions.  But, for custom
    widgets it is sometimes simpler to handle your own popups.  This class makes that
    easier
    
    
    
    .. seealso::
    
        | :obj:`.popupTriggered(MouseEvent)`
    
        | :obj:`.doubleClickTriggered(MouseEvent)`
    
        | :obj:`.shouldConsume(MouseEvent)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def doubleClickTriggered(self, e: java.awt.event.MouseEvent):
        """
        Called when a double-click event is discovered.
        
        :param java.awt.event.MouseEvent e: the event that triggered the double-click
        """

    def popupTriggered(self, e: java.awt.event.MouseEvent):
        """
        Called when a popup event is discovered.
        
        :param java.awt.event.MouseEvent e: the event that triggered the popup
        """

    def shouldConsume(self, e: java.awt.event.MouseEvent) -> bool:
        """
        This method is called to ask the client if they wish to consume the given event.  This
        allows clients to keep events from propagating to other listeners.
        
        :param java.awt.event.MouseEvent e: the event to potentially consume
        :return: true if the event should be consumed
        :rtype: bool
        """



__all__ = ["GMouseListenerAdapter"]
