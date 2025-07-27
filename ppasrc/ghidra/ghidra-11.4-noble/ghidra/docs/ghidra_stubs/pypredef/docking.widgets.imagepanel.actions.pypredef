from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.action
import docking.widgets.imagepanel
import java.lang # type: ignore


class ZoomOutAction(ImagePanelDockingAction):
    """
    An action to de-zoom the image on a NavigableImagePanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...


class ResetTranslationAction(ImagePanelDockingAction):
    """
    An action to re-center the image on a NavigableImagePanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...


@typing.type_check_only
class ImagePanelDockingAction(docking.action.DockingAction):
    """
    Base class of DockingActions that require a NavigableImagePanel
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...


class ZoomResetAction(ImagePanelDockingAction):
    """
    An action to reset the zoom of a NavigableImagePanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...


class SaveImageAction(ImagePanelDockingAction):
    """
    An action to save the image from a NavigableImagePanel to a file.
     
    
    The user is asked to provide a file to save the image to.
     
    
    This class uses the ImageIO library to write the image to a file;
    the image format is determined by filename extension -- PNG, GIF and JPG extensions are 
    recognized and honored, other extensions are ignored, and the file is written in PNG 
    format. Image transparency is honored when possible.
    
    
    .. seealso::
    
        | :obj:`javax.imageio.ImageIO`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...


class ZoomInAction(ImagePanelDockingAction):
    """
    An action to zoom the image on a NavigableImagePanel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], imagePanel: docking.widgets.imagepanel.ImagePanel):
        ...



__all__ = ["ZoomOutAction", "ResetTranslationAction", "ImagePanelDockingAction", "ZoomResetAction", "SaveImageAction", "ZoomInAction"]
