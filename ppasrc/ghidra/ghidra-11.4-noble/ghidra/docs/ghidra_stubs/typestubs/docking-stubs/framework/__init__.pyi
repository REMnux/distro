from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import ghidra.framework
import ghidra.util
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class AboutDialog(docking.DialogComponentProvider):
    """
    Splash screen window to display version information about the current release of
    the Ghidra application. The window is displayed when Ghidra starts; when
    initialization is complete, the splash screen is dismissed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class ApplicationInformationDisplayFactory(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def createAboutComponent() -> javax.swing.JComponent:
        ...

    @staticmethod
    def createAboutTitle() -> str:
        ...

    @staticmethod
    def createHelpLocation() -> ghidra.util.HelpLocation:
        ...

    @staticmethod
    def createSplashScreenComponent() -> javax.swing.JComponent:
        ...

    @staticmethod
    def createSplashScreenTitle() -> str:
        ...

    @staticmethod
    def getHomeCallback() -> java.lang.Runnable:
        ...

    @staticmethod
    def getHomeIcon() -> javax.swing.Icon:
        ...

    @staticmethod
    def getLargestWindowIcon() -> java.awt.Image:
        ...

    @staticmethod
    def getWindowIcons() -> java.util.List[java.awt.Image]:
        ...


class SplashScreen(javax.swing.JWindow):
    """
    Splash screen window to display version information about the current release of
    the Ghidra application. The window is displayed when Ghidra starts; when
    initialization is complete, the splash screen is dismissed.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def disposeSplashScreen():
        """
        Remove the splash screen; Ghidra is done loading.
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    @staticmethod
    def showLater():
        """
        Show the splash screen on the Swing thread later.
        """

    @staticmethod
    def showNow() -> SplashScreen:
        """
        Show the splash screen on the Swing thread now.  This will block.
        
        :return: the new splash screen
        :rtype: SplashScreen
        """

    @staticmethod
    def updateSplashScreenStatus(status: typing.Union[java.lang.String, str]):
        """
        Update the load status on the splash screen.
        
        :param java.lang.String or str status: string to put in the message area of the splash screen
        """


class DockingApplicationConfiguration(ghidra.framework.ApplicationConfiguration):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def isShowSplashScreen(self) -> bool:
        ...

    def setShowSplashScreen(self, showSplashScreen: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def showSplashScreen(self) -> jpype.JBoolean:
        ...

    @showSplashScreen.setter
    def showSplashScreen(self, value: jpype.JBoolean):
        ...



__all__ = ["AboutDialog", "ApplicationInformationDisplayFactory", "SplashScreen", "DockingApplicationConfiguration"]
