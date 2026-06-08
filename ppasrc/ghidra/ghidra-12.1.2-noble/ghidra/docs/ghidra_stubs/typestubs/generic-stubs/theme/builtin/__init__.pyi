from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.theme


class NimbusTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Nimbus :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class MacTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Aqua :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class GTKTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the GTK+ :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class MetalTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Metal :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class FlatLightTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the FlatLight :obj:`LookAndFeel` and the dark application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class CDEMotifTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Motif :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class WindowsClassicTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Windows Classic :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class FlatDarkTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the FlatDark :obj:`LookAndFeel` and the dark application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


class WindowsTheme(generic.theme.DiscoverableGTheme):
    """
    Built-in GTheme that uses the Windows :obj:`LookAndFeel` and the standard (light)
    application defaults.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...



__all__ = ["NimbusTheme", "MacTheme", "GTKTheme", "MetalTheme", "FlatLightTheme", "CDEMotifTheme", "WindowsClassicTheme", "FlatDarkTheme", "WindowsTheme"]
