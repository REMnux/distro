-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: yara
Binary: yara, libyara3, libyara-dev, yara-doc
Architecture: any all
Version: 4.0.2
Maintainer: Debian Security Tools <team+pkg-security@tracker.debian.org>
Uploaders: Hilko Bengen <bengen@debian.org>
Homepage: https://virustotal.github.io/yara/
Standards-Version: 4.3.0
Vcs-Browser: https://salsa.debian.org/pkg-security-team/yara
Vcs-Git: https://salsa.debian.org/pkg-security-team/yara.git
Build-Depends: debhelper, python3-sphinx, flex, bison, libjansson-dev, libmagic-dev, libssl-dev, pkg-config
Package-List:
 libyara-dev deb libdevel optional arch=any
 libyara3 deb libs optional arch=any
 yara deb utils optional arch=any
 yara-doc deb doc optional arch=all
Checksums-Sha1:
 5e4ad1bd653904da87f72512c3dcc9b9007e060c 888137 yara_4.0.2.orig.tar.gz
 bb7b5c6baea40ae8a179b05892a51f69127dc9b3 7248 yara_4.0.2.debian.tar.xz
Checksums-Sha256:
 05ad88eac9a9f0232432fd14516bdaeda14349d6cf0cac802d76e369abcee001 888137 yara_4.0.2.orig.tar.gz
 78c2ebf988d8bd8755713d51e57bb55144099347f6619315fcd3176faca0b334 7248 yara_4.0.2.debian.tar.xz
Files:
 46df98d0dd945f49725ff970f5aa5dc6 888137 yara_4.0.2.orig.tar.gz
 2b3eae1ed5aee8169dfc15bd4bc27bfd 7248 yara_4.0.2.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdZ3kvrDeRmm6bcxEytW8NijNGdsFAl8A2Y8ACgkQytW8NijN
GdvpRhAAwObuuMQBuucZwICASTbygzux5DQ7dtj/F01aisGrT+IbvzzcDyXMupNr
IRAXqkXa0skA5UQb7x9iSQzk1kQOz4fphZ9O5NIPvLHRExoDeG0jtWloU3wIrjWP
uBhwRD/sgy/KY/uFw/YZvRa44QSxH3yZ7UWCSilkiEIdzUle8v9+rnjAvRMeiLmf
llqikRHa7BAhkNeOVKUt/FnWTyFVN+rTKsX1brzAgNaTRrXrZ9ACTWMXUtVYu4Id
u9k1Jeqb6gkWCo6WqxyfNBPnKv4WRgfRfsdaFH8xickwha6KdbfVVaJtcHWOuYPv
PBRYl994XkOlBAAds7fhmRcTDmxXVMoWLqND0/PzXNJUFufnRz9lhrlwlwZinhwt
9w39l0FTUbTFXVyp4l3eG5XkiUjsDQ5pjToJF9KHHpTi4iyt7ZD2t6Lt/7Y6eioP
DMPLrw2TgkJv6CPHOXy6dZcTlFId8nlEdxzqIxI9QQBEHDQO0oEto6RVcHebOITu
aXAy9PY8r4CF9d+5qQRG7Y45cpBUYanoChSEmVIGzgo2tcWHjzpmWQYOtcZLacMA
sAJHoA7bogmtP+2vBJO9ymQB0C46zNwk59is4nWnqsMa1RrJXhct84jP11/iYLRp
+6KC0b8C8fatvI2h3Q0MaS0DqmZJy4O1TbdcU6BHcOgb12zBVVs=
=24Mr
-----END PGP SIGNATURE-----
