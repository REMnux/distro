-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: yara
Binary: yara, libyara3, libyara-dev, yara-doc
Architecture: any all
Version: 4.0.2-focal
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
 5c14f2a4ce6dd6f7a8e2ecd9047affdcf8d262f0 7232 yara_4.0.2-focal.debian.tar.xz
Checksums-Sha256:
 05ad88eac9a9f0232432fd14516bdaeda14349d6cf0cac802d76e369abcee001 888137 yara_4.0.2.orig.tar.gz
 aad3ded7fefac18c1d5bb7e9866c2badea027f88880db336266014daac43213e 7232 yara_4.0.2-focal.debian.tar.xz
Files:
 46df98d0dd945f49725ff970f5aa5dc6 888137 yara_4.0.2.orig.tar.gz
 31b89bd22d0955084e32b76bbca71ed9 7232 yara_4.0.2-focal.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdZ3kvrDeRmm6bcxEytW8NijNGdsFAl+8Nt4ACgkQytW8NijN
Gdt9FA/+PdoFp+VfPKUOuvhVsdhjzsaiIJkoeAMZ55FcDz4eV0UYUWeg1WDfofAV
8bW6VkU1MKKs9HzfdC79Mc7+s0ossR7BtTT8aly++98L2jTc1UETIkFT0V/DMgEh
hr4vJhlIlFS5sV24n1H0vm9uNBYyXoMPOFA/CU/oyMDXrGOUbVDUWKYgd4Nbddv9
JGdvntFUWFAqI0KRlfZG4YOJJm0TrcL20hsHbQ8PoGtYS9t+1+MMuAvw7KkAmc3M
r7O9082Dx2YvMbdYuH1RE6QSNUYFkZmKWjcwZxEBlZE4V+X+d3vi/OnVaOXGeUN0
TsB1ZOR+4QuzQJjFfSECPFRDvqs636osIyMBZF+8Vmt0QJK+jrbv3hhGSdy5avUM
LZJ7KkpDFLRyXLFVebIwaU+N6gy4Iykpu0PSBlFEPUaUkWRQmeWSYfILQC7mzH69
qhtVi73ZHpxDvBjVfarX/hEIDuiRrMbHgVutZyWVQVApemii7LgUDwfknIahhYDU
viun7Y9EtvYSRMpmOsyZ3eqW70RBUORQ6GO7XNE6nf4QqrNAQKToDHvN0wb/rC9s
HmvhZ/XVfusNWVS6SB0l2TDoJk9WvnNLUuxWf7kzvSF4SNHgZTLOa528i/Z67jSY
m2IZ+pztbfv26pb02PTkUD43hMoEBtj3N+6FeXMAk0ahsGRe420=
=252x
-----END PGP SIGNATURE-----
