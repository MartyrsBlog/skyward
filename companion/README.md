# Companion directories

The service directories a phone's own HALs register with, and the libraries
they are built against, of the version diting's vendor image is. A HIDL
service registers only with a directory of its own version, so an image for
this phone carries these under `/skyward/hidl/a31/`.

They are not built here: they are taken from the recovery the phone's own ROM
ships, which is the only place on this phone they exist.
