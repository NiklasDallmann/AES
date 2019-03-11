QT						-= core gui

TARGET					= aes

TEMPLATE				= lib
CONFIG					+= staticlib
DESTDIR					= $$PWD/../../target/lib

SOURCES					+=

HEADERS					+= \
    utilities.h \
    key.h \
    constants.h \
    block.h \
    mode.h \
    ctr.h

include($$PWD/../../base_configuration.pri)
