QT						-= core gui

TARGET					= aes

TEMPLATE				= lib
CONFIG					+= staticlib
DESTDIR					= $$PWD/../../target/lib

SOURCES					+=

HEADERS					+= \
    primitiveblock.h \
    utilities.h \
    key.h \
    constants.h

include($$PWD/../../base_configuration.pri)
