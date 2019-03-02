QT						-= core gui

TARGET					= aes

TEMPLATE				= lib
CONFIG					+= staticlib
DESTDIR					= $$PWD/../../target/lib

SOURCES					+= \
    primitiveblock.cpp

HEADERS					+= \
    primitiveblock.h

include($$PWD/../../base_configuration.pri)
