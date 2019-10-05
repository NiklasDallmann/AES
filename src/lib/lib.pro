QT						-= core gui

TARGET					= crypto

TEMPLATE				= lib
CONFIG					+= staticlib
DESTDIR					= $$PWD/../../target/lib

SOURCES					+= \
    sha2digest.cpp

HEADERS					+= \
    aesblock.h \
    aesconstants.h \
    aestraits.h \
    cryptoglobals.h \
    ciphermode.h \
    cryptoutilities.h \
    cipherkey.h \
    ctrmode.h \
    sha2traits.h \
    sha2constants.h \
    sha2digest.h \
    cbcmode.h \
    paddingtype.h

include($$PWD/../../base_configuration.pri)
