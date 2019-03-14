QT						-= core gui

TARGET					= aes

TEMPLATE				= lib
CONFIG					+= staticlib
DESTDIR					= $$PWD/../../target/lib

SOURCES					+=

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
    sha2.h \
    sha2constants.h

include($$PWD/../../base_configuration.pri)
