TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += $$PWD/../../lib

LIBS += -L$$PWD/../../../target/lib/ -lcrypto
DEPENDPATH += $$PWD/../../../target
PRE_TARGETDEPS += $$PWD/../../../target/lib/libcrypto.a

SOURCES += \
        main.cpp

include($$PWD/../../../base_configuration.pri)
