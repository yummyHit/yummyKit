#-------------------------------------------------
#
# Project created by QtCreator 2017-01-09T19:04:27
#
#-------------------------------------------------

QT       += core gui
QT       += network
QT       += widgets
LIBS     += -lpthread -lpcap

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = yummyKit
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += main.cpp\
        mainwindow.cpp \
    scanning.cpp \
    falsify.cpp \
    spoofurl.cpp \
    routing_thread.cpp \
    relay_falsify.cpp \
    relay_spoof.cpp \
    hostname.cpp \
    wifi_cracking.cpp

HEADERS  += mainwindow.h \
    scanning.h \
    falsify.h \
    spoofurl.h \
    routing_thread.h \
    relay_falsify.h \
    relay_spoof.h \
    statusq.h \
    hostname.h \
    wifi_cracking.h

FORMS    += mainwindow.ui \
    scanning.ui \
    falsify.ui \
    spoofurl.ui \
    wifi_cracking.ui
