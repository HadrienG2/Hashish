QMAKE_CXXFLAGS += -std=c++0x -U__STRICT_ANSI__ -Wall

QT += network

RESOURCES = hashish.qrc

SOURCES += main.cpp \
    return_filter.cpp \
    main_window.cpp \
    service_window.cpp \
    crypto_hash.cpp \
    password_generator.cpp \
    hmac.cpp \
    qstring_to_qwords.cpp \
    password_cipher.cpp \
    service_descriptor.cpp \
    service_manager.cpp \
    parsing_tools.cpp \
    password_window.cpp \
    settings_window.cpp \
    about_window.cpp \
    error_management.cpp \
    test_suite.cpp

HEADERS += return_filter.h \
    main_window.h \
    service_window.h \
    service_descriptor.h \
    crypto_hash.h \
    password_generator.h \
    hmac.h \
    qstring_to_qwords.h \
    password_cipher.h \
    service_manager.h \
    parsing_tools.h \
    password_window.h \
    settings_window.h \
    about_window.h \
    error_management.h \
    test_suite.h

TRANSLATIONS = hashish_fr.ts \
               hashish_en.ts

# make install rule
unix {
    isEmpty(PREFIX) {
        PREFIX = /usr/local
    }

    binaries.path  = $$PREFIX/bin
    binaries.files = $$TARGET
    icon.path  = /usr/share/pixmaps/
    icon.files = hashish.png

    INSTALLS += binaries icon
}

#Windows resources
windows {
    RC_FILE = win_hashish.rc
}

OTHER_FILES += \
    win_hashish.rc \
    hashish_fr.ts \
    hashish_fr.qm \
    hashish_en.ts \
    hashish_en.qm \
    hashish.xcf \
    hashish.ico \
    hashish.desktop \
    hashish.png \
    COPYING \
    Tests/SHA-512.testvecs \
    "Tests/RFC 2104.testvecs" \
    "Tests/OFB-chained XOR cipher.testvecs" \
    "Tests/Default generator.testvecs" \
    README
