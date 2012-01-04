/* Hashish's main program

      Copyright (C) 2011  Hadrien Grasland

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA */

#include <QApplication>
#include <QLocale>
#include <QTranslator>

#include <main_window.h>
#include <service_manager.h>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    //Translate application using available locales (+ English as a fallback)
    QString locale = QLocale::system().name();
    QTranslator translator;
    bool success = translator.load(QString("hashish_") + locale, ":/");
    if(!success) translator.load(QString("hashish_en"), ":/");
    app.installTranslator(&translator);

    //Setup initial app environment
    app.setApplicationName(app.translate("CoreApplication", "Hashish"));
    app.setWindowIcon(QIcon(":/hashish.png"));

    //Initialize ServiceManager backend
    ServiceManager service_manager;

    //Create and display main window
    MainWindow main_window(service_manager);
    main_window.setWindowTitle(app.translate("CoreApplication", "Hashish"));
    main_window.show();

    return app.exec();
}
