/* Hashish's main window : centralizes all other windows under a tabbed interface

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

#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QWidget>
#include <QString>
#include <QStringListModel>
#include <QTabWidget>
#include <QVBoxLayout>

#include <password_window.h>
#include <service_manager.h>
#include <service_window.h>
#include <settings_window.h>

class MainWindow : public QWidget {
    Q_OBJECT

  public:
    MainWindow(ServiceManager& service_manager,
               const int max_height = 200,
               const int max_width = 300);

  public slots:
    void create_service(const QString& service_name);
    void editing_done(const QString& new_service_name);
    void reset_main_window_size();

  private:
    AboutWindow* about_window;
    PasswordWindow* password_window;
    ServiceWindow* service_window;
    SettingsWindow* settings_window;
    int tab_height;
    int tab_width;
    QTabWidget* tab_widget;
    QVBoxLayout* vbox_layout;
};

#endif // MAIN_WINDOW_H
