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

#include <QApplication>
#include <QMessageBox>
#include <main_window.h>
#include <test_suite.h>

#include <QTimer>

MainWindow::MainWindow(ServiceManager& service_manager,
                       const int max_height,
                       const int max_width) {
    service_man = &service_manager;

    //Set window title
    setWindowTitle(qApp->translate("CoreApplication", "Hashish"));

    //Ensure that this window does not become too large
    setMaximumHeight(max_height);
    setMaximumWidth(max_width);

    //Generate password window
    password_window = new PasswordWindow(service_manager);

    //Generate service window
    service_window = new ServiceWindow(service_manager);

    //Generate settings window
    settings_window = new SettingsWindow(service_manager);

    //Generate About windows
    about_window = new AboutWindow;

    //Generate tabbed layout
    vbox_layout = new QVBoxLayout;
    tab_widget = new QTabWidget;
    tab_widget->addTab(password_window, tr("&Passwords"));
    tab_widget->addTab(service_window, tr("&Services"));
    tab_widget->addTab(settings_window, tr("Se&ttings"));
    tab_widget->addTab(about_window, tr("A&bout"));
    vbox_layout->addWidget(tab_widget);
    setLayout(vbox_layout);

    //Switch keyboard focus to password window
    tab_widget->setCurrentIndex(0);
    password_window->setFocus();

    //Connect signals and slots of different windows together
    connect(password_window,
            SIGNAL(create_service(const QString&)),
            this,
            SLOT(create_service(const QString&)));

    //Prepare window size reset mechanism
    connect(service_window,
            SIGNAL(reset_main_window_size()),
            this,
            SLOT(reset_main_window_size()));

    //Display a warning if the cryptographic functions have not passed the required tests
    if(service_manager.crypto_function_tests_passed() == false) {
        QMessageBox::warning(this,
                             tr("Self-check failed"),
                             WARNING_TESTS_FAILED);
    }

    //Recreate the main window each time a new instance of Hashish should be spawned
    connect(service_man,
            SIGNAL(new_instance_spawned()),
            this,
            SLOT(new_instance_spawned()));
}

void MainWindow::create_service(const QString& service_id) {
    connect(service_window,
            SIGNAL(editing_done(const QString&)),
            this,
            SLOT(editing_done(const QString&)));
    service_window->create_service(service_id);
    tab_widget->setCurrentIndex(1);
    service_window->setFocus();
}

void MainWindow::editing_done(const QString &new_service_name) {
    disconnect(service_window,
               SIGNAL(editing_done(const QString&)),
               this,
               SLOT(editing_done(const QString&)));
    service_window->clear_service_edit();
    password_window->editing_done(new_service_name);
    tab_widget->setCurrentIndex(0);
    password_window->setFocus();
}

void MainWindow::new_instance_spawned() {
    //Recreates the main window of Hashish so that it goes to the current desktop
    hide();
    MainWindow* new_win = new MainWindow(*service_man, maximumHeight(), maximumWidth());
    new_win->setWindowTitle(windowTitle());
    new_win->show();
    service_man->delete_qobject(this);
}

void MainWindow::reset_main_window_size() {
    tab_widget->adjustSize();
    adjustSize();
}
