/* Hashish's password generation window : allows the user to choose a service name
   and enter a master password to generate a service password

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

#ifndef PW_WINDOW_H
#define PW_WINDOW_H

#include <QClipboard>
#include <QCompleter>
#include <QPushButton>
#include <QLineEdit>
#include <QFormLayout>
#include <QString>
#include <QStringListModel>
#include <QVBoxLayout>

#include <return_filter.h>
#include <service_manager.h>

class PasswordWindow : public QWidget {
    Q_OBJECT

  public:
    PasswordWindow(ServiceManager& service_manager,
                   const int min_service_width = 250,
                   const int min_masterpw_width = 200);

  signals:
    void create_service(const QString& service_name);
    void generate_password(const QString& service_name, const QString& master_password);

  public slots:
    void editing_done(const QString& new_service_name);
    void password_generation_failed();
    void password_ready(const QString& password);

  private slots:
    void service_edit_changed();
    void service_edit_return_pressed();
    void start_password_generation();
    void verify_service();

  private:
    QPushButton* confirm_button;
    ReturnFilter* confirm_button_return_filter;
    QFormLayout* form_layout;
    QVBoxLayout* vert_layout;
    QLineEdit* masterpw_edit;
    QString masterpw_buffer;
    ReturnFilter* masterpw_edit_return_filter;
    bool service_changed;
    QCompleter* service_completion;
    QLineEdit* service_edit;
    ReturnFilter* service_edit_return_filter;
    QString service_name_buffer;
    QStringListModel* service_names_mod;
};

#endif // PW_WINDOW_H
