/* Hashish's service window : allows for the creation, deletion, and edition of
   service records

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

#ifndef SERVICE_WINDOW_H
#define SERVICE_WINDOW_H

#include <QCheckBox>
#include <QCompleter>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListView>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QString>
#include <QStringListModel>
#include <QVBoxLayout>
#include <QWidget>

#include <return_filter.h>
#include <service_manager.h>
#include <service_descriptor.h>

class ServiceWindow : public QWidget {
    Q_OBJECT

  public:
    ServiceWindow(ServiceManager& service_manager,
                  const int min_service_width = 250);

  signals:
    void add_service(const QString& service_name);
    void editing_done(const QString& new_service_name);
    void load_service(const QString& service_name);
    void remove_service(const QString& service_name);
    void reset_main_window_size();
    void save_service(const QString& previous_name, const QString& new_name, ServiceDescriptor& service);

  public slots:
    void clear_service_edit();
    void create_service(const QString& service_name);
    void service_loading_failed();
    void service_ready(ServiceDescriptor& service);
    void service_removed();
    void service_saved();
    void service_saving_failed();

  private slots:
    void accept_completion();
    void add_clicked();
    void cancel_clicked();
    void case_sens_toggled(bool new_status);
    void confirm_clicked();
    void edit_clicked();
    void encrypted_radio_toggled(bool new_status);
    void enforce_spin_coherence();
    void remove_clicked();
    void regen_clicked();
    void service_name_edited(const QString& new_text);
    void service_selected(const QModelIndex& index);
    void truncate_toggled(bool new_status);

  private:
    QPushButton* add_button;
    bool add_mode; //If true during service edition, we are adding a new service,
                   //otherwise we are editing an existing one
    QHBoxLayout* button_layout;
    QPushButton* cancel_button;
    QSpinBox* caps_amount_spin;
    QCheckBox* case_sens_check;
    QPushButton* confirm_button;
    QGroupBox* constraints_group;
    QFormLayout* constraints_layout;
    size_t current_nonce;
    QSpinBox* digits_amount_spin;
    QPushButton* edit_button;
    QHBoxLayout* edit_button_layout;
    ServiceDescriptor* edited_service;
    QRadioButton* encrypted_radio;
    QLineEdit* extra_symbols_edit;
    QString former_service_name;
    QRadioButton* generated_radio;
    QSpinBox* max_length_spin;
    QLineEdit* password_edit;
    ReturnFilter* password_edit_return_filter;
    QGroupBox* password_group;
    QHBoxLayout* password_layout;
    QGroupBox* pw_type_group;
    QVBoxLayout* pw_type_layout;
    QPushButton* regen_button;
    QGroupBox* regen_group;
    QLabel* regen_label;
    QHBoxLayout* regen_layout;
    QPushButton* remove_button;
    QCompleter* service_completion;
    QLineEdit* service_edit;
    QFormLayout* service_edit_layout;
    ReturnFilter* service_edit_return_filter;
    QStringListModel* service_names_mod;
    QListView* service_view;
    QCheckBox* truncate_check;
    QVBoxLayout* vert_layout;

    void disable_editing_controls();
    void disable_main_controls();
    void enable_editing_controls();
    void fix_service_edit_case();
    const QString* lookup_service_name(const QString& name);
    void start_editing();
    void stop_editing();
    void update_regen_label(int times_regened);
};

#endif // SERVICE_WINDOW_H
