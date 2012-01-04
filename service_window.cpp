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

#include <QInputDialog>
#include <QMessageBox>

#include <error_management.h>
#include <service_window.h>

ServiceWindow::ServiceWindow(ServiceManager& service_manager,
                             const int min_service_width) {
    //Initialize service ID entry
    service_edit = new QLineEdit;
    setFocusProxy(service_edit);
    service_edit_layout = new QFormLayout;
    service_edit_layout->addRow(tr("Service name :"), service_edit);

    //Initialize service view
    service_view = new QListView;
    service_view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    service_view->setMinimumWidth(min_service_width);
    service_view->setSelectionMode(QAbstractItemView::SingleSelection);

    //Initialize buttons
    add_button = new QPushButton(tr("&Add"));
    remove_button = new QPushButton(tr("&Remove"));
    remove_button->setEnabled(false);
    edit_button = new QPushButton(tr("&Edit"));
    edit_button->setEnabled(false);
    button_layout = new QHBoxLayout;
    button_layout->addWidget(add_button);
    button_layout->addWidget(remove_button);
    button_layout->addWidget(edit_button);

    //Initialize operating mode selection
    pw_type_group = new QGroupBox(tr("Mode of operation"));
    generated_radio = new QRadioButton(tr("Generate a new password"));
    encrypted_radio = new QRadioButton(tr("Encrypt an existing password"));
    generated_radio->setChecked(true);
    pw_type_layout = new QVBoxLayout;
    pw_type_layout->addWidget(generated_radio);
    pw_type_layout->addWidget(encrypted_radio);
    pw_type_group->setLayout(pw_type_layout);
    pw_type_group->hide();

    //Initialize password regeneration facilities (for generated passwords)
    regen_group = new QGroupBox(tr("Password regeneration"));
    regen_label = new QLabel;
    update_regen_label(0);
    regen_button = new QPushButton(tr("Regenerate"));
    regen_button->setToolTip(tr("Click this button to regenerate your password if it is not safe anymore.\nIt can be a good idea to do this regularly, even if your password has no known problem."));
    regen_layout = new QHBoxLayout;
    regen_layout->addWidget(regen_label);
    regen_layout->addWidget(regen_button);
    regen_group->setLayout(regen_layout);
    regen_group->hide();

    //Initialize constraints setup (for generated passwords)
    constraints_group = new QGroupBox(tr("Password generation constraints"));
    case_sens_check = new QCheckBox;
    caps_amount_spin = new QSpinBox;
    caps_amount_spin->setEnabled(false); //Will only be enabled if case sensitivity is enabled
    digits_amount_spin = new QSpinBox;
    truncate_check = new QCheckBox;
    truncate_check->setToolTip(tr("As a default, your password will be as long as possible.\nIf your service provider puts constraints on password length, we can voluntarily shorten it."));
    max_length_spin = new QSpinBox;
    max_length_spin->setEnabled(false); //Will only be enabled if truncate_check is enabled
    extra_symbols_edit = new QLineEdit;
    extra_symbols_edit->setToolTip(tr("As a default, we generate passwords using Latin letters from A to Z and digits from 0 to 9.\nUsing this parameter, you can specify extra characters that may be used in the generated password."));
    constraints_layout = new QFormLayout;
    constraints_layout->addRow(tr("Case sensitive :"), case_sens_check);
    constraints_layout->addRow(tr("Minimal amount of caps :"), caps_amount_spin);
    constraints_layout->addRow(tr("Minimal amount of digits :"), digits_amount_spin);
    constraints_layout->addRow(tr("Truncate password :"), truncate_check);
    constraints_layout->addRow(tr("Maximal length :"), max_length_spin);
    constraints_layout->addRow(tr("Extra allowed symbols :"), extra_symbols_edit);
    constraints_group->setLayout(constraints_layout);
    constraints_group->hide();

    //Initialize password input (for encryption)
    password_group = new QGroupBox(tr("Password to encrypt"));
    password_edit = new QLineEdit;
    password_edit->setEchoMode(QLineEdit::Password);
    password_layout = new QHBoxLayout;
    password_layout->addWidget(password_edit);
    password_group->setLayout(password_layout);
    password_group->hide();

    //Initialize cancel and confirm buttons
    cancel_button = new QPushButton(tr("&Cancel"));
    confirm_button = new QPushButton(tr("C&onfirm"));
    edit_button_layout = new QHBoxLayout;
    edit_button_layout->addWidget(cancel_button, 1);
    edit_button_layout->addSpacing(10);
    edit_button_layout->addWidget(confirm_button, 2);
    cancel_button->hide();
    confirm_button->hide();

    //Lay out things
    vert_layout = new QVBoxLayout;
    vert_layout->addLayout(service_edit_layout);
    vert_layout->addWidget(service_view);
    vert_layout->addLayout(button_layout);
    vert_layout->addWidget(pw_type_group);
    vert_layout->addWidget(regen_group);
    vert_layout->addWidget(constraints_group);
    vert_layout->addWidget(password_group);
    vert_layout->addLayout(edit_button_layout);
    vert_layout->addStretch();
    setLayout(vert_layout);
    setTabOrder(extra_symbols_edit, confirm_button);
    setTabOrder(password_edit, confirm_button);

    //Set up service completion so that service_edit becomes a search box for service_view
    service_names_mod = service_manager.available_services();
    service_completion = new QCompleter(service_manager.available_services());
    service_completion->setCaseSensitivity(Qt::CaseInsensitive);
    service_completion->setModelSorting(QCompleter::CaseInsensitivelySortedModel);
    service_view->setModel(service_completion->completionModel());
    connect(service_edit,
            SIGNAL(textEdited(QString)),
            this,
            SLOT(service_name_edited(QString)));

    //Monitor action of the return key on the service entry to make it
    //switch keyboard focus to the service view
    service_edit_return_filter = new ReturnFilter;
    connect(service_edit_return_filter,
            SIGNAL(return_pressed()),
            this,
            SLOT(accept_completion()));
    service_edit->installEventFilter(service_edit_return_filter);

    //Monitor user-driven selections in service_view
    connect(service_view,
            SIGNAL(activated(QModelIndex)),
            this,
            SLOT(service_selected(QModelIndex)));
    connect(service_view,
            SIGNAL(clicked(QModelIndex)),
            this,
            SLOT(service_selected(QModelIndex)));

    //Monitor action of the return key on the password entry to make it confirm the password
    password_edit_return_filter = new ReturnFilter;
    connect(password_edit_return_filter,
            SIGNAL(return_pressed()),
            this,
            SLOT(confirm_clicked()));
    password_edit->installEventFilter(password_edit_return_filter);

    //Connect the various controls to their signal handlers
    connect(add_button,
            SIGNAL(clicked()),
            this,
            SLOT(add_clicked()));
    connect(cancel_button,
            SIGNAL(clicked()),
            this,
            SLOT(cancel_clicked()));
    connect(case_sens_check,
            SIGNAL(toggled(bool)),
            this,
            SLOT(case_sens_toggled(bool)));
    connect(confirm_button,
            SIGNAL(clicked()),
            this,
            SLOT(confirm_clicked()));
    connect(edit_button,
            SIGNAL(clicked()),
            this,
            SLOT(edit_clicked()));
    connect(encrypted_radio,
            SIGNAL(toggled(bool)),
            this,
            SLOT(encrypted_radio_toggled(bool)));
    connect(caps_amount_spin,
            SIGNAL(valueChanged(int)),
            this,
            SLOT(enforce_spin_coherence()));
    connect(digits_amount_spin,
            SIGNAL(valueChanged(int)),
            this,
            SLOT(enforce_spin_coherence()));
    connect(max_length_spin,
            SIGNAL(valueChanged(int)),
            this,
            SLOT(enforce_spin_coherence()));
    connect(remove_button,
            SIGNAL(clicked()),
            this,
            SLOT(remove_clicked()));
    connect(regen_button,
            SIGNAL(clicked()),
            this,
            SLOT(regen_clicked()));
    connect(truncate_check,
            SIGNAL(toggled(bool)),
            this,
            SLOT(truncate_toggled(bool)));

    //Connect this component to the service manager
    connect(this,
            SIGNAL(add_service(const QString&)),
            &service_manager,
            SLOT(add_service(const QString&)));
    connect(this,
            SIGNAL(load_service(const QString)),
            &service_manager,
            SLOT(load_service(const QString)));
    connect(this,
            SIGNAL(remove_service(const QString&)),
            &service_manager,
            SLOT(remove_service(const QString&)));
    connect(this,
            SIGNAL(save_service(const QString&, const QString&, ServiceDescriptor&)),
            &service_manager,
            SLOT(save_service(const QString&, const QString&, ServiceDescriptor&)));
    connect(&service_manager,
            SIGNAL(service_loading_failed()),
            this,
            SLOT(service_loading_failed()));
    connect(&service_manager,
            SIGNAL(service_ready(ServiceDescriptor&)),
            this,
            SLOT(service_ready(ServiceDescriptor&)));
    connect(&service_manager,
            SIGNAL(service_removed()),
            this,
            SLOT(service_removed()));
    connect(&service_manager,
            SIGNAL(service_saved()),
            this,
            SLOT(service_saved()));
    connect(&service_manager,
            SIGNAL(service_saving_failed()),
            this,
            SLOT(service_saving_failed()));
}

void ServiceWindow::clear_service_edit() {
    service_edit->clear();
}

void ServiceWindow::create_service(const QString& service_name) {
    service_edit->setText(service_name);
    service_name_edited(service_name);
    add_clicked();
}

void ServiceWindow::service_loading_failed() {
    //Display apologies
    static const QString error_summary(tr("Service loading failed"));
    static const QString error_desc(tr("An error was encountered while loading the service's description."));
    display_error_message(this, error_summary, error_desc);

    //Enable controls again
    service_edit->setEnabled(true);
    service_view->setEnabled(true);
    remove_button->setEnabled(true);
    edit_button->setEnabled(true);
    edit_button->setFocus();
}

void ServiceWindow::service_ready(ServiceDescriptor& service) {
    //Set interface to edition mode
    disable_editing_controls();
    start_editing();

    //Save pointer to descriptor, fill the various fields
    edited_service = &service;
    switch(service.password_type) {
      case GENERATED:
        generated_radio->setChecked(true);
        if(!add_mode) regen_group->show();
        constraints_group->show();
        break;
      case ENCRYPTED:
        encrypted_radio->setChecked(true);
        password_group->show();
        break;
    }
    current_nonce = service.nonce;
    update_regen_label(current_nonce);
    if(service.constraints) {
        case_sens_check->setChecked(service.constraints->case_sensitivity);
        caps_amount_spin->setValue(service.constraints->number_of_caps);
        digits_amount_spin->setValue(service.constraints->number_of_digits);
        if(service.constraints->maximal_length) {
            truncate_check->setChecked(true);
            max_length_spin->setValue(service.constraints->maximal_length);
        } else {
            truncate_check->setChecked(false);
        }
        extra_symbols_edit->setText(service.constraints->extra_symbols);
    }
    password_edit->setText("");
    enable_editing_controls();

    //Restore initial main control state
    service_edit->setEnabled(true);
    service_edit->setFocus();
    service_view->setEnabled(true);
    if(add_mode) {
        add_button->setEnabled(true);
    } else {
        remove_button->setEnabled(true);
        edit_button->setEnabled(true);
    }
}

void ServiceWindow::service_removed() {
    service_edit->setEnabled(true);
    service_edit->clear();
    service_name_edited(service_edit->text());
    service_edit->setFocus();
    service_view->setEnabled(true);
    add_button->setEnabled(true);
}

void ServiceWindow::service_saved() {
    enable_editing_controls();
    stop_editing();
    service_name_edited(service_edit->text());
    add_button->setEnabled(false);
    edit_button->setEnabled(true);
    remove_button->setEnabled(true);
}

void ServiceWindow::service_saving_failed() {
    //Display apologies
    static const QString error_summary(tr("Service saving failed"));
    static const QString error_desc(tr("An error was encountered while saving the service's description."));
    display_error_message(this, error_summary, error_desc);

    //Enable controls again
    enable_editing_controls();
    confirm_button->setFocus();
}

void ServiceWindow::accept_completion() {
    if(service_edit->text() != "") {
        service_selected(service_view->currentIndex());
    }
}

void ServiceWindow::add_clicked() {
    disable_main_controls();

    former_service_name = service_edit->text();
    add_mode = true;
    emit add_service(former_service_name);
}

void ServiceWindow::cancel_clicked() {
    service_edit->setText("");
    service_name_edited(service_edit->text());
    stop_editing();
}

void ServiceWindow::case_sens_toggled(bool new_status) {
    if(new_status) {
        caps_amount_spin->setEnabled(true);
    } else {
        caps_amount_spin->setValue(0);
        caps_amount_spin->setEnabled(false);
    }
}

void ServiceWindow::confirm_clicked() {
    //Make sure that the service name is valid and not taken
    QString new_service_name = service_edit->text();
    if(new_service_name.isEmpty()) {
        QMessageBox::warning(this,
                             tr("Service name is empty"),
                             tr("Please give a name to this service."));
        service_edit->setFocus();
        return;
    }
    const QString* existing_service_name = lookup_service_name(new_service_name);
    if(existing_service_name) {
        if(former_service_name != *existing_service_name) {
            static const QString existing_service_warning(tr("Service name <em>%1</em> is already taken, please choose another name."));
            QMessageBox::warning(this,
                                 tr("Invalid service name"),
                                 existing_service_warning.arg(*existing_service_name));
            service_edit->setFocus();
            service_edit->selectAll();
            return;
        }
    }

    //Perform checks specific to encrypted passwords
    static QString master_pw;
    if(encrypted_radio->isChecked()) {
        //A password must be provided for newly encrypted passwords
        bool new_encrypted_password = add_mode;
        if(edited_service->password_type != ENCRYPTED) new_encrypted_password = true;
        if(new_encrypted_password && (password_edit->text().isEmpty())) {
            QMessageBox::warning(this,
                                 tr("Password is empty"),
                                 tr("Please provide the password that is to be encrypted."));
            password_edit->setFocus();
            return;
        }

        //If a password is to be encrypted, ask for the user's master password
        if(password_edit->text().isEmpty() == false) {
            bool ok;
            master_pw = QInputDialog::getText(this,
                                              tr("Enter master password"),
                                              tr("Please enter your master password in order to perform the encryption"),
                                              QLineEdit::Password,
                                              QString(),
                                              &ok);
            if(!ok) return;
            if(master_pw.isEmpty()) {
                QMessageBox::warning(this,
                                     tr("No master password given"),
                                     tr("You must provide your master password for encryption to be performed !"));
                return;
            }
        }
    }

    //Commit changes to the service descriptor
    if(add_mode) edited_service->service_name = new_service_name;
    if(generated_radio->isChecked()) {
        //For security purpose, passwords which are former encryption keys must be regened
        if((edited_service->nonce == current_nonce) && (edited_service->password_type == ENCRYPTED)) {
            current_nonce+= 1;
        }
        edited_service->password_type = GENERATED;
        edited_service->nonce = current_nonce;
        edited_service->constraints->case_sensitivity = case_sens_check->isChecked();
        edited_service->constraints->number_of_caps = caps_amount_spin->value();
        edited_service->constraints->number_of_digits = digits_amount_spin->value();
        edited_service->constraints->maximal_length = max_length_spin->value();
        edited_service->constraints->extra_symbols = extra_symbols_edit->text();
        edited_service->encrypted_pw_length = 0;
        if(edited_service->encrypted_pw) delete[] edited_service->encrypted_pw, edited_service->encrypted_pw = NULL;
    } else {
        //We try to perform encryption before writing the service's descriptor, because this step may fail
        if(password_edit->text().isEmpty() == false) {
            if(!add_mode) edited_service->nonce+=1;
            bool result = edited_service->encrypt_password(master_pw, password_edit->text());
            if(!result) {
                static const QString error_summary(tr("Password encryption failed"));
                static const QString error_desc(tr("An error was encountered while encrypting the password."));
                display_error_message(this, error_summary, error_desc);
                if(!add_mode) edited_service->nonce-=1;
                return;
            }
        }
        edited_service->password_type = ENCRYPTED;
    }

    //Freeze the dialog, save the service descriptor
    disable_editing_controls();
    emit save_service(former_service_name, new_service_name, *edited_service);
}

void ServiceWindow::edit_clicked() {
    disable_main_controls();

    fix_service_edit_case();
    former_service_name = service_edit->text();
    add_mode = false;
    emit load_service(former_service_name);
}

void ServiceWindow::encrypted_radio_toggled(bool new_status) {
    static bool previous_regen_visibility = false;
    if(new_status) {
        constraints_group->hide();
        previous_regen_visibility = regen_group->isVisible();
        regen_group->hide();
        password_group->show();
    } else {
        constraints_group->show();
        if(previous_regen_visibility) regen_group->show();
        password_group->hide();
    }
}

void ServiceWindow::enforce_spin_coherence() {
    if(max_length_spin->value() == 0) return;

    int min_max_length = caps_amount_spin->value() + digits_amount_spin->value();
    if(!min_max_length) ++min_max_length;
    max_length_spin->setMinimum(min_max_length);
}

void ServiceWindow::remove_clicked() {
    fix_service_edit_case();
    static QString service_name;
    service_name = service_edit->text();

    static const QString service_removal_warning(tr("Password for service <em>%1</em> will be irremediably lost !"));
    int choice = QMessageBox::warning(this,
                                      tr("Irreversible password loss"),
                                      service_removal_warning.arg(service_name),
                                      QMessageBox::Ok | QMessageBox::Cancel,
                                      QMessageBox::Ok);
    if(choice == QMessageBox::Ok) {
        disable_main_controls();
        emit remove_service(service_name);
    }
}

void ServiceWindow::regen_clicked() {
    ++current_nonce;
    update_regen_label(current_nonce);
}

void ServiceWindow::service_name_edited(const QString& new_text) {
    //Update service_view's contents
    service_completion->setCompletionPrefix(new_text);

    //If new_text is nonzero, select first item in service_view. If not, deselect
    //the contents of service_view
    QAbstractItemModel* service_view_contents = service_view->model();
    if(service_view_contents->hasIndex(0,0)) {
        if(new_text != "") {
            QModelIndex first_service_view_item = service_view_contents->index(0,0);
            service_view->setCurrentIndex(first_service_view_item);
        } else {
            service_view->setCurrentIndex(QModelIndex());
        }
    }

    //Manage transition between button states
    QStringList service_list = service_names_mod->stringList();
    if(service_list.contains(new_text, Qt::CaseInsensitive)) {
        add_button->setEnabled(false);
        remove_button->setEnabled(true);
        edit_button->setEnabled(true);
    } else {
        add_button->setEnabled(true);
        remove_button->setEnabled(false);
        edit_button->setEnabled(false);
    }
}

void ServiceWindow::service_selected(const QModelIndex& index) {
    service_view->setCurrentIndex(index);

    QVariant selected_item = service_view->model()->data(index);
    service_edit->setText(selected_item.toString());

    add_button->setEnabled(false);
    remove_button->setEnabled(true);
    edit_button->setEnabled(true);
}

void ServiceWindow::truncate_toggled(bool new_status) {
    if(new_status) {
        max_length_spin->setMinimum(1);
        max_length_spin->setValue(15);
        max_length_spin->setEnabled(true);
    } else {
        max_length_spin->setMinimum(0);
        max_length_spin->setValue(0);
        max_length_spin->setEnabled(false);
    }
}

void ServiceWindow::disable_editing_controls() {
    service_edit->setEnabled(false);
    pw_type_group->setEnabled(false);
    regen_group->setEnabled(false);
    constraints_group->setEnabled(false);
    password_group->setEnabled(false);
    cancel_button->setEnabled(false);
    confirm_button->setEnabled(false);
}

void ServiceWindow::disable_main_controls() {
    service_edit->setEnabled(false);
    service_view->setEnabled(false);
    add_button->setEnabled(false);
    remove_button->setEnabled(false);
    edit_button->setEnabled(false);
}

void ServiceWindow::enable_editing_controls() {
    service_edit->setEnabled(true);
    pw_type_group->setEnabled(true);
    regen_group->setEnabled(true);
    constraints_group->setEnabled(true);
    password_group->setEnabled(true);
    cancel_button->setEnabled(true);
    confirm_button->setEnabled(true);
}

void ServiceWindow::fix_service_edit_case() {
    service_edit->setText(*lookup_service_name(service_edit->text()));
}

const QString* ServiceWindow::lookup_service_name(const QString& name) {
    QStringList service_list = service_names_mod->stringList();

    for(int i = 0; i < service_list.count(); ++i) {
        if(service_list.at(i).compare(name, Qt::CaseInsensitive) == 0) {
            return &(service_list.at(i));
        }
    }

    return NULL;
}

void ServiceWindow::start_editing() {
    //Switch the interface to edition mode
    service_edit->blockSignals(true);
    service_edit_return_filter->blockSignals(true);
    service_view->hide();
    add_button->hide();
    remove_button->hide();
    edit_button->hide();
    pw_type_group->show();
    cancel_button->show();
    confirm_button->show();
}

void ServiceWindow::stop_editing() {
    service_edit->blockSignals(false);
    service_edit_return_filter->blockSignals(false);
    service_edit->setFocus();
    service_view->show();
    add_button->show();
    remove_button->show();
    edit_button->show();
    pw_type_group->hide();
    regen_group->hide();
    constraints_group->hide();
    password_group->hide();
    cancel_button->hide();
    confirm_button->hide();
    emit reset_main_window_size();
    emit editing_done(service_edit->text());
}

void ServiceWindow::update_regen_label(int times_regened) {
    regen_label->setText(tr("This password was regenerated %n time(s).", "", times_regened));
}
