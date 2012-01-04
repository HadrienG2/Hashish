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

#include <QApplication>
#include <QMessageBox>

#include <error_management.h>
#include <password_window.h>

PasswordWindow::PasswordWindow(ServiceManager& service_manager,
                               const int min_service_width,
                               const int min_masterpw_width) {
    //Initialize service ID entry
    service_edit = new QLineEdit;
    service_edit->setMinimumWidth(min_service_width);
    service_edit->setToolTip(tr("Name of the service whose password you want to retrieve"));
    setFocusProxy(service_edit);

    //Initialize master password entry
    masterpw_edit = new QLineEdit;
    masterpw_edit->setEchoMode(QLineEdit::Password);
    masterpw_edit->setMinimumWidth(min_masterpw_width);
    masterpw_edit->setToolTip(tr("Your personnal master password"));

    //Initialize confirmation button
    confirm_button = new QPushButton(tr("Copy service password to clipboard"));
    confirm_button->setToolTip(tr("The password associated to the requested service will be computed and copied to the clipboard."));

    //Lay out window components
    form_layout = new QFormLayout;
    form_layout->addRow(tr("Service name :"), service_edit);
    form_layout->addRow(tr("Master password :"), masterpw_edit);
    vert_layout = new QVBoxLayout;
    vert_layout->addLayout(form_layout);
    vert_layout->addWidget(confirm_button);
    vert_layout->addStretch();
    setLayout(vert_layout);

    //Initialize service ID autocompletion
    service_names_mod = service_manager.available_services();
    service_completion = new QCompleter(service_names_mod);
    service_completion->setCaseSensitivity(Qt::CaseInsensitive);
    service_completion->setCompletionMode(QCompleter::InlineCompletion);
    service_completion->setModelSorting(QCompleter::CaseInsensitivelySortedModel);
    service_edit->setCompleter(service_completion);

    //Monitor action of the return key on the service entry to make it
    //switch keyboard focus to the master password entry if it is empty
    //or start password generation if everything is ready
    service_edit_return_filter = new ReturnFilter;
    connect(service_edit_return_filter,
            SIGNAL(return_pressed()),
            this,
            SLOT(service_edit_return_pressed()));
    service_edit->installEventFilter(service_edit_return_filter);

    //Monitor action of the return key on master password entry to make it
    //press the confirmation button
    masterpw_edit_return_filter = new ReturnFilter;
    connect(masterpw_edit_return_filter,
            SIGNAL(return_pressed()),
            confirm_button,
            SLOT(animateClick()));
    masterpw_edit->installEventFilter(masterpw_edit_return_filter);

    //Monitor action of the return key on confirm button to make it
    //animate the click
    confirm_button_return_filter = new ReturnFilter;
    QObject::connect(confirm_button_return_filter,
                     SIGNAL(return_pressed()),
                     confirm_button,
                     SLOT(animateClick()));
    confirm_button->installEventFilter(confirm_button_return_filter);

    //Monitor changes to the service edit
    service_changed = false;
    connect(service_edit,
            SIGNAL(textEdited(QString)),
            this,
            SLOT(service_edit_changed()));

    //Each time service_edit is edited, check that the requested service actually
    //exists and offer creating it otherwise
    connect(service_edit,
            SIGNAL(editingFinished()),
            this,
            SLOT(verify_service()));

    //Install a handler for confirm_button presses
    connect(confirm_button,
            SIGNAL(clicked()),
            this,
            SLOT(start_password_generation()));

    //Connect password generation signals and slots to the service manager
    connect(this,
            SIGNAL(generate_password(const QString&, const QString&)),
            &service_manager,
            SLOT(generate_password(const QString&, const QString&)));
    connect(&service_manager,
            SIGNAL(password_generation_failed()),
            this,
            SLOT(password_generation_failed()));
    connect(&service_manager,
            SIGNAL(password_ready(const QString&)),
            this,
            SLOT(password_ready(const QString&)));
}

void PasswordWindow::editing_done(const QString& new_service_name) {
    service_edit->setText(new_service_name);
    service_edit->setFocus();
}

void PasswordWindow::password_generation_failed() {
    //Clean up sensitive data
    masterpw_buffer.clear();

    //Display apologies
    static const QString error_summary(tr("Password generation failed"));
    static const QString error_desc(tr("An error was encountered during the generation of the password."));
    display_error_message(this, error_summary, error_desc);

    //Prepare the user for another attempt
    confirm_button->setEnabled(true);
    confirm_button->setFocus();
}

void PasswordWindow::password_ready(const QString& password) {
    //Clean up sensitive data
    masterpw_buffer.clear();

    //Copy password to clipboard
    QClipboard* clipboard = QApplication::clipboard();
    clipboard->setText(password);

    //Update UI to reflect that we are ready for next password generation
    confirm_button->setEnabled(true);
    confirm_button->setFocus();
}

void PasswordWindow::service_edit_changed() {
    //We maintain an internal variable to check if services have changed
    //This is needed because for some reason, when pressing "Return" in a LineEdit,
    //Qt triggers the associated editingFinished() event twice, which in our case
    //would lead to the successive appearance of two popups.
    service_changed = true;
}

void PasswordWindow::service_edit_return_pressed() {
    //Check if we are ready for password generation. If not, switch to password field, if so,
    //start password generation.

    //First, the password edit must be filled...
    if(masterpw_edit->text().isEmpty()) {
        masterpw_edit->setFocus();
        return;
    }

    //Second, the proposed service name must be valid.
    service_name_buffer = service_edit->text();
    QStringList service_list = service_names_mod->stringList();
    if(service_list.contains(service_name_buffer, Qt::CaseInsensitive) == false) {
        masterpw_edit->setFocus();
        return;
    }

    //If both are good, start password generation
    verify_service();
    confirm_button->animateClick();
}

void PasswordWindow::start_password_generation() {
    //Make a temporary copy of service ID and master password
    service_name_buffer = service_edit->text();
    masterpw_buffer = masterpw_edit->text();

    //Check that tmp_service_name is valid, otherwise abort
    QStringList service_list = service_names_mod->stringList();
    if(service_list.contains(service_name_buffer, Qt::CaseSensitive) == false) {
        static const QString invalid_service_warning(tr("Service <em>%1</em> is unknown, please choose a known service or register this one."));
        QMessageBox::warning(this,
                             tr("Invalid service name"),
                             invalid_service_warning.arg(service_name_buffer));
        service_changed = true;
        service_edit->setFocus();
        masterpw_buffer.clear();
        return;
    }

    //Check that tmp_master_password is valid, otherwise abort
    if(masterpw_buffer == "") {
        QMessageBox::warning(this,
                             tr("Blank master password"),
                             tr("Please enter the master password."));
        masterpw_edit->setFocus();
        masterpw_buffer.clear();
        return;
    }

    //Update UI to reflect that a service password is being generated
    confirm_button->setEnabled(false);

    //Start service password generation
    emit generate_password(service_name_buffer, masterpw_buffer);
}

void PasswordWindow::verify_service() {
    //There is nothing to verify in a blank edit
    if(service_edit->text() == "") return;

    //Check if service has changed since last time we checked
    if(service_changed == false) return;
    service_changed = false;

    //Verify that the requested service name exists, correcting its case if needed.
    //Otherwise, offer to create it.
    QStringList service_list = service_names_mod->stringList();
    QString service_name = service_edit->text();
    if(service_list.contains(service_name, Qt::CaseSensitive) == false) {
        QString correct_name;
        for(int i = 0; i < service_list.count(); ++i) {
            if(service_list.at(i).compare(service_name, Qt::CaseInsensitive) == 0) {
                correct_name = service_list.at(i);
                break;
            }
        }

        if(!(correct_name.isEmpty())) {
            service_edit->setText(correct_name);
        } else {
            static const QString unknown_service_warning(tr("Service <em>%1</em> is unknown, do you want to register it ?"));
            int choice = QMessageBox::question(this,
                                               tr("Unknown service name"),
                                               unknown_service_warning.arg(service_name),
                                               QMessageBox::Yes | QMessageBox::No,
                                               QMessageBox::Yes);
            if(choice == QMessageBox::Yes) emit create_service(service_name);
        }
    }
}
