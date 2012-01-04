/* Hashish's settings window : allows setting up acceptable latency and other application-wide
  parameters

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

#include <QMessageBox>
#include <QTimer>

#include <error_management.h>
#include <settings_window.h>

SettingsWindow::SettingsWindow(ServiceManager& service_manager,
                               int min_acceptable_latency,
                               int max_acceptable_latency) {
    //Initialize latency settings area
    size_t acceptable_latency = service_manager.current_latency();
    latency_group = new QGroupBox(tr("Password generation latency"));
    latency_help = new QLabel(tr("Here you can set up the time which you are ready to wait during password generation (this setting only applies to the services that will be added in the future)"));
    latency_help->setWordWrap(true);
    latency_slider = new QSlider(Qt::Horizontal);
    latency_slider->setMinimum(min_acceptable_latency);
    latency_slider->setMaximum(max_acceptable_latency);
    latency_slider->setValue(acceptable_latency);
    latency_label = new QLabel;
    latency_changed(acceptable_latency);
    latency_check_button = new QPushButton(tr("Check"));
    setFocusProxy(latency_group);

    latency_horz_layout = new QHBoxLayout;
    latency_horz_layout->addWidget(latency_slider);
    latency_horz_layout->addWidget(latency_label);
    latency_horz_layout->addSpacing(10);
    latency_horz_layout->addWidget(latency_check_button);
    latency_layout = new QVBoxLayout;
    latency_layout->addWidget(latency_help);
    latency_layout->addLayout(latency_horz_layout);
    latency_group->setLayout(latency_layout);

    //Initialize cancel and confirm buttons
    cancel_button = new QPushButton(tr("&Cancel"));
    confirm_button = new QPushButton(tr("C&onfirm"));
    button_layout = new QHBoxLayout;
    button_layout->addWidget(cancel_button, 1);
    button_layout->addSpacing(10);
    button_layout->addWidget(confirm_button, 2);

    //Initialize global window layout
    main_layout = new QVBoxLayout;
    main_layout->addWidget(latency_group);
    main_layout->addStretch();
    main_layout->addLayout(button_layout);
    setLayout(main_layout);
    setTabOrder(latency_slider, confirm_button);
    setTabOrder(confirm_button, cancel_button);

    //Keep latency_label up to date
    connect(latency_slider,
            SIGNAL(valueChanged(int)),
            this,
            SLOT(latency_changed(int)));

    //Monitor action of the return key on the latency slider to make it
    //press the test button
    latency_slider_return_filter = new ReturnFilter;
    connect(latency_slider_return_filter,
            SIGNAL(return_pressed()),
            latency_check_button,
            SLOT(animateClick()));
    latency_slider->installEventFilter(latency_slider_return_filter);

    //Implement latency checks
    connect(latency_check_button,
            SIGNAL(clicked()),
            this,
            SLOT(latency_check_start()));

    //Connect buttons to their event handlers
    connect(cancel_button,
            SIGNAL(clicked()),
            this,
            SLOT(cancel_button_clicked()));
    connect(confirm_button,
            SIGNAL(clicked()),
            this,
            SLOT(confirm_button_clicked()));

    //Keep a pointer on the service manager, we'll need it for settings changes
    service_mgr = &service_manager;
}

void SettingsWindow::cancel_button_clicked() {
    size_t acceptable_latency = service_mgr->current_latency();

    latency_slider->setValue(acceptable_latency);
}

void SettingsWindow::confirm_button_clicked() {
    bool result = service_mgr->set_current_latency(latency_slider->value());
    if(!result) {
        static const QString error_summary(tr("Setting password generation latency failed"));
        static const QString error_desc(tr("An error was encountered while setting the password generation latency."));
        display_error_message(this, error_summary, error_desc);
    }
}

void SettingsWindow::latency_changed(int new_latency) {
    latency_label->setText(tr("%n ms", "miliseconds", new_latency));
}

void SettingsWindow::latency_check_start() {
    latency_check_button->setEnabled(false);
    latency_slider->setFocus();

    QTimer::singleShot(latency_slider->value(), this, SLOT(latency_check_stop()));
}

void SettingsWindow::latency_check_stop() {
    latency_check_button->setEnabled(true);
}
