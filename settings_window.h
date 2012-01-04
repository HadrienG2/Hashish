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

#ifndef SETTINGS_WINDOW_H
#define SETTINGS_WINDOW_H

#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSlider>
#include <QVBoxLayout>
#include <QWidget>

#include <about_window.h>
#include <return_filter.h>
#include <service_manager.h>

class SettingsWindow : public QWidget {
    Q_OBJECT

  public:
    SettingsWindow(ServiceManager& service_manager,
                   int min_acceptable_latency = 10,
                   int max_acceptable_latency = 400);

  private slots:
    void cancel_button_clicked();
    void confirm_button_clicked();
    void latency_changed(int new_latency);
    void latency_check_start();
    void latency_check_stop();

  private:
    QHBoxLayout* button_layout;
    QPushButton* cancel_button;
    QPushButton* confirm_button;
    QPushButton* latency_check_button;
    QGroupBox* latency_group;
    QLabel* latency_label;
    QLabel* latency_help;
    QSlider* latency_slider;
    ReturnFilter* latency_slider_return_filter;
    QHBoxLayout* latency_horz_layout;
    QVBoxLayout* latency_layout;
    QVBoxLayout* main_layout;
    ServiceManager* service_mgr;
};

#endif // SETTINGS_WINDOW_H
