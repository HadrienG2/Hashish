/* Hashish's about window : gives software version, contact information, credits,
   and licensing stuff

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

#ifndef ABOUT_WINDOW_H
#define ABOUT_WINDOW_H

#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QWidget>

class AboutWindow : public QWidget {
    Q_OBJECT

  public:
    AboutWindow(int max_icon_size = 80);

  private:
    QLabel* about_text;
    QScrollArea* about_text_scroll_area;
    QLabel* app_icon;
    QHBoxLayout* main_layout;
};

#endif // ABOUT_WINDOW_H
