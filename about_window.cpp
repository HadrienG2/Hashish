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

#include <QPixmap>

#include <about_window.h>

AboutWindow::AboutWindow(int max_icon_size) {
    //Display the application's icon, in large size
    app_icon = new QLabel;
    app_icon->setPixmap(QPixmap(":/hashish.png"));
    app_icon->setScaledContents(true);
    app_icon->setMaximumWidth(max_icon_size);
    app_icon->setMaximumHeight(max_icon_size);

    //Display the full about text
    const int hashish_version = 3;
    const QString website_url = "http://neolander.github.com/Hashish/";
    QString about_text_contents(tr("<center><h2>Hashish v%1</h2></center>").arg(hashish_version));
    about_text_contents+=tr("This simple and secure password generator and manager ");
    about_text_contents+=tr("is brought to you by Hadrien Grasland \"Neolander\" (main developer) ");
    about_text_contents+=tr("and Louis Gosselin (cryptography expert)<br />");
    about_text_contents+=QString("<center><a href=\"%1\">%1</a></center><br />").arg(website_url);
    about_text_contents+=tr("(C) 2011-2012 Hadrien Grasland, released under GPLv2 license (see COPYING for more details)");

    about_text_scroll_area = new QScrollArea;
    about_text_scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    about_text = new QLabel(about_text_contents);
    about_text->setOpenExternalLinks(true);
    about_text->setWordWrap(true);
    about_text_scroll_area->setWidget(about_text);
    about_text_scroll_area->setWidgetResizable(true);

    //Lay things out
    main_layout = new QHBoxLayout;
    main_layout->addWidget(app_icon);
    main_layout->addWidget(about_text_scroll_area);
    setLayout(main_layout);
}
