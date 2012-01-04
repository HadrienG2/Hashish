/* Return filter : event filter that notifies attached slots of return key presses,
   without blocking them.

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

#ifndef RETURN_FILTER_H
#define RETURN_FILTER_H

#include <QEvent>
#include <QObject>

class ReturnFilter : public QObject {
    Q_OBJECT

  public:
    bool eventFilter(QObject* monitored_object, QEvent* event);

  signals:
    void return_pressed();
};

#endif // RETURN_FILTER_H
