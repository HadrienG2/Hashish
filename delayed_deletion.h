/* This unit provides facilities for deleting objects after a short time has elapsed.
   This is typically useful when an object wants to destroy itself, which it obviously
   cannot do in one of its methods.

      Copyright (C) 2011-2012  Hadrien Grasland

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


#ifndef DELAYED_DELETION_H
#define DELAYED_DELETION_H

#include <QThread>

template <typename T> class DelayedDeletion : public QThread {
  public:
    unsigned long delay_ms;
    T* target;
    DelayedDeletion() : delay_ms(100), target(NULL) {}
    void run() {
        if(target) {
            msleep(delay_ms);
            delete target;
            target = NULL;
        }
    }
};

#endif // DELAYED_DELETION_H
