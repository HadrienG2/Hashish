/* Service functions useful for transforming QStrings into the qword arrays that are used
   in cryptographic functions (and vice versa)

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

#ifndef QSTRING_TO_QWORDS_H
#define QSTRING_TO_QWORDS_H

#include <QString>
#include <stddef.h>
#include <stdint.h>

//We use two different QString <-> qword (uint64_t) transformations
// -  The "raw" transformations directly map heaps of 4 16-bit unicode chars into qwords.
//  They are suitable for transforming QStrings into qword arrays for processing purpose, and
//  getting the initial QString back, but for a random qword array there is no guarantee that
//  the resulting Unicode string will be readable or even valid.

size_t qword_length_raw(const QString& data); //Length of a transformed QString in qwords
uint64_t* qwords_from_raw_str(const QString& data,
                              uint64_t* dest_buffer);
QString* qwords_to_raw_str(const size_t data_length,
                           const uint64_t* data,
                           QString& dest_buffer);


// -  The "hex" transformations map qwords into their hexadecimal expression, written as
//  "0x0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef".
//  They are suitable for expressing a qword array in a human-readable way and processing
//  such expressions.

size_t qword_length_hex(const QString& data);
QString* qwords_to_hex_str(const size_t data_length,
                           const uint64_t* data,
                           QString& dest_buffer);
uint64_t* qwords_from_hex_str(const QString& data,
                              uint64_t* dest_buffer);

#endif // QSTRING_TO_QWORDS_H
