/* Service functions useful for transforming QStrings into the qword arrays that are used
   in cryptographic functions

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

#include <qstring_to_qwords.h>

size_t qword_length_raw(const QString& data) {
    size_t str_length = data.size();
    if(str_length%4) {
        return (str_length/4) + 1;
    } else {
        return str_length/4;
    }
}

uint64_t* qwords_from_raw_str(const QString& data,
                              uint64_t* dest_buffer) {
    uint64_t* result = dest_buffer;
    uint64_t* result_parser = result-1;
    for(int i = 0; i < data.size(); ++i) {
        if(i%4 == 0) {
            ++result_parser;
            *result_parser = 0;
        }
        *result_parser*= 65536;
        *result_parser+= data.at(i).unicode();
    }

    return result;
}

QString* qwords_to_raw_str(const size_t data_length,
                           const uint64_t* data,
                           QString& dest_buffer) {
    dest_buffer.clear();
    uint64_t current_data;
    ushort c1 = 0, c2 = 0, c3 = 0, c4 = 0;

    for(size_t i = 0; i < data_length; ++i) {
        //Extract chars from the qword data
        current_data = data[i];
        c4 = current_data % 65536;
        current_data/= 65536;
        c3 = current_data % 65536;
        current_data/= 65536;
        c2 = current_data % 65536;
        current_data/= 65536;
        c1 = current_data % 65536;
        if(i == data_length - 1) break;

        //Insert them into the destination buffer
        dest_buffer.append(c1);
        dest_buffer.append(c2);
        dest_buffer.append(c3);
        dest_buffer.append(c4);
    }

    //Last qword requires special treatment
    if(c1) dest_buffer.append(c1);
    if(c2) dest_buffer.append(c2);
    if(c3) dest_buffer.append(c3);
    if(c4) dest_buffer.append(c4);

    return &dest_buffer;
}


int hex_from_qchar(const QChar ch) {
    if((ch.toAscii() >= '0') && (ch.toAscii() <= '9')) {
        return ch.toAscii()-'0';
    } else {
        return (ch.toAscii()-'a') + 10;
    }
}

QChar hex_to_qchar(const int hex_digit) {
    if(hex_digit < 10) {
        return '0'+hex_digit;
    } else {
        return 'a'+(hex_digit-10);
    }
}

size_t qword_length_hex(const QString& data) {
    //A hex string is of the form "0x0123456789abcdef 012...def". As such, length in qwords
    //may be determined by taking the string length, subtracting 2 (for the 0x), adding one (for
    //the absence of trailing in last qword), and dividing by 17 (length of a qword + space)
    if((data.count() - 1) % 17) return 0;
    return (data.count() - 1)/17;
}

uint64_t* qwords_from_hex_str(const QString& data,
                              uint64_t* dest_buffer) {
    //Check string validity
    if(data.at(0) != '0') return NULL;
    if(data.at(1) != 'x') return NULL;
    size_t qw_length = qword_length_hex(data);
    if(!qw_length) return NULL;

    //Retrieve the encrypted password
    for(size_t i=0; i < qw_length; ++i) {
        int string_offset = 2+17*i;
        dest_buffer[i] = hex_from_qchar(data.at(string_offset));
        for(int j = 1; j < 16; ++j) {
            dest_buffer[i]*= 16;
            dest_buffer[i]+= hex_from_qchar(data.at(string_offset+j));
        }
    }

    return dest_buffer;
}

QString* qwords_to_hex_str(const size_t data_length,
                           const uint64_t* data,
                           QString& dest_buffer) {
    //Initialize work data
    dest_buffer = "0x";
    char hex_digits[18];
    hex_digits[16] = ' ';
    hex_digits[17] = '\0';
    uint64_t tmp_buff;

    //Perform transformation
    for(size_t i=0; i < data_length; ++i) {
        tmp_buff = data[i];
        for(int j = 15; j >= 0; --j) {
            hex_digits[j] = hex_to_qchar(tmp_buff % 16).toAscii();
            tmp_buff/= 16;
        }
        dest_buffer.append(hex_digits);
    }
    dest_buffer.remove(dest_buffer.size()-1, 1); // Remove trailing space

    return &dest_buffer;
}
