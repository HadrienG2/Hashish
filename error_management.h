/* Error management routines : centralize all functions related to error management :
   generating error messages, displaying them to users, saving error logs...
   Also includes a few common error messages.

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


#ifndef ERROR_MANAGEMENT_H
#define ERROR_MANAGEMENT_H

#include <QString>
#include <QTextStream>
#include <QWidget>

//A few common error messages first
extern const QString ERR_BAD_ALLOC; //Used when a variable was not properly allocated. First
                                    //argument (to be set with arg()) is the name of the variable.
extern const QString ERR_BAD_HEX_DATA; //There is something in a config file which claims to be
                                       //hex data but is at least badly formatted and at worst
                                       //totally wrong. First argument is the bad data.
extern const QString ERR_FILE_HEADER_INCORRECT; //The header of a file this is to be loaded is
                                                //incorrect. First argument is the filename.
extern const QString ERR_FILE_NOT_FOUND; //A file was not found, and could not be automatically
                                         //generated. First argument is the filename.
extern const QString ERR_FILE_OPEN_FAILURE; //A file could not be opened as intended. First
                                            //argument is the filename.
extern const QString ERR_FOLDER_CREATION_FAILURE; //A folder could not be created. First argument
                                                  //is the filename.
extern const QString ERR_NOT_AN_HASHED_KEY; //Some cryptographic functions specifically take an hashed
                                           //key as one of their argument. If the input does not
                                           //verify this property, use this error. First argument is
                                           //the invalid key.
extern const QString ERR_UNSUPPORTED_CIPHER; //An external file specifies the name of a cipher that
                                             //is not implemented in this version of Hashish. First
                                             //argument is the name of the cipher
extern const QString ERR_UNSUPPORTED_HASH; //An external file specifies the name of a hash that is
                                           //not implemented in this version of Hashish. First
                                           //argument is the name of the hash
extern const QString ERR_UNSUPPORTED_HMAC; //An external file specifies the name of a HMAC that is
                                           //not implemented in this version of Hashish. First
                                           //argument is the name of the HMAC
extern const QString ERR_UNSUPPORTED_PW_GEN; //An external file specifies the name of a password
                                             //generator that is not implemented in this version of
                                             //Hashish. First argument is the name of the generator

void display_error_message(QWidget* host_window,
                           const QString& error_summary,
                           const QString& error_description);
QString generate_error_message(const QString& error_description);
void log_error(const QString& failing_component,
               const QString& error_description);
void start_error_logging(QTextStream& error_output);
void stop_error_logging();

#endif // ERROR_MANAGEMENT_H
