/* Error management routines : centralize all functions related to error management :
   generating error messages, displaying them to users, saving error logs...

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
#include <time.h>

#include <error_management.h>

const QString ERR_BAD_ALLOC("Allocation of dynamic variable %1 failed.");
const QString ERR_BAD_HEX_DATA("Bad hexadecimal data : %1");
const QString ERR_FILE_HEADER_INCORRECT("Header of file %1 is incorrect.");
const QString ERR_FILE_NOT_FOUND("File %1 not found.");
const QString ERR_FILE_OPEN_FAILURE("File %1 could not be opened.");
const QString ERR_FOLDER_CREATION_FAILURE("Folder %1 could not be created.");
const QString ERR_NOT_AN_HASHED_KEY("Provided input is not an hashed key : %1");
const QString ERR_UNSUPPORTED_CIPHER("Unsupported password cipher : %1");
const QString ERR_UNSUPPORTED_HASH("Unsupported hash : %1");
const QString ERR_UNSUPPORTED_HMAC("Unsupported HMAC : %1");
const QString ERR_UNSUPPORTED_PW_GEN("Unsupported password generator : %1");

QTextStream* err_out = NULL;
bool no_errors_yet = true;

void display_error_message(QWidget* host_window,
                           const QString& error_summary,
                           const QString& error_description) {
    QMessageBox::critical(host_window,
                          error_summary,
                          generate_error_message(error_description));
}

QString generate_error_message(const QString& error_description) {
    static const QString output(qApp->translate("CoreApplication", "%1\nIf this is a persistent problem, please contact us using the information that you will find in the \"About\" tab."));
    return output.arg(error_description);
}

void log_error(const QString& failing_component,
               const QString& error_description) {
    if(!err_out) return;

    if(no_errors_yet) {
        time_t today = time(NULL);
        *err_out << endl << ctime(&today);
        no_errors_yet = false;
    }
    *err_out << "[" << failing_component << "] " << error_description << endl;
}

void start_error_logging(QTextStream& error_output) {
    err_out = &error_output;
}

void stop_error_logging() {
    err_out = NULL;
}
