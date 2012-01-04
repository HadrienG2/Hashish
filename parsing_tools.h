/* Service functions that are useful for parsing Hashish's various configuration files

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

#ifndef PARSING_TOOLS_H
#define PARSING_TOOLS_H

#include <QChar>
#include <QString>

bool has_id(const QString& config_file_line, const QString& identifier); //Check config file line
                                                                         //for an identifier
void isolate_content(QString& config_file_line); //Removes spacing, comments, and other junk
void remove_id(QString& config_file_line, const QString& identifier); //Removes an identifier from
                                                                      //a config file line

#endif // PARSING_TOOLS_H
