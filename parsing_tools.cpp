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

#include <parsing_tools.h>

bool has_id(const QString& config_file_line, const QString& identifier) {
    if(config_file_line.left(identifier.count()) == identifier) return true;

    return false;
}

void isolate_content(QString& config_file_line) {
    //Remove spacing on the left
    int i;
    for(i = 0; i < config_file_line.count(); ++i) {
        if(config_file_line.at(i) != ' ') break;
    }
    config_file_line.remove(0, i);

    //If the line is empty, stop here
    if(config_file_line.isEmpty()) return;

    //If the file is a comment, empty it
    if(config_file_line.at(0) == '#') config_file_line.clear();
}

void remove_id(QString& config_file_line, const QString& identifier) {
    config_file_line.remove(0, identifier.count());
}
