/* Test suite : a set of functions and tools to automatically test cryptographic hashes and other
  mathematical functions against known-good input/output combinations.

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

#ifndef TEST_SUITE_H
#define TEST_SUITE_H

#include <qstring.h>

extern const QString ERR_WRONG_RESULT; //Error that is logged when a test leads to the wrong result. First
                                       //argument is the result that is obtained, second argument is the
                                       //result that should have been obtained.

//IDs that are used in test files
extern const QString ID_CACHED_DATA;
extern const QString ID_CONSTRAINTS;
extern const QString ID_HASH;
extern const QString ID_HMAC;
extern const QString ID_KEY;
extern const QString ID_MESSAGE;
extern const QString ID_RESULT;

extern const QString TEST_FILE_HEADER; //Header of a test file

extern const QString TEST_VEC_FILEPATH; //Location of the test files (first argument is the name
                                        //of the cryptographic function that is being tested)

extern const QString WARNING_TESTS_FAILED; //Warning to be displayed in the UI when some of the
                                           //startup tests of Hashish have failed.

#endif // TEST_SUITE_H
