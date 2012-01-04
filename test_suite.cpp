/* Test suite : a set of function to automatically test cryptographic hashes and other
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

#include <QApplication>
#include <QFile>
#include <QTextStream>
#include <stdint.h>

#include <error_management.h>
#include <parsing_tools.h>
#include <qstring_to_qwords.h>
#include <test_suite.h>

const QString ERR_WRONG_RESULT("Got result : %1\nExpected   : %2");

const QString ID_CACHED_DATA("cached_data : ");
const QString ID_CONSTRAINTS("constraints : ");
const QString ID_HASH("hash : ");
const QString ID_HMAC("hmac : ");
const QString ID_KEY("key : ");
const QString ID_MESSAGE("message : ");
const QString ID_RESULT("result : ");

const QString TEST_FILE_HEADER("*** Hashish test file v1 ***");

const QString TEST_VEC_FILEPATH(":/Tests/%1.testvecs");

const QString WARNING_TESTS_FAILED(qApp->translate("CoreApplication", "It seems that Hashish has a problem with your computer, because it does its mathematics wrong. We recommend that you contact us about this problem, using the information which you will find in the About tab."));
