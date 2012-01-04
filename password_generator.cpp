/* Service classes and methods used for generating alphanumeric (and beyond)
   passwords that match certain constraints.

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

#include <QFile>

#include <error_management.h>
#include <parsing_tools.h>
#include <password_generator.h>
#include <qstring_to_qwords.h>
#include <test_suite.h>

const PwdGenConstraints default_constraints;

const QString PWD_GEN_CONSTRAINTS_NAME("PwdGenConstraints");

const QString ID_CASE_SENSITIVITY("case_sensitivity : ");
const QString ID_EXTRA_SYMBOLS("extra_symbols : ");
const QString ID_MAXIMAL_LENGTH("maximal_length : ");
const QString ID_NUMBER_OF_DIGITS("number_of_digits : ");
const QString ID_NUMBER_OF_CAPS("number_of_caps : ");

bool PwdGenConstraints::parse_constraint_desc(QTextStream &service_istream) {
    QString line;
    while(service_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments
        line = service_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //Check if we have reached the end of constraint declaration
        if(line.at(0) == '}') break;

        //Check service name
        if(has_id(line, ID_CASE_SENSITIVITY)) {
            remove_id(line, ID_CASE_SENSITIVITY);
            if(line == "true") {
                case_sensitivity = true;
            } else if(line == "false") {
                case_sensitivity = false;
            } else {
                static const QString ERR_NONBOOL_CASE_SENS("Non-boolean value of case_sensitivity.");
                log_error(PWD_GEN_CONSTRAINTS_NAME, ERR_NONBOOL_CASE_SENS);
                return false;
            }
            continue;
        }

        //Check number of caps
        if(has_id(line, ID_NUMBER_OF_CAPS)) {
            remove_id(line, ID_NUMBER_OF_CAPS);
            number_of_caps = line.toInt();
            continue;
        }

        //Check number of digits
        if(has_id(line, ID_NUMBER_OF_DIGITS)) {
            remove_id(line, ID_NUMBER_OF_DIGITS);
            number_of_digits = line.toInt();
            continue;
        }

        //Check maximal length
        if(has_id(line, ID_MAXIMAL_LENGTH)) {
            remove_id(line, ID_MAXIMAL_LENGTH);
            maximal_length = line.toInt();
            continue;
        }

        //Check extra symbols
        if(has_id(line, ID_EXTRA_SYMBOLS)) {
            remove_id(line, ID_EXTRA_SYMBOLS);
            extra_symbols = line;
            continue;
        }
    }

    return true;
}

bool PwdGenConstraints::write_constraint_desc(QTextStream &service_ostream) {
    QString case_sens;
    if(case_sensitivity) {
        case_sens = "true";
    } else {
        case_sens = "false";
    }
    service_ostream << "    " << ID_CASE_SENSITIVITY << case_sens << endl;
    service_ostream << "    " << ID_NUMBER_OF_CAPS << number_of_caps << endl;
    service_ostream << "    " << ID_NUMBER_OF_DIGITS << number_of_digits << endl;
    service_ostream << "    " << ID_MAXIMAL_LENGTH << maximal_length << endl;
    service_ostream << "    " << ID_EXTRA_SYMBOLS << extra_symbols << endl;

    return true;
}

const PwdGenCachedData default_cached_data;

const QString ID_CONSTRAINT_COUNTER("constraint_counter : ");

bool PwdGenCachedData::parse_cached_data_desc(QTextStream &service_istream) {
    QString line;
    while(service_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments
        line = service_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //Check if we have reached the end of constraint declaration
        if(line.at(0) == '}') break;

        //Check constraint counter
        if(has_id(line, ID_CONSTRAINT_COUNTER)) {
            remove_id(line, ID_CONSTRAINT_COUNTER);
            constraint_counter = line.toULongLong();
            continue;
        }
    }

    return true;
}

bool PwdGenCachedData::write_cached_data_desc(QTextStream &service_ostream) {
    service_ostream << "    " << ID_CONSTRAINT_COUNTER << constraint_counter << endl;

    return true;
}

DefaultPasswordGenerator default_pw_generator;
PasswordGenerator& default_generator = default_pw_generator;

PasswordGenerator* generator_database(const QString& generator_name) {
    if(generator_name == default_pw_generator.name()) {
        return &default_pw_generator;
    }

    return NULL;
}

bool test_password_generators() {
    bool result = default_pw_generator.test();
    if(!result) return false;

    return true;
}

const QString PASSWORD_GENERATOR_NAME("PasswordGenerator");

bool PasswordGenerator::test() {
    const QString file_path = TEST_VEC_FILEPATH.arg(name());
    CryptoHash* hash = NULL;
    HMAC* hmac = NULL;
    QString line, result;
    size_t hashed_key_length = 0;
    uint64_t* hashed_key = NULL;
    PwdGenConstraints constraints;
    PwdGenCachedData cached_data;

    //Open test file
    QFile test_file(file_path);
    if(test_file.exists() == false) {
        log_error(PASSWORD_GENERATOR_NAME, ERR_FILE_NOT_FOUND.arg(file_path));
        return false;
    }
    if(test_file.open(QIODevice::ReadOnly) == false) {
        log_error(PASSWORD_GENERATOR_NAME, ERR_FILE_OPEN_FAILURE.arg(file_path));
        return false;
    }
    QTextStream test_istream(&test_file);
    if(test_istream.readLine() != TEST_FILE_HEADER) {
        log_error(PASSWORD_GENERATOR_NAME, ERR_FILE_HEADER_INCORRECT.arg(file_path));
        return false;
    }

    //Perform tests
    while(test_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments and spacing
        line = test_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //When encountering a hash, use it
        if(has_id(line, ID_HASH)) {
            remove_id(line, ID_HASH);
            hash = crypto_hash_database(line);
            if(!hash) return false;
            continue;
        }

        //When encountering an hmac, use it
        if(has_id(line, ID_HMAC)) {
            remove_id(line, ID_HMAC);
            hmac = hmac_database(line);
            if(!hmac) return false;
            continue;
        }

        //When encountering a key, store it for future use
        if(has_id(line, ID_KEY)) {
            //Convert key to qwords
            remove_id(line, ID_KEY);
            hashed_key_length = qword_length_hex(line);
            if(hashed_key_length != hash->hash_length()) {
                log_error(PASSWORD_GENERATOR_NAME, ERR_NOT_AN_HASHED_KEY.arg(line));
                return false;
            }
            hashed_key = new uint64_t[hashed_key_length];
            if(!hashed_key) {
                log_error(PASSWORD_GENERATOR_NAME, ERR_BAD_ALLOC.arg(QString("hashed_key")));
                return false;
            }
            if(qwords_from_hex_str(line, hashed_key) == false) {
                delete[] hashed_key;
                log_error(PASSWORD_GENERATOR_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            continue;
        }

        //When encountering a constraints descriptor, load it
        if(has_id(line, ID_CONSTRAINTS)) {
            remove_id(line, ID_CONSTRAINTS);
            bool result = constraints.parse_constraint_desc(test_istream);
            if(!result) {
                if(hashed_key) delete[] hashed_key;
                return false;
            }
            continue;
        }

        //When encountering a cached data descriptor, load it
        if(has_id(line, ID_CACHED_DATA)) {
            remove_id(line, ID_CACHED_DATA);
            bool result = cached_data.parse_cached_data_desc(test_istream);
            if(!result) {
                if(hashed_key) delete[] hashed_key;
                return false;
            }
            continue;
        }

        //When encountering a result, generate a password and check it against the known good result
        if(has_id(line, ID_RESULT)) {
            remove_id(line, ID_RESULT);
            generate_password(hashed_key, hmac, hash, &constraints, &cached_data, result);
            delete[] hashed_key;
            if(result!=line) {
                log_error(PASSWORD_GENERATOR_NAME, ERR_WRONG_RESULT.arg(result).arg(line));
                return false;
            }
            continue;
        }
    }

    return true;
}

const QString DEFAULT_PASSWORD_GENERATOR_NAME("DefaultPasswordGenerator");

QString* DefaultPasswordGenerator::generate_password(uint64_t* hashed_key,
                                              HMAC* hmac,
                                              CryptoHash* hash,
                                              PwdGenConstraints* constraints,
                                              PwdGenCachedData* cached_data,
                                              QString& dest_buffer) {
    //Check if the requested constraints are actually matchable
    bool tmp_result = matchable_constraints(constraints);
    if(!tmp_result) return NULL;

    //Generate number->QChar conversion table for the allowed character set
    tmp_result = generate_conversion_table(constraints);
    if(!tmp_result) return NULL;

    //Prepare HMAC storage space
    size_t hmac_length = hash->hash_length();
    uint64_t* hmac_buffer = new uint64_t[hmac_length];
    if(!hmac_buffer) {
        log_error(DEFAULT_PASSWORD_GENERATOR_NAME, ERR_BAD_ALLOC.arg(QString("hmac_buffer")));
        return NULL;
    }

    //Compute HMAC(hashed_key, cached_date->constraint_counter) and convert it to a string,
    //try to make the result match constraints. If it fails, increment the counter and start over.
    bool first_run = true;
    do {
        if(!first_run) {
            cached_data->constraint_counter+= 1;
        } else {
            first_run = false;
        }

        uint64_t* hmac_result = hmac->hmac(hash->hash_length(),
                                           hashed_key,
                                           1,
                                           &(cached_data->constraint_counter),
                                           hash,
                                           hmac_buffer);
        if(!hmac_result) {
            memset((void*) hmac_buffer, 0, hmac_length*sizeof(uint64_t));
            delete[] hmac_buffer;
            return NULL;
        }
        hmac_to_qstring(hmac_length, hmac_result, dest_buffer);
    } while(match_constraints(dest_buffer, constraints) == false);

    memset((void*) hmac_buffer, 0, hmac_length*sizeof(uint64_t));
    delete[] hmac_buffer;
    return &dest_buffer;
}

bool DefaultPasswordGenerator::generate_conversion_table(PwdGenConstraints* constraints) {
    //Determine conversion table length and allocate it if needed
    size_t previous_conversion_table_length = conversion_table_length;
    conversion_table_length = 26+10; //Minuscules + digits
    if(constraints->case_sensitivity) conversion_table_length+= 26; //Caps
    conversion_table_length+= constraints->extra_symbols.size(); //Extra symbols

    if((!conversion_table) || (conversion_table_length != previous_conversion_table_length)) {
        if(conversion_table) delete[] conversion_table;
        conversion_table = new QChar[conversion_table_length];
        if(!conversion_table) {
            conversion_table_length = 0;
            log_error(DEFAULT_PASSWORD_GENERATOR_NAME, ERR_BAD_ALLOC.arg(QString("conversion_table")));
            return false;
        }
    }


    //Fill conversion table
    size_t offset = 0;
    for(char i = 0; i<26; ++i) {
        conversion_table[i+offset] = 'a'+i;
    }
    offset+= 26;
    for(char i = 0; i<10; ++i) {
        conversion_table[i+offset] = '0'+i;
    }
    offset+= 10;
    if(constraints->case_sensitivity) {
        for(char i = 0; i<26; ++i) {
            conversion_table[i+offset] = 'A'+i;
        }
        offset+= 26;
    }
    for(char i = 0; i<constraints->extra_symbols.size(); ++i) {
        conversion_table[i+offset] = constraints->extra_symbols[i];
    }
    offset+= constraints->extra_symbols.size();

    return conversion_table;
}

QString& DefaultPasswordGenerator::hmac_to_qstring(size_t hmac_length, uint64_t* hmac, QString& dest_buffer) {
    dest_buffer.clear();
    for(size_t hmac_index = 0; hmac_index < hmac_length; ++hmac_index) {
        uint64_t hmac_digit = hmac[hmac_index];
        uint64_t mask = 0xffffffffffffffff;
        while(mask) {
            size_t current_char = hmac_digit%conversion_table_length;
            dest_buffer.append(conversion_table[current_char]);
            hmac_digit/= conversion_table_length;
            mask/= conversion_table_length;
        }
    }

    return dest_buffer;
}

bool DefaultPasswordGenerator::match_constraints(QString& potential_result, PwdGenConstraints* constraints) {
    //For the final truncating step, we will need to keep a list of "protected chars"
    //that one should not touch in order to keep constraints matched.
    int* protected_chars = new int[potential_result.size()];
    if(!protected_chars) return false;
    int protected_chars_amount = 0;

    //Make sure that the potential result matches constraints on the number of digits and caps
    if(constraints->number_of_digits || constraints->number_of_caps) {
        int digit_amount = 0;
        int caps_amount = 0;
        for(int i = 0; i < potential_result.size(); ++i) {
            if(digit_amount < constraints->number_of_digits) {
                if(potential_result.at(i) >= QChar('0') && potential_result.at(i) <= QChar('9')) {
                    ++digit_amount;
                    protected_chars[protected_chars_amount] = i;
                    ++protected_chars_amount;
                }
            }
            if(caps_amount < constraints->number_of_caps) {
                if(potential_result.at(i) >= QChar('A') && potential_result.at(i) <= QChar('Z')) {
                    ++caps_amount;
                    protected_chars[protected_chars_amount] = i;
                    ++protected_chars_amount;
                }
            }
            //If all constraints are matched, there's no need to parse further
            if((digit_amount == constraints->number_of_digits) && (caps_amount == constraints->number_of_caps)) break;
        }
        if(digit_amount < constraints->number_of_digits) {
            delete[] protected_chars;
            return false;
        }
        if(caps_amount < constraints->number_of_caps) {
            delete[] protected_chars;
            return false;
        }
    }

    //Truncate the password to reach desired length, keeping other constraints matched
    if(constraints->maximal_length) {
        if(potential_result.size() > constraints->maximal_length) {
            int removed_chars = 0;
            int protected_chars_index = 0;
            int initial_size = potential_result.size();
            for(int i = 0; i < initial_size; ++i) {
                //Skip protected chars
                if((protected_chars_index < protected_chars_amount) &&
                        (i == protected_chars[protected_chars_index])) {
                    ++protected_chars_index;
                    continue;
                }

                //Remove current character
                potential_result.remove(i - removed_chars, 1);
                ++removed_chars;

                //Check if the string has reached the desired length
                if(potential_result.size() == constraints->maximal_length) break;
            }
        }
        if(potential_result.size() > constraints->maximal_length) {
            delete[] protected_chars;
            return false;
        }
    }

    delete[] protected_chars;
    return true;
}

bool DefaultPasswordGenerator::matchable_constraints(PwdGenConstraints* constraints) {
    //number_of_caps constraint may only be matched if case sensitivity is enabled
    if((constraints->case_sensitivity == false) && constraints->number_of_caps) {
        static const QString ERR_IMPOSSIBLE_CAPS("Unmatchable constraint : nonzero minimal number of caps without case sensitivity.");
        log_error(DEFAULT_PASSWORD_GENERATOR_NAME, ERR_IMPOSSIBLE_CAPS);
        return false;
    }

    //maximal_length, if any, must be superior to the total number of requested specific characters
    int requested_specific_chars = constraints->number_of_digits + constraints->number_of_caps;
    if((constraints->maximal_length) && (constraints->maximal_length < requested_specific_chars)) {
        static const QString ERR_IMPOSSIBLE_MAX_LENGTH("Unmatchable constraint : more caps and digits required than the maximal length.");
        log_error(DEFAULT_PASSWORD_GENERATOR_NAME, ERR_IMPOSSIBLE_MAX_LENGTH);
        return false;
    }

    return true;
}
