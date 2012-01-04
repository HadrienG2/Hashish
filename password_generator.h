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

#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <QString>
#include <QTextStream>
#include <cstddef>

#include <crypto_hash.h>
#include <hmac.h>

struct PwdGenConstraints {
    bool case_sensitivity;
    int number_of_caps; //0 means no constraints
    int number_of_digits; //0 means no constraint
    int maximal_length; //0 means unlimited
    QString extra_symbols; //As a default, we allow latin characters (both lower and upper case)
                           //and numbers. Extra symbols can be added by putting them in that string
    PwdGenConstraints() : case_sensitivity(false),
                          number_of_caps(0),
                          number_of_digits(0),
                          maximal_length(15) {}
    bool parse_constraint_desc(QTextStream &service_istream);
    bool write_constraint_desc(QTextStream &service_ostream);
};
extern const PwdGenConstraints default_constraints;

struct PwdGenCachedData {
    uint64_t constraint_counter; //If the first automatically generated password does not match
                                 //constraints, a counter is added to the generator's input and
                                 //incremented until constraints are matched. To accelerate
                                 //subsequent runs, the right counter value is cached.
                                 //
                                 //This is set to 0 when the password has not been generated yet
    PwdGenCachedData() : constraint_counter(0) {}
    bool parse_cached_data_desc(QTextStream &service_istream);
    bool write_cached_data_desc(QTextStream &service_ostream);
};
extern const PwdGenCachedData default_cached_data;

class PasswordGenerator {
  public:
    virtual QString* generate_password(uint64_t* hashed_key,
                                       HMAC* hmac,
                                       CryptoHash* hash,
                                       PwdGenConstraints* constraints,
                                       PwdGenCachedData* cached_data,
                                       QString& dest_buffer) = 0;
    virtual QString name() = 0;
    bool test(); //Check the function against its known-good test vectors (if available)
};
extern PasswordGenerator& default_generator;
PasswordGenerator* generator_database(const QString& generator_name); //Fetches the generator that bears a given name, if any
bool test_password_generators(); //Check all finalized password generators against their known test vectors


class DefaultPasswordGenerator : public PasswordGenerator {
  public:
    DefaultPasswordGenerator() : conversion_table(NULL) {}
    ~DefaultPasswordGenerator() {if(conversion_table) delete[] conversion_table;}
    virtual QString* generate_password(uint64_t* hashed_key,
                                       HMAC* hmac,
                                       CryptoHash* hash,
                                       PwdGenConstraints* constraints,
                                       PwdGenCachedData* cached_data,
                                       QString& dest_buffer);
    virtual QString name() {return "Default generator";}
  private:
    size_t conversion_table_length;
    QChar* conversion_table;

    bool generate_conversion_table(PwdGenConstraints* constraints);
    QString& hmac_to_qstring(size_t hmac_length, uint64_t* hmac, QString& dest_buffer);
    bool match_constraints(QString& potential_result, PwdGenConstraints* constraints);
    bool matchable_constraints(PwdGenConstraints* constraints);
};

#endif // PASSWORD_GENERATOR_H
