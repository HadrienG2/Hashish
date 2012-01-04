/* Service descriptor : contains all the information about a registered service
   that is necessary in order to generate it.

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

#ifndef SERVICE_DESCRIPTOR_H
#define SERVICE_DESCRIPTOR_H

#include <QFile>
#include <QString>
#include <QTextStream>
#include <stddef.h>
#include <stdint.h>

#include <crypto_hash.h>
#include <hmac.h>
#include <password_cipher.h>
#include <password_generator.h>

enum PasswordType {GENERATED = 0, ENCRYPTED};

struct ServiceDescriptor {
  public:
    //Service identifier
    QString service_name;

    //Hashed key generation parameters
    CryptoHash* hash_used;
    HMAC* hmac_used;
    uint64_t iterations;
    uint64_t nonce;

    //Hashed key -> password conversion
    PasswordType password_type;
    //For purely generated passwords
    PasswordGenerator* generator_used;
    PwdGenConstraints* constraints;
    PwdGenCachedData* cached_data;
    //For encrypted passwords
    PasswordCipher* cipher_used;
    size_t encrypted_pw_length;
    uint64_t* encrypted_pw;

    //Default constructor, copy constructor...
    ServiceDescriptor(QString initial_name = "",
                      uint64_t default_iterations = 0);
    ServiceDescriptor(const ServiceDescriptor& source);
    ~ServiceDescriptor();
    ServiceDescriptor& operator=(const ServiceDescriptor& source);

    //Determine optimal amount of iterations on current hardware. Designed to be run on an
    //unmodified and disposable ServiceDescriptor (the value of default_iterations doesn't matter)
    uint64_t benchmark_iterations(uint64_t acceptable_latency);

    //Computes the service password, given a master password
    QString* compute_password(const QString& master_pw,
                              QString& dest_buffer);

    //Encrypt a service password and store it in encrypted_password. Switch to encryption mode.
    bool encrypt_password(const QString& master_pw,
                          const QString& service_pw);

    //Load and save services from "descriptor files"
    bool load_from_file(const QString& descriptor_filepath);
    bool save_to_file(const QString& descriptor_filepath);

    //Reinitialize the service descriptor to its initial password-generating state.
    void reset(const QString& initial_name, const uint64_t default_iterations);
  private:
    QFile* service_file;

    uint64_t* compute_hashed_key(const QString& master_pw,
                                 uint64_t* dest_buffer,
                                 bool benchmark_mode = false);
    uint64_t* compute_initial_key(const QString& master_pw,
                                  size_t service_nonce_length,
                                  uint64_t* service_nonce,
                                  uint64_t* dest_buffer);
    QString* decrypt_password(uint64_t* hashed_key, QString& dest_buffer);
    bool encrypted_pw_from_qstring(QString& line);
    bool encrypted_pw_to_qstring(QString& line);
    QString* generate_password(uint64_t* hashed_key, QString& dest_buffer);
    bool parse_service_desc(QTextStream &service_istream);
    bool write_service_desc(QTextStream &service_ostream);
};

#endif // SERVICE_DESCRIPTOR_H
