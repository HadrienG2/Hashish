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

#include <string.h>
#include <time.h>

#include <error_management.h>
#include <parsing_tools.h>
#include <qstring_to_qwords.h>
#include <service_descriptor.h>

const QString SERVICE_DESCRIPTOR_NAME("ServiceDescriptor");

const QString ID_SERVICE_NAME("service_name : ");
const QString ID_HASH_USED("hash_used : ");
const QString ID_HMAC_USED("hmac_used : ");
const QString ID_ITERATIONS("iterations : ");
const QString ID_NONCE("nonce : ");
const QString ID_PASSWORD_TYPE("password_type : ");
const QString ID_GENERATOR_USED("generator_used : ");
const QString ID_CONSTRAINTS("constraints : ");
const QString ID_CACHED_DATA("cached_data : ");
const QString ID_CIPHER_USED("cipher_used : ");
const QString ID_ENCRYPTED_PW("encrypted_pw : ");

const QString SERVICE_DESCRIPTOR_HEADER("*** Hashish service descriptor v1 ***");

ServiceDescriptor::ServiceDescriptor(QString initial_name,
                                     uint64_t default_iterations) : service_name(initial_name),
                                                                    hash_used(&default_hash),
                                                                    hmac_used(&default_hmac),
                                                                    iterations(default_iterations),
                                                                    nonce(0),
                                                                    password_type(GENERATED),
                                                                    generator_used(&default_generator),
                                                                    cipher_used(&default_cipher),
                                                                    encrypted_pw_length(0),
                                                                    encrypted_pw(NULL),
                                                                    service_file(NULL) {
    constraints = new PwdGenConstraints;
    if(!constraints) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("constraints")));
    } else {
        *constraints = default_constraints;
    }
    cached_data = new PwdGenCachedData;
    if(!cached_data) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("cached_data")));
    } else {
        *cached_data = default_cached_data;
    }
}

ServiceDescriptor::ServiceDescriptor(const ServiceDescriptor& source) : service_name(source.service_name),
                                                                        hash_used(source.hash_used),
                                                                        hmac_used(source.hmac_used),
                                                                        iterations(source.iterations),
                                                                        nonce(source.nonce),
                                                                        password_type(source.password_type),
                                                                        generator_used(source.generator_used),
                                                                        cipher_used(source.cipher_used),
                                                                        encrypted_pw_length(source.encrypted_pw_length),
                                                                        service_file(NULL) {
    if(source.constraints) {
        constraints = new PwdGenConstraints;
        if(!constraints) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("constraints")));
        } else {
            *constraints = *(source.constraints);
        }
    }

    if(source.cached_data) {
        cached_data = new PwdGenCachedData;
        if(!cached_data) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("cached_data")));
        } else {
            *cached_data = *(source.cached_data);
        }
    }

    if(source.encrypted_pw) {
        encrypted_pw = new uint64_t[encrypted_pw_length];
        if(!encrypted_pw) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("encrypted_pw")));
            encrypted_pw_length = 0;
        } else {
            memcpy((void*) encrypted_pw, (const void*) source.encrypted_pw, encrypted_pw_length*sizeof(uint64_t));
        }
    }
}

ServiceDescriptor::~ServiceDescriptor() {
    if(constraints) delete constraints;
    if(cached_data) delete cached_data;
    if(encrypted_pw) delete[] encrypted_pw;
    if(service_file) delete service_file;
}

ServiceDescriptor& ServiceDescriptor::operator=(const ServiceDescriptor& source) {
    service_name = source.service_name;
    hash_used = source.hash_used;
    hmac_used = source.hmac_used;
    iterations = source.iterations;
    nonce = source.nonce;
    password_type = source.password_type;
    generator_used = source.generator_used;
    cipher_used = source.cipher_used;

    if(constraints && !(source.constraints)) delete constraints, constraints = NULL;
    if(source.constraints) {
        if(!constraints) constraints = new PwdGenConstraints;
        if(!constraints) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("constraints")));
        } else {
            *constraints = *(source.constraints);
        }
    }

    if(cached_data && !(source.cached_data)) delete cached_data, cached_data = NULL;
    if(source.cached_data) {
        if(!cached_data) cached_data = new PwdGenCachedData;
        if(!cached_data) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("cached_data")));
        } else {
            *cached_data = *(source.cached_data);
        }
    }

    if(encrypted_pw && (encrypted_pw_length != source.encrypted_pw_length)) delete[] encrypted_pw, encrypted_pw = NULL;
    encrypted_pw_length = source.encrypted_pw_length;
    if(source.encrypted_pw) {
        if(!encrypted_pw) encrypted_pw = new uint64_t[encrypted_pw_length];
        if(!encrypted_pw) {
            log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("encrypted_pw")));
            encrypted_pw_length = 0;
        } else {
            memcpy((void*) encrypted_pw, (const void*) source.encrypted_pw, encrypted_pw_length*sizeof(uint64_t));
        }
    }

    return *this;
}

uint64_t ServiceDescriptor::benchmark_iterations(uint64_t acceptable_latency) {
    service_name = "This dummy service name is voluntarily very long, as a worst-case scenario.";
    QString dummy_pw = "The same goes for this dummy master password ! 0123456789ABCDEFGHIJKLMNOP";

    //Determine the final time at which the benchmark must stop
    clock_t final_time = clock() + (acceptable_latency*CLOCKS_PER_SEC)/1000;

    //Run compute_password in benchmark mode, which makes it stop just before key hashing and
    //return a casted key block that is ready to hash
    size_t hashed_key_length = hash_used->hash_length();
    uint64_t* hashed_key = new uint64_t[hashed_key_length];
    if(!hashed_key) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("hashed_key")));
        return 0;
    }
    uint64_t* tmp_result = compute_hashed_key(dummy_pw, hashed_key, true);
    if(!tmp_result) {
        delete[] hashed_key;
        return 0;
    }

    //Hash the key until the timer stops
    uint64_t current_iteration = 0;
    while(clock() < final_time) {
        ++current_iteration;
        uint64_t* tmp_result = hash_used->hash(hashed_key_length, hashed_key, hashed_key);
        if(!tmp_result) {
            delete[] hashed_key;
            return 0;
        }
    }

    //Clean up allocated blocks, return number of iterations
    delete[] hashed_key;
    return current_iteration;
}

QString* ServiceDescriptor::compute_password(const QString& master_pw,
                                             QString& dest_buffer) {
    //Compute a hashed key from the master password, service name, nonce, etc...
    size_t hashed_key_length = hash_used->hash_length();
    uint64_t* hashed_key = new uint64_t[hashed_key_length];
    if(!hashed_key) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("hashed_key")));
        return NULL;
    }
    uint64_t* tmp_result = compute_hashed_key(master_pw, hashed_key);
    if(!tmp_result) {
        memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
        delete[] hashed_key;
        return NULL;
    }

    //Use hashed_key as a basis to generate or decrypt the service password
    QString* result = NULL;
    switch(password_type) {
      case GENERATED:
        result = generate_password(hashed_key, dest_buffer);
        break;
      case ENCRYPTED:
        result = decrypt_password(hashed_key, dest_buffer);
        break;
    }
    memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
    delete[] hashed_key;
    return result;
}

bool ServiceDescriptor::encrypt_password(const QString& master_pw,
                                         const QString& service_pw) {
    //Create a qword version of the service password
    size_t qw_service_length = qword_length_raw(service_pw);
    uint64_t* qw_service = new uint64_t[qw_service_length];
    if(!qw_service) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("qw_service")));
        return false;
    }
    qwords_from_raw_str(service_pw, qw_service);

    //Compute a hashed key from the master password, service name, nonce, etc...
    size_t hashed_key_length = hash_used->hash_length();
    uint64_t* hashed_key = new uint64_t[hashed_key_length];
    if(!hashed_key) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("hashed_key")));
        memset((void*) qw_service, 0, qw_service_length*sizeof(uint64_t));
        delete[] qw_service;
        return false;
    }
    uint64_t* tmp_result = compute_hashed_key(master_pw, hashed_key);
    if(!tmp_result) {
        memset((void*) qw_service, 0, qw_service_length*sizeof(uint64_t));
        delete[] qw_service;
        memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
        delete[] hashed_key;
        return false;
    }

    //Make sure there's space for storing the encrypted password
    encrypted_pw_length = qw_service_length;
    if(encrypted_pw) delete[] encrypted_pw;
    encrypted_pw = new uint64_t[encrypted_pw_length];
    if(!encrypted_pw) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("encrypted_pw")));
        memset((void*) qw_service, 0, qw_service_length*sizeof(uint64_t));
        delete[] qw_service;
        memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
        delete[] hashed_key;
        return false;
    }

    //Compute the encrypted password
    tmp_result = cipher_used->encrypt(hashed_key,
                                      qw_service_length,
                                      qw_service,
                                      hash_used,
                                      encrypted_pw);
    memset((void*) qw_service, 0, qw_service_length*sizeof(uint64_t));
    delete[] qw_service;
    memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
    delete[] hashed_key;
    if(!tmp_result) return false;

    //Switch the descriptor to encrypted password mode and return
    password_type = ENCRYPTED;
    return true;
}

bool ServiceDescriptor::load_from_file(const QString& descriptor_filepath) {
    bool success;
    //Access service descriptor file. If it does not exist, abort.
    if(!service_file) service_file = new QFile;
    if(!service_file) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("service_file")));
        return false;
    }
    service_file->setFileName(descriptor_filepath);
    if(service_file->exists() == false) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_FILE_NOT_FOUND.arg(descriptor_filepath));
        return false;
    }

    //Check file header. If it is incorrect, abort.
    success = service_file->open(QFile::ReadOnly);
    if(!success) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_FILE_OPEN_FAILURE.arg(descriptor_filepath));
        return false;
    }
    QTextStream service_istream(service_file);
    QString header = service_istream.readLine();
    if(header != SERVICE_DESCRIPTOR_HEADER) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_FILE_HEADER_INCORRECT.arg(descriptor_filepath));
        service_istream.flush();
        service_file->close();
        return false;
    }

    //Read service descriptor from the file
    success = parse_service_desc(service_istream);
    service_file->close();
    if(!success) return false;
    return true;
}

bool ServiceDescriptor::save_to_file(const QString& descriptor_filepath) {
    bool success;
    //Access service descriptor file. If it exists, make a backup copy.
    if(!service_file) service_file = new QFile;
    if(!service_file) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("service_file")));
        return false;
    }
    QString backup_file = descriptor_filepath+'~';
    service_file->setFileName(descriptor_filepath);
    if(service_file->exists()) service_file->copy(backup_file);

    //Open file for writing
    success = service_file->open(QFile::WriteOnly | QFile::Truncate);
    if(!success) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_FILE_OPEN_FAILURE.arg(descriptor_filepath));
        service_file->remove(backup_file);
        return false;
    }

    //Write header, then contents
    QTextStream service_ostream(service_file);
    service_ostream << SERVICE_DESCRIPTOR_HEADER << endl << endl;
    success = write_service_desc(service_ostream);
    service_ostream.flush();
    service_file->close();
    if(!success) {
        //Restore backup if writing has failed
        service_file->remove();
        service_file->copy(backup_file, descriptor_filepath);
        return false;
    }

    //Clean up
    service_file->remove(backup_file);
    return true;
}

void ServiceDescriptor::reset(const QString& initial_name, const uint64_t default_iterations) {
    *this = ServiceDescriptor(initial_name, default_iterations);
}

uint64_t* ServiceDescriptor::compute_hashed_key(const QString& master_pw,
                                                uint64_t* dest_buffer,
                                                bool benchmark_mode) {
    //Generate service_nonce = service_name + delim + nonce where delim is (uint64_t) 0
    size_t service_nonce_length = qword_length_raw(service_name) + 2;
    uint64_t* service_nonce = new uint64_t[service_nonce_length];
    if(!service_nonce) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("service_nonce")));
        return NULL;
    }

    qwords_from_raw_str(service_name, service_nonce);
    service_nonce[service_nonce_length - 2] = 0;
    service_nonce[service_nonce_length - 1] = nonce;

    //Compute initial_key = HMAC(master_pw, service_nonce)
    size_t initial_key_length = hash_used->hash_length();
    uint64_t* initial_key = new uint64_t[initial_key_length];
    if(!initial_key) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("initial_key")));
        delete[] service_nonce;
        return NULL;
    }

    uint64_t* tmp_result = compute_initial_key(master_pw,
                                               service_nonce_length,
                                               service_nonce,
                                               initial_key);
    delete[] service_nonce;
    if(!tmp_result) {
        memset((void*) initial_key, 0, initial_key_length*sizeof(uint64_t));
        delete[] initial_key;
        return NULL;
    }

    //Compute hashed_key = hash^iterations(initial_key)
    size_t hashed_key_length = initial_key_length;
    uint64_t* hashed_key = dest_buffer;
    memcpy((void*) hashed_key, (const void*) initial_key, hashed_key_length*sizeof(uint64_t));
    memset((void*) initial_key, 0, initial_key_length*sizeof(uint64_t));
    delete[] initial_key;

    if(benchmark_mode) return hashed_key; //In benchmark mode, we stop just before hashing
    for(size_t i = 0; i<iterations; ++i) {
        tmp_result = hash_used->hash(hashed_key_length, hashed_key, hashed_key);
        if(!tmp_result) {
            memset((void*) hashed_key, 0, hashed_key_length*sizeof(uint64_t));
            return NULL;
        }
    }

    return hashed_key;
}

uint64_t* ServiceDescriptor::compute_initial_key(const QString& master_pw,
                                                 size_t service_nonce_length,
                                                 uint64_t* service_nonce,
                                                 uint64_t* dest_buffer) {
    //Convert master_pw to a qword form suitable for hash computations
    size_t qw_password_length = qword_length_raw(master_pw);
    uint64_t* qw_password = new uint64_t[qw_password_length];
    if(!qw_password) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("qw_password")));
        return NULL;
    }
    qwords_from_raw_str(master_pw, qw_password);

    //Compute HMAC(master_pw, service_nonce), return result
    uint64_t* result = hmac_used->hmac(qw_password_length,
                                       qw_password,
                                       service_nonce_length,
                                       service_nonce,
                                       hash_used,
                                       dest_buffer);
    memset((void*) qw_password, 0, qw_password_length*sizeof(uint64_t));
    delete[] qw_password;
    if(!result) return NULL;

    return result;

}

QString* ServiceDescriptor::decrypt_password(uint64_t* hashed_key, QString& dest_buffer) {
    //Prepare space for the qword version of the decrypted password
    size_t decrypted_pw_length = encrypted_pw_length;
    uint64_t* decrypted_pw = new uint64_t[decrypted_pw_length];
    if(!decrypted_pw) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg("decrypted_pw"));
        return NULL;
    }

    //Perform decryption
    uint64_t* decryption_result = cipher_used->decrypt(hashed_key,
                                                       encrypted_pw_length,
                                                       encrypted_pw,
                                                       hash_used,
                                                       decrypted_pw);
    if(!decryption_result) {
        memset((void*) decrypted_pw, 0, decrypted_pw_length*sizeof(uint64_t));
        delete[] decrypted_pw;
        return NULL;
    }

    //Convert result back to a QString
    QString* result = qwords_to_raw_str(encrypted_pw_length, decrypted_pw, dest_buffer);
    memset((void*) decrypted_pw, 0, decrypted_pw_length*sizeof(uint64_t));
    delete[] decrypted_pw;
    return result;
}

bool ServiceDescriptor::encrypted_pw_from_qstring(QString& line) {
    //Attempt to compute encrypted password length. If it fails, the password is malformed : abort.
    size_t tmp_encrypted_pw_length = qword_length_hex(line);
    if(!tmp_encrypted_pw_length) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_HEX_DATA.arg(line));
        return false;
    }

    //Allocate encrypted password
    encrypted_pw_length = tmp_encrypted_pw_length;
    if(encrypted_pw) delete[] encrypted_pw;
    encrypted_pw = new uint64_t[encrypted_pw_length];
    if(!encrypted_pw) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_ALLOC.arg(QString("encrypted_pw")));
        return false;
    }

    //Decode encrypted password
    uint64_t* result = qwords_from_hex_str(line, encrypted_pw);
    if(!result) {
        log_error(SERVICE_DESCRIPTOR_NAME, ERR_BAD_HEX_DATA.arg(line));
        return false;
    }

    return true;
}

bool ServiceDescriptor::encrypted_pw_to_qstring(QString& line) {
    qwords_to_hex_str(encrypted_pw_length, encrypted_pw, line);

    return true;
}

QString* ServiceDescriptor::generate_password(uint64_t* hashed_key, QString& dest_buffer) {
    return generator_used->generate_password(hashed_key,
                                             hmac_used,
                                             hash_used,
                                             constraints,
                                             cached_data,
                                             dest_buffer);
}

bool ServiceDescriptor::parse_service_desc(QTextStream &service_istream) {
    bool success;
    QString line;
    while(service_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments
        line = service_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //Check service name
        if(has_id(line, ID_SERVICE_NAME)) {
            remove_id(line, ID_SERVICE_NAME);
            service_name = line;
            continue;
        }

        //Check cryptographic hash
        if(has_id(line, ID_HASH_USED)) {
            remove_id(line, ID_HASH_USED);
            CryptoHash* requested_hash = crypto_hash_database(line);
            if(!requested_hash) {
                log_error(SERVICE_DESCRIPTOR_NAME, ERR_UNSUPPORTED_HASH.arg(line));
                return false;
            }
            hash_used = requested_hash;
            continue;
        }

        //Check HMAC
        if(has_id(line, ID_HMAC_USED)) {
            remove_id(line, ID_HMAC_USED);
            HMAC* requested_hmac = hmac_database(line);
            if(!requested_hmac) {
                log_error(SERVICE_DESCRIPTOR_NAME, ERR_UNSUPPORTED_HMAC.arg(line));
                return false;
            }
            hmac_used = requested_hmac;
            continue;
        }

        //Check number of hash iterations
        if(has_id(line, ID_ITERATIONS)) {
            remove_id(line, ID_ITERATIONS);
            iterations = line.toULongLong();
            continue;
        }

        //Check hash nonce
        if(has_id(line, ID_NONCE)) {
            remove_id(line, ID_NONCE);
            nonce = line.toULongLong();
            continue;
        }

        //Check password type
        if(has_id(line, ID_PASSWORD_TYPE)) {
            remove_id(line, ID_PASSWORD_TYPE);
            password_type = (PasswordType) line.toInt();
            continue;
        }

        //Check password generator
        if(has_id(line, ID_GENERATOR_USED)) {
            remove_id(line, ID_GENERATOR_USED);
            PasswordGenerator* requested_generator = generator_database(line);
            if(!requested_generator) {
                log_error(SERVICE_DESCRIPTOR_NAME, ERR_UNSUPPORTED_PW_GEN.arg(line));
                return false;
            }
            generator_used = requested_generator;
            continue;
        }

        //Check constraints
        if(has_id(line, ID_CONSTRAINTS)) {
            success = constraints->parse_constraint_desc(service_istream);
            if(!success) return false;
            continue;
        }

        //Check cached data
        if(has_id(line, ID_CACHED_DATA)) {
            success = cached_data->parse_cached_data_desc(service_istream);
            if(!success) return false;
            continue;
        }

        //Check password cipher
        if(has_id(line, ID_CIPHER_USED)) {
            remove_id(line, ID_CIPHER_USED);
            PasswordCipher* requested_cipher = cipher_database(line);
            if(!requested_cipher) {
                log_error(SERVICE_DESCRIPTOR_NAME, ERR_UNSUPPORTED_CIPHER.arg(line));
                return false;
            }
            cipher_used = requested_cipher;
            continue;
        }

        //Check encrypted password (and its length)
        if(has_id(line, ID_ENCRYPTED_PW)) {
            remove_id(line, ID_ENCRYPTED_PW);
            success = encrypted_pw_from_qstring(line);
            if(!success) return false;
            continue;
        }
    }

    return true;
}

bool ServiceDescriptor::write_service_desc(QTextStream &service_ostream) {
    bool success;
    service_ostream << ID_SERVICE_NAME << service_name << endl << endl;

    if(hash_used) service_ostream << ID_HASH_USED << hash_used->name() << endl;
    if(hmac_used) service_ostream << ID_HMAC_USED << hmac_used->name() << endl;
    service_ostream << ID_ITERATIONS << iterations << endl;
    service_ostream << ID_NONCE << nonce << endl << endl;

    service_ostream << ID_PASSWORD_TYPE << (int) password_type << endl;
    if(generator_used) service_ostream << ID_GENERATOR_USED << generator_used->name() << endl;
    if(constraints) {
        service_ostream << ID_CONSTRAINTS << '{' << endl;
        success = constraints->write_constraint_desc(service_ostream);
        if(!success) return false;
        service_ostream << '}' << endl;
    }
    if(cached_data) {
        service_ostream << ID_CACHED_DATA << '{' << endl;
        success = cached_data->write_cached_data_desc(service_ostream);
        if(!success) return false;
        service_ostream << '}' << endl;
    }
    if(cipher_used) service_ostream << ID_CIPHER_USED << cipher_used->name() << endl;
    if(encrypted_pw) {
        QString encrypted_pw_buff;
        success = encrypted_pw_to_qstring(encrypted_pw_buff);
        if(!success) return false;
        service_ostream << ID_ENCRYPTED_PW << encrypted_pw_buff << endl;
    }

    return true;
}
