/* Service manager : this QObject is the back-end of Hashish.
   It loads, save, and manages services, computes passwords, etc...

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

#ifndef SERVICE_MANAGER_H
#define SERVICE_MANAGER_H

#include <QDir>
#include <QFile>
#include <QHash>
#include <QLocalServer>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QStringListModel>
#include <QTextStream>
#include <stddef.h>
#include <time.h>

#include <service_descriptor.h>

#define CACHE_SIZE 10 //Maximum amount of services to keep cached

struct ServiceDescriptorCache {
    ServiceDescriptor descriptor;
    QString service_filename;
    clock_t last_used;
    ServiceDescriptorCache() : last_used(0) {}
};

class ServiceManager : public QObject {
    Q_OBJECT

  public:
    ServiceManager();
    ~ServiceManager();
    bool already_running() {return running_instance_found;}
    QStringListModel* available_services() {return service_name_list_model;}
    bool crypto_function_tests_passed() {return tests_passed;}
    uint64_t current_latency() {return acceptable_latency;}
    bool set_current_latency(uint64_t new_latency);

  public slots:
    void add_service(const QString& service_name);
    void delete_qobject(QObject* object); //Deletes a QObject after a small delay
    void generate_password(const QString& service_name, const QString& master_password);
    void load_service(const QString& service_name);
    void remove_service(const QString& service_name);
    void save_service(const QString& previous_name, const QString& new_name, ServiceDescriptor& service);

  signals:
    void new_instance_spawned(); //Triggered each time a new instance of Hashish is spawned
    void password_generation_failed();
    void password_ready(const QString& password);
    void service_loading_failed();
    void service_saving_failed();
    void service_ready(ServiceDescriptor& service);
    void service_removed();
    void service_saved();

  private slots:
    void ipc_new_connection();
    void perform_delete();

  private:
    uint64_t acceptable_latency;
    QDir* app_data_dir;
    ServiceDescriptorCache cached_services[CACHE_SIZE];
    uint64_t default_iterations;
    QFile* error_log_file;
    QTextStream* error_log_stream;
    QLocalServer* ipc_server;
    QString password_buffer;
    bool running_instance_found;
    QFile* service_db_file;
    QDir* service_dir;
    QStringList service_name_list;
    QStringListModel* service_name_list_model;
    QHash<QString, QString> service_filenames;
    QFile* settings_file;
    bool tests_passed;
    QObject* to_delete;

    void case_insensitive_sort(QStringList& list);
    void close_error_output();
    ServiceDescriptor* fetch_service(const QString& service_name);
    ServiceDescriptorCache* find_in_cache(const QString& service_filename);
    QString* find_new_service_filename();
    ServiceDescriptorCache& find_oldest_cache_entry();
    bool generate_service_database(bool from_scratch = false);
    bool generate_settings(bool from_scratch = false);
    QDir* open_application_data_directory();
    bool open_error_output();
    QDir* open_service_directory();
    bool parse_service_db(QTextStream& service_db_istream);
    bool parse_settings(QTextStream& settings_istream);
    QFile* read_service_database();
    QFile* read_settings();
    void sift_down(QStringList& list, const int start, const int end);
    bool start_ipc();
    void stop_ipc();
    void test_cryptographic_functions();
    bool update_service_name(const QString& former_name, const QString& new_name);
};

#endif // SERVICE_MANAGER_H
