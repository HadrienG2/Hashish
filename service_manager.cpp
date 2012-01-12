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

#include <QDesktopServices>
#include <QLocalSocket>
#include <QTimer>

#include <crypto_hash.h>
#include <error_management.h>
#include <hmac.h>
#include <parsing_tools.h>
#include <password_cipher.h>
#include <password_generator.h>
#include <service_descriptor.h>
#include <service_manager.h>

const QString SERVICE_MANAGER_NAME("ServiceManager");

const size_t DEFAULT_LATENCY = 50; //Default acceptable password generation latency in ms

const QString ERROR_LOG_FILENAME("error_log.txt");

const QString HASHISH_SOCKET_NAME("hashish_command_stream");

const QString ID_FILENAME("file_name : ");
const QString ID_ITERATIONS("default_iterations : ");
const QString ID_LATENCY("acceptable_latency : ");
const QString ID_SERVICE("service : ");

const QString SERVICE_DATABASE_FILENAME("service_database.txt");
const QString SERVICE_DATABASE_HEADER("*** Hashish service database v1 ***");

const QString SERVICE_DIRECTORY_FILENAME("services");

const QString SETTINGS_FILENAME("settings.txt");
const QString SETTINGS_HEADER("*** Hashish settings v1 ***");

ServiceManager::ServiceManager() : ipc_server(NULL),
                                   service_name_list_model(NULL),
                                   to_delete(NULL) {
    start_ipc();
    open_application_data_directory();
    open_error_output();
    read_settings();
    open_service_directory();
    read_service_database();
    test_cryptographic_functions();
}

ServiceManager::~ServiceManager() {
    close_error_output();
    password_buffer.clear();
}

bool ServiceManager::set_current_latency(uint64_t new_latency) {
    ServiceDescriptor tmp_desc;
    uint64_t tmp_iterations = tmp_desc.benchmark_iterations(new_latency);
    if(!tmp_iterations) return false;

    acceptable_latency = new_latency;
    default_iterations = tmp_iterations;
    return generate_settings();
}

void ServiceManager::add_service(const QString& service_name) {
    //Find a cache entry for our new service, set it up with a default descriptor
    ServiceDescriptorCache& cache_entry = find_oldest_cache_entry();
    cache_entry.descriptor.reset(service_name, default_iterations);
    cache_entry.service_filename = "";
    cache_entry.last_used = clock();

    emit service_ready(cache_entry.descriptor);
}

void ServiceManager::delete_qobject(QObject* object) {
    to_delete = object;
    QTimer::singleShot(10, this, SLOT(perform_delete()));
}

void ServiceManager::generate_password(const QString& service_name, const QString& master_password) {
    //Fetch service descriptor associated to the requested service id
    ServiceDescriptor* service_desc = fetch_service(service_name);
    if(!service_desc) {
        emit password_generation_failed();
        return;
    }

    //Compute service password
    QString* result = service_desc->compute_password(master_password, password_buffer);
    if(result) {
        emit password_ready(password_buffer);
    } else {
        emit password_generation_failed();
    }
}

void ServiceManager::load_service(const QString& service_name) {
    ServiceDescriptor* result = fetch_service(service_name);
    if(result) {
        emit service_ready(*result);
    } else {
        emit service_loading_failed();
    }
}

void ServiceManager::remove_service(const QString& service_name) {
    //Delete the service's entry in service_name_list and service_filenames. Delete its file.
    service_name_list.removeOne(service_name);
    service_name_list_model->setStringList(service_name_list);
    QString service_filename = service_filenames[service_name];
    service_filenames.remove(service_name);
    service_dir->remove(service_filename);

    //Mark the cache entry assocated to the service, if any, for deletion.
    ServiceDescriptorCache* cache_entry = find_in_cache(service_filename);
    if(cache_entry) cache_entry->last_used = 0;

    //Regenerate service database
    generate_service_database();

    emit service_removed();
}

void ServiceManager::save_service(const QString& former_name, const QString& new_name, ServiceDescriptor& service) {
    //Make management structures follow the new service name
    bool tmp_result = update_service_name(former_name, new_name);
    if(!tmp_result) {
        emit service_saving_failed();
        return;
    }

    //Save the service to its dedicated file
    QString filepath = service_dir->filePath(service_filenames[new_name]);
    tmp_result = service.save_to_file(filepath);
    if(!tmp_result) {
        emit service_saving_failed();
        return;
    }

    //Regenerate service database
    tmp_result = generate_service_database();
    if(!tmp_result) {
        emit service_saving_failed();
        return;
    }

    emit service_saved();
}

void ServiceManager::perform_delete() {
    delete to_delete;
    to_delete = NULL;
}

void ServiceManager::case_insensitive_sort(QStringList& list) {
    //Since Qt does not offer a serious way to sort a QStringList case insensitively, here is some
    //ugly heap sort implementation that will do it

    //First, we want to place the list in max-heap order.
    //To do this, we explore each of its heap nodes, starting at the last parent node
    for(int current_node = (list.count()/2)-1; current_node>=0; --current_node) {
        //Sift down the current node so that all nodes below it are in heap order
        sift_down(list, current_node, list.count() - 1);
    }

    QString swap_buffer;
    for(int end = list.count()-1; end > 0; --end) {
        //The root of a heap is its maximal value, put it at the end
        swap_buffer = list.at(end);
        list[end] = list[0];
        list[0] = swap_buffer;

        //Put the heap back in max-heap order, keeping previous max value in proper placement
        sift_down(list, 0, end-1);
    }
}

void ServiceManager::close_error_output() {
    stop_error_logging();
    error_log_stream->flush();
    error_log_file->close();
}

ServiceDescriptor* ServiceManager::fetch_service(const QString& service_name) {
    //First, we can only fetch descriptors that are associated to a filename.
    bool success = service_filenames.contains(service_name);
    if(!success) {
        static const QString ERR_UNKNOWN_SERVICE("Unknown service name : %1");
        log_error(SERVICE_MANAGER_NAME, ERR_UNKNOWN_SERVICE.arg(service_name));
        return NULL;
    }

    //First try to find the requested service in the service cache
    ServiceDescriptorCache* potential_result = find_in_cache(service_filenames[service_name]);
    if(potential_result) return &(potential_result->descriptor);

    //Look for the oldest cache entry (free entries have last_used = 0)
    ServiceDescriptorCache& oldest_cache_entry = find_oldest_cache_entry();
    ServiceDescriptor& oldest_descriptor = oldest_cache_entry.descriptor;

    //Fetch our descriptor's full file path and load it in the oldest cache entry.
    QString filepath = service_dir->filePath(service_filenames[service_name]);
    success = oldest_descriptor.load_from_file(filepath);
    if(!success) return NULL;

    //Update our cache entry's last usage date, return the descriptor
    oldest_cache_entry.last_used = clock();
    return &oldest_descriptor;
}

ServiceDescriptorCache* ServiceManager::find_in_cache(const QString& service_filename) {
    //Try to find the requested service in the service cache
    for(int i = 0; i < CACHE_SIZE; ++i) {
        if(cached_services[i].service_filename == service_filename) {
            cached_services[i].last_used = clock();
            return &(cached_services[i]);
        }
    }

    return NULL;
}

QString* ServiceManager::find_new_service_filename() {
    static QString potential_filename;
    uint64_t i;
    for(i = 1; i!=0; ++i) {
        potential_filename.setNum(i);
        potential_filename.append(".txt");
        if(service_dir->exists(potential_filename) == false) break;
    }
    if(i == 0) {
        static const QString ERR_NO_AVL_FILENAME("No suitable filename could be found for the new service.");
        log_error(SERVICE_MANAGER_NAME, ERR_NO_AVL_FILENAME);
        return NULL;
    }

    return &potential_filename;
}

ServiceDescriptorCache& ServiceManager::find_oldest_cache_entry() {
    //Find the oldest cache entry
    int oldest = 0;
    for(int i = 1; i < CACHE_SIZE; ++i) {
        if(cached_services[i].last_used < cached_services[oldest].last_used) {
            oldest = i;
            if(cached_services[i].last_used == 0) break;
        }
    }

    return cached_services[oldest];
}

bool ServiceManager::generate_service_database(bool from_scratch) {
    //Open database file in writing mode and write its header
    bool success = service_db_file->open(QIODevice::WriteOnly | QIODevice::Truncate);
    if(!success) {
        log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(service_db_file->fileName()));
        return false;
    }
    QTextStream service_db_ostream(service_db_file);
    service_db_ostream << SERVICE_DATABASE_HEADER << endl << endl;

    if(!from_scratch) {
        //Save service database from the in-memory copy
        for(int i = 0; i < service_name_list.count(); ++i) {
            const QString& current_service_name = service_name_list[i];
            service_db_ostream << ID_SERVICE << current_service_name << endl;
            service_db_ostream << ID_FILENAME << service_filenames[current_service_name] << endl << endl;
        }
    } else {
        //If we have no existing database to rely on, parse files in service_dir
        QStringList service_dir_contents = service_dir->entryList();
        QString current_filename;
        ServiceDescriptor tmp_desc;
        for(int i = 0; i < service_dir_contents.count(); ++i) {
            if(service_dir_contents[i].at(0) == '.') continue;
            current_filename = service_dir->filePath(service_dir_contents[i]);
            success = tmp_desc.load_from_file(current_filename);
            if(success) {
                service_db_ostream << ID_SERVICE << tmp_desc.service_name << endl;
                service_db_ostream << ID_FILENAME << service_dir_contents[i] << endl << endl;
            }
        }
    }

    service_db_file->close();
    return true;
}

bool ServiceManager::generate_settings(bool from_scratch) {
    //Open settings file in writing mode and write its header
    bool success = settings_file->open(QIODevice::WriteOnly | QIODevice::Truncate);
    if(!success) {
        log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(settings_file->fileName()));
        return false;
    }
    QTextStream settings_ostream(settings_file);
    settings_ostream << SETTINGS_HEADER << endl << endl;

    if(!from_scratch) {
        //Save settings from the in-memory copy
        settings_ostream << ID_LATENCY << acceptable_latency << endl;
        settings_ostream << ID_ITERATIONS << default_iterations << endl;
    } else {
        //Write default settings
        settings_ostream << ID_LATENCY << DEFAULT_LATENCY << endl;
        ServiceDescriptor tmp_desc;
        settings_ostream << ID_ITERATIONS << tmp_desc.benchmark_iterations(DEFAULT_LATENCY) << endl;
    }

    settings_file->close();
    return true;
}

QDir* ServiceManager::open_application_data_directory() {
    //Get standard application data directory from QDesktopServices
    QDesktopServices desktop_services;
    QString app_data_location = desktop_services.storageLocation(desktop_services.DataLocation);
    app_data_dir = new QDir(app_data_location);
    if(!app_data_dir) {
        log_error(SERVICE_MANAGER_NAME, ERR_BAD_ALLOC.arg(QString("app_data_dir")));
        return NULL;
    }

    //If the directory does not exist, attempt to create it
    if(app_data_dir->exists() == false) {
        bool success = app_data_dir->mkpath(app_data_location);
        if(!success) {
            log_error(SERVICE_MANAGER_NAME, ERR_FOLDER_CREATION_FAILURE.arg(app_data_location));
            return NULL;
        }
    }

    return app_data_dir;
}

bool ServiceManager::open_error_output() {
    //Access error log file
    error_log_file = new QFile(app_data_dir->filePath(ERROR_LOG_FILENAME));
    if(!error_log_file) return false;

    //Open the file in write-append mode and start error logging
    bool success = error_log_file->open(QIODevice::WriteOnly | QIODevice::Append);
    if(!success) return false;
    error_log_stream = new QTextStream(error_log_file);
    if(!error_log_stream) return false;
    start_error_logging(*error_log_stream);

    return true;
}

QDir* ServiceManager::open_service_directory() {
    //Get standard application data directory from QDesktopServices
    service_dir = new QDir(app_data_dir->filePath(SERVICE_DIRECTORY_FILENAME));
    if(!service_dir) {
        log_error(SERVICE_MANAGER_NAME, ERR_BAD_ALLOC.arg(QString("service_dir")));
        return NULL;
    }

    //If the directory does not exist, attempt to create it
    if(service_dir->exists() == false) {
        bool success = app_data_dir->mkdir(SERVICE_DIRECTORY_FILENAME);
        if(!success) {
            log_error(SERVICE_MANAGER_NAME, ERR_FOLDER_CREATION_FAILURE.arg(SERVICE_DIRECTORY_FILENAME));
            return NULL;
        }
    }

    return service_dir;
}

bool ServiceManager::parse_service_db(QTextStream& service_db_istream) {
    service_name_list.clear();
    service_filenames.clear();
    QString line, service_name, service_filename;
    while(service_db_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments and spacing
        line = service_db_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //When encountering a service declaration, set up a service name and clear other parameters.
        if(has_id(line, ID_SERVICE)) {
            remove_id(line, ID_SERVICE);
            service_name = line;
            service_filename.clear();
            continue;
        }

        //At the moment, a service is only described by its name and filename, so once we have
        //both a service name and a valid file name, we may create an entry.
        if(has_id(line, ID_FILENAME) && (service_name.isEmpty() == false)) {
            remove_id(line, ID_FILENAME);
            service_filename = line;
            if(service_dir->exists(service_filename) == false) continue;
            service_name_list.append(service_name);
            service_filenames[service_name] = service_filename;
            service_name.clear();
            continue;
        }
    }
    case_insensitive_sort(service_name_list);
    if(service_name_list_model) delete service_name_list_model;
    service_name_list_model = new QStringListModel(service_name_list);
    if(!service_name_list_model) {
        log_error(SERVICE_MANAGER_NAME, ERR_BAD_ALLOC.arg(QString("service_name_list_model")));
        return false;
    }

    return true;
}

bool ServiceManager::parse_settings(QTextStream& settings_istream) {
    acceptable_latency = DEFAULT_LATENCY;
    default_iterations = 0;
    QString line;
    while(settings_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments
        line = settings_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //Set acceptable latency
        if(has_id(line, ID_LATENCY)) {
            remove_id(line, ID_LATENCY);
            acceptable_latency = line.toULongLong();
            continue;
        }

        //Set default number of iterations
        if(has_id(line, ID_ITERATIONS)) {
            remove_id(line, ID_ITERATIONS);
            default_iterations = line.toULongLong();
            continue;
        }
    }

    return true;
}

QFile* ServiceManager::read_service_database() {
    bool success;
    //Access standard service database
    service_db_file = new QFile(app_data_dir->filePath(SERVICE_DATABASE_FILENAME));
    if(!service_db_file) {
        log_error(SERVICE_MANAGER_NAME, ERR_BAD_ALLOC.arg(QString("service_db_file")));
        return NULL;
    }

    //If it does not exist, generate it from scratch
    if(service_db_file->exists() == false) {
        success = generate_service_database(true);
        if(!success) return NULL;
    }

    //Open the database, read its header to see if it is correct. If not, regenerate it.
    success = service_db_file->open(QIODevice::ReadOnly);
    if(!success) {
        log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(service_db_file->fileName()));
        return NULL;
    }
    QTextStream service_db_istream(service_db_file);
    QString header = service_db_istream.readLine();
    if(header != SERVICE_DATABASE_HEADER) {
        //The file is corrupted. Regenerate it from scratch and re-open it.
        service_db_istream.flush();
        service_db_file->close();
        success = generate_service_database(true);
        if(!success) return NULL;

        success = service_db_file->open(QIODevice::ReadOnly);
        if(!success) {
            log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(service_db_file->fileName()));
            return NULL;
        }
        service_db_istream.setDevice(service_db_file);
        header = service_db_istream.readLine();
    }

    //Extract service name list and a service names->filenames dictionnary
    parse_service_db(service_db_istream);
    service_db_file->close();

    return service_db_file;
}

QFile* ServiceManager::read_settings() {
    bool success;
    //Access settings file
    settings_file = new QFile(app_data_dir->filePath(SETTINGS_FILENAME));
    if(!settings_file) {
        log_error(SERVICE_MANAGER_NAME, ERR_BAD_ALLOC.arg(QString("settings_file")));
        return NULL;
    }

    //If it does not exist, generate it from scratch
    if(settings_file->exists() == false) {
        success = generate_settings(true);
        if(!success) return NULL;
    }

    //Open the database, read its header to see if it is correct. If not, regenerate file.
    success = settings_file->open(QIODevice::ReadOnly);
    if(!success) {
        log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(settings_file->fileName()));
        return NULL;
    }
    QTextStream settings_istream(settings_file);
    QString header = settings_istream.readLine();
    if(header != SETTINGS_HEADER) {
        //The file is corrupted. Regenerate it from scratch and re-open it.
        settings_istream.flush();
        settings_file->close();
        success = generate_settings(true);
        if(!success) return NULL;

        success = settings_file->open(QIODevice::ReadOnly);
        if(!success) {
            log_error(SERVICE_MANAGER_NAME, ERR_FILE_OPEN_FAILURE.arg(settings_file->fileName()));
            return NULL;
        }
        settings_istream.setDevice(settings_file);
        header = settings_istream.readLine();
    }

    //Extract settings
    parse_settings(settings_istream);
    settings_file->close();

    return settings_file;
}

void ServiceManager::sift_down(QStringList& list, const int start, const int end) {
    int root_node = start;
    QString swap_buffer;

    while(root_node*2+1 <= end) { //While current root node has at least one child, check if
                                  //there is a larger child node to swap the root with
        int left_child_node = root_node*2+1;
        int right_child_node = left_child_node+1;
        int swap_with = root_node;

        //Start by comparing root value with left child value
        const QString& root_value = list.at(root_node);
        const QString& left_child_value = list.at(left_child_node);
        if(root_value.compare(left_child_value, Qt::CaseInsensitive) < 0) {
            swap_with = left_child_node;
        }

        //Next, compare swap_with node with right child, if it exists : we want to
        //swap the root with its largest child
        if(right_child_node <= end) {
            const QString& swap_value = list.at(swap_with);
            const QString& right_child_value = list.at(right_child_node);
            if(swap_value.compare(right_child_value, Qt::CaseInsensitive) < 0) {
                swap_with = right_child_node;
            }
        }

        //Should we swap root_node with another node ?
        if(swap_with != root_node) {
            //If yes, perform the swap and iterate the algorithm on the child node
            swap_buffer = list.at(root_node);
            list[root_node] = list[swap_with];
            list[swap_with] = swap_buffer;

            root_node = swap_with;
        } else {
            //If not, the heap is sorted below the current root node
            return;
        }
    }
}

bool ServiceManager::start_ipc() {
    //Attempt to connect to an already running "server" instance of Hashish.
    QLocalSocket client_socket(this);
    client_socket.connectToServer(HASHISH_SOCKET_NAME);
    bool success = client_socket.waitForConnected(5);

    if(success) {
        running_instance_found = true;

        //If a running instance is found, the connection will act as a new instance notification.
        //We do not need to keep it running for current versions of Hashish's IPC protocol.
        client_socket.abort();
        return success;
    } else {
        running_instance_found = false;

        //If the connection error is not due to a missing server, abort.
        if(client_socket.error() != QLocalSocket::ServerNotFoundError) return false;

        //Otherwise, become the server instance of Hashish
        ipc_server = new QLocalServer(this);
        ipc_server->listen(HASHISH_SOCKET_NAME);
        connect(ipc_server, SIGNAL(newConnection()), this, SIGNAL(new_instance_spawned()));
        return true;
    }
}

void ServiceManager::test_cryptographic_functions() {
    tests_passed = false;
    if(test_crypto_hashes() == false) return;
    if(test_hmacs() == false) return;
    if(test_password_ciphers() == false) return;
    if(test_password_generators() == false) return;
    tests_passed = true;
}

bool ServiceManager::update_service_name(const QString& former_name, const QString& new_name) {
    //Update internal records
    int service_index = service_name_list.indexOf(former_name);
    if(service_index == -1) {
        //The service has just been created
        service_name_list.append(new_name);

        QString* tmp_filename = find_new_service_filename();
        if(!tmp_filename) {
            service_name_list.removeLast();
            return false;
        }
        service_filenames[new_name] = *tmp_filename;
    } else {
        //The service already exists. If its name has not changed, there's nothing to do, otherwise update.
        if(new_name == former_name) return true;
        service_name_list[service_index] = new_name;

        service_filenames[new_name] = service_filenames[former_name];
        service_filenames.remove(former_name);
    }

    //Update service_name_list_model
    case_insensitive_sort(service_name_list);
    service_name_list_model->setStringList(service_name_list);

    return true;
}
