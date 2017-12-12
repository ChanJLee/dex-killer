//
// Created by chan on 2017/12/11.
//
#include "dex_killer.h"
#include <stdlib.h>
#include <sstream>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

pid_t find_pid(const std::string &pkg) {
    if (pkg.empty()) {
        return 0;
    }

    DIR *proc_dir = NULL;
    if ((proc_dir = opendir("/proc")) == NULL) {
        return 0;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (strcmp(entry->d_name, "self") == 0) {
            continue;
        }

        std::ostringstream cmd_file_name_os;
        cmd_file_name_os << "/proc/" << entry->d_name << "/cmdline";
        std::string cmd_file_name = cmd_file_name_os.str();
        FILE *cmd_file = fopen(cmd_file_name.c_str(), "r");
        if (cmd_file == NULL) {
            continue;
        }

        char cmd_file_content[1024] = {0};
        fscanf(cmd_file, "%s", cmd_file_content);
        fclose(cmd_file);
        if (strcmp(cmd_file_content, pkg.c_str()) == 0) {
            return atoi(entry->d_name);
        }
    }

    closedir(proc_dir);
    return 0;
}

pid_t find_tid(const pid_t pid) {
    if (pid == 0) {
        return 0;
    }

    std::ostringstream process_task_dir_name_os;
    process_task_dir_name_os << "/proc/" << pid << "/task";
    std::string process_task_dir_name = process_task_dir_name_os.str();
    DIR *process_task_dir = opendir(process_task_dir_name.c_str());
    if (process_task_dir == NULL) {
        LOGI("open %s failed", process_task_dir_name.c_str());
        return 0;
    }

    struct dirent *entry = NULL;
    pid_t tid = 0;
    while ((entry = readdir(process_task_dir)) != NULL) {
        tid = atoi(entry->d_name);
    }
    closedir(process_task_dir);

    return tid;
}

int find_mem_file(const pid_t tid) {
    std::ostringstream tid_mem_file_name_os;
    tid_mem_file_name_os << "/proc/" << tid << "/mem";
    std::string tid_mem_file_name = tid_mem_file_name_os.str();

    int attach_result = ptrace(PTRACE_ATTACH, tid, NULL, NULL);
    if (attach_result != 0) {
        return -1;
    }

    return open(tid_mem_file_name.c_str(), O_RDONLY);
}

bool is_usable_mem_info(const char *mem_info) {
    if (mem_info == NULL) {
        return false;
    }

    size_t mem_info_string_len = strlen(mem_info);
    if (mem_info_string_len == 0) {
        //没有名称的内存区域，我们也认为是有用的
        return true;
    }

    size_t dot_start_index = strlen(mem_info) - 1;
    for (; dot_start_index != 0; --dot_start_index) {
        if (mem_info[dot_start_index] == '.') {
            break;
        }
    }

    //ttf so apk 的话直接忽略
    const char *suffix = mem_info + dot_start_index;
    if (!strcmp(suffix, ".ttf") || !strcmp(suffix, ".so") || !strcmp(suffix, ".apk")) {
        return false;
    }

    return true;
}

inline bool is_dex_magic_number(const u1 *buffer, ssize_t offset, ssize_t len) {
    return buffer[offset] == 0x64 &&
           offset + 8 < len &&
           buffer[offset + 1] == 0x65 &&
           buffer[offset + 2] == 0x78 &&
           buffer[offset + 3] == 0x0A &&
           buffer[offset + 4] == 0x30 &&
           buffer[offset + 5] == 0x33 &&
           buffer[offset + 6] == 0x35 &&
           buffer[offset + 7] == 0x00;
}

void scan_memory(std::vector<std::string> &result_container, const std::string& save_to_dir, int tid, int mem_fd) {
    std::ostringstream maps_file_name_os;
    maps_file_name_os << "/proc/" << tid << "/maps";
    std::string maps_file_name = maps_file_name_os.str();

    FILE *maps_file = fopen(maps_file_name.c_str(), "r");
    if (maps_file == NULL) {
        LOGI("open %s failed", maps_file_name.c_str());
        return;
    }

    char mem_file_line[1024];
    while (fscanf(maps_file, "%[^\n]\n", mem_file_line) >= 0) {
        char mem_address_start_s[10] = {0};
        char mem_address_end_s[10] = {0};
        char mem_info[1024] = {0};
        sscanf(mem_file_line, "%8[^-]-%8[^ ]%*s%*s%*s%*s%s",
               mem_address_start_s,
               mem_address_end_s, mem_info);

        if (!is_usable_mem_info(mem_info)) {
            return;
        }

        uint64_t mem_address_start = strtoul(mem_address_start_s, NULL, 16);
        uint64_t mem_address_end = strtoul(mem_address_end_s, NULL, 16);
        uint64_t segment_len = mem_address_end - mem_address_start;
        if (segment_len <= sizeof(DexHeader)) {
            continue;
        }

        off_t seek_result = lseek64(mem_fd, mem_address_start, SEEK_SET);
        if (seek_result == -1) {
            LOGI("seek failed, start %llu end %llu info %s", mem_address_start, mem_address_end,
                 mem_info);
            continue;
        }

        u1 *buffer = (u1 *) malloc(segment_len);
        if (buffer == NULL) {
            LOGI("malloc failed");
            continue;
        }

        ssize_t read_len = read(mem_fd, buffer, segment_len);
        if (read_len <= 0) {
            free(buffer);
            LOGI("read failed");
            continue;
        }

        for (ssize_t i = 0; i < read_len; ++i) {
            if (is_dex_magic_number(buffer, i, read_len) &&
                i + sizeof(DexHeader) < read_len) {

                DexHeader dex_header;
                memcpy(&dex_header, buffer + i, sizeof(DexHeader));

                if (dex_header.fileSize + i >= read_len) {
                    LOGI("invalid dex header");
                    break;
                }

                std::ostringstream save_to_os;
                save_to_os << save_to_dir << "/mem_start_" << (mem_address_start + i) << ".dex";
                std::string save_to = save_to_os.str();
                int write_len = copy_memory(buffer, i, read_len, save_to);
                if (write_len >= 0) {
                    result_container.push_back(save_to);
                    i += write_len;
                }
            }
        }
        free(buffer);
    }
}

int copy_memory(const u1 *buffer, ssize_t offset, ssize_t len, const std::string &save_to) {
    FILE *save_to_file = fopen(save_to.c_str(), "wb");
    int result = fwrite(buffer + offset, sizeof(char), len, save_to_file);
    fclose(save_to_file);
    return result != -1 ? len : -1;
}