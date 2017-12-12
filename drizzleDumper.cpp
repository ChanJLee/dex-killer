//
// Created by chan on 2017/12/6.
//

#include "drizzleDumper.h"

std::vector<memory_region *> result_container;

int main(int argc, char *argv[]) {
    const char *package_name = "com.yingwoo.yingwoxiaoyuan";
    double wait_times = 3;
    if (getuid() != 0) {
        LOGI("device not root!\n");
        return -1;
    }

    uint32_t pid = -1;
    int mem_file;
    uint32_t clone_pid;
    char *dumped_file_name;

    LOGI("prepare in %f seconds\n", wait_times);
    for (;;) {
        //wait some time
        sleep(wait_times);
        pid = -1;
        pid = get_process_pid(package_name);

        //find process
        if (pid < 1 || pid == -1) {
            LOGI("can not find pid\n");
            continue;
        }
        LOGI("pid is %d\n", pid);

        clone_pid = get_clone_pid(pid);
        if (clone_pid <= 0) {
            LOGI("fork failed\n");
            continue;
        }
        LOGI("clone pid is %d\n", clone_pid);

        mem_file = attach_get_memory(clone_pid);
        if (mem_file == -10201 || mem_file == -20402 || mem_file == -30903) {
            LOGI("can not find mem file\n");
            continue;
        }
        LOGI("mem file is %d\n", mem_file);

        dumped_file_name = (char *) malloc(
                strlen(SAFE_LOCATION) + strlen(package_name) + strlen(SUFFIX));
        sprintf(dumped_file_name, "%s%s%s", SAFE_LOCATION, package_name, SUFFIX);

        LOGI("scan dex ...\n");
        memory_region *memory = new memory_region;
        int result = find_magic_memory(clone_pid, mem_file, memory, dumped_file_name);
        if (result <= 0) {
            LOGI("The magic was not found! code: %d\n", result);
            ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
            close(mem_file);
            delete memory;
            continue;
        } else {
            result_container.push_back(memory);
            close(mem_file);
            ptrace(PTRACE_DETACH, clone_pid, NULL, 0);
            break;
        }
    }

    LOGI("done\n\n");
    return 0;
}

uint32_t get_clone_pid(uint32_t service_pid) {
    DIR *service_pid_dir;
    char service_pid_directory[1024];
    sprintf(service_pid_directory, "/proc/%d/task/", service_pid);

    if ((service_pid_dir = opendir(service_pid_directory)) == NULL) {
        return -1;
    }

    struct dirent *directory_entry = NULL;
    struct dirent *last_entry = NULL;

    while ((directory_entry = readdir(service_pid_dir)) != NULL) {
        last_entry = directory_entry;
    }

    if (last_entry == NULL)
        return -1;

    closedir(service_pid_dir);

    return atoi(last_entry->d_name);
}

uint32_t get_process_pid(const char *target_package_name) {
    char self_pid[10] = {0};
    sprintf(self_pid, "%u", getpid());

    DIR *proc = NULL;

    if ((proc = opendir("/proc")) == NULL)
        return -1;

    struct dirent *directory_entry = NULL;
    while ((directory_entry = readdir(proc)) != NULL) {

        if (directory_entry == NULL)
            return -1;
        if (strcmp(directory_entry->d_name, "self") == 0 ||
            strcmp(directory_entry->d_name, self_pid) == 0)
            continue;

        char cmdline[1024];
        snprintf(cmdline, sizeof(cmdline), "/proc/%s/cmdline", directory_entry->d_name);
        FILE *cmdline_file = NULL;
        if ((cmdline_file = fopen(cmdline, "r")) == NULL)
            continue;

        char process_name[1024];
        fscanf(cmdline_file, "%s", process_name);
        fclose(cmdline_file);

        if (strcmp(process_name, target_package_name) == 0) {
            closedir(proc);
            return atoi(directory_entry->d_name);
        }
    }

    closedir(proc);
    return -1;
}

int release_id = 0;

int
find_magic_memory(uint32_t clone_pid, int memory_fd, memory_region *memory, const char *file_name) {
    char maps[2048];

    snprintf(maps, sizeof(maps), "/proc/%d/maps", clone_pid);
    FILE *maps_file = NULL;
    if ((maps_file = fopen(maps, "r")) == NULL) {
        LOGI(" can not open maps: %s", maps);
        return -1;
    }

    char mem_line[1024];
    while (fscanf(maps_file, "%[^\n]\n", mem_line) >= 0) {
        char mem_address_start[10] = {0};
        char mem_address_end[10] = {0};
        char mem_info[1024] = {0};
        sscanf(mem_line, "%8[^-]-%8[^ ]%*s%*s%*s%*s%s", mem_address_start, mem_address_end,
               mem_info);
        memset(mem_line, 0, 1024);

        //忽略 ttf so
        size_t mem_info_string_len = strlen(mem_info);
        if (mem_info_string_len != 0) {
            size_t dot_start_index = strlen(mem_info) - 1;
            for (; dot_start_index != 0; --dot_start_index) {
                if (mem_info[dot_start_index] == '.') {
                    break;
                }
            }
            char *suffix = mem_info + dot_start_index;
            if (!strcmp(suffix, ".ttf") || !strcmp(suffix, ".so")) {
                //LOGI("ignore: %s\n", mem_info);
                continue;
            }
        }

        memory->start = strtoul(mem_address_start, NULL, 16);
        memory->end = strtoul(mem_address_end, NULL, 16);

        for (int i = 0; i < result_container.size(); ++i) {
            if (result_container[i]->start == memory->start) {
                return -2;
            }
        }

        uint32_t len = memory->end - memory->start;
        lseek64(memory_fd, 0, SEEK_SET);    //保险，先归零
        off_t r1 = lseek64(memory_fd, memory->start, SEEK_SET);
        if (r1 != -1) {
            char *buffer = (char *) malloc(len);
            ssize_t read_len = read(memory_fd, buffer, len);

            for (int i = 0; i < read_len; ++i) {
                if (buffer[i] == 0x64 &&
                    i + 8 < read_len &&
                    buffer[i + 1] == 0x65 &&
                    buffer[i + 2] == 0x78 &&
                    buffer[i + 3] == 0x0A &&
                    buffer[i + 4] == 0x30 &&
                    buffer[i + 5] == 0x33 &&
                    buffer[i + 6] == 0x35 &&
                    buffer[i + 7] == 0x00) {

                    if (i + sizeof(DexHeader) < read_len) {
                        DexHeader header;
                        memcpy(&header, buffer + i, sizeof(DexHeader));
                        if (header.fileSize + i >= read_len) {
                            break;
                        }

                        LOGI("file size: %d, current index: %d\n", header.fileSize, i);
                        char each_filename[254] = {0};
                        char rand_str[10] = {0};
                        sprintf(rand_str, "%d", release_id++);

                        strncpy(each_filename, file_name, 200);    //防溢出
                        strncat(each_filename, rand_str, 10);
                        strncat(each_filename, ".dex", 4);
                        int size = dump_memory(buffer, i, header.fileSize, each_filename);
                        if (size > 0) {
                            i += size;
                            LOGI(" [+] dex dump into %s, next pos: %d, len: %d\n", each_filename, i,
                                 read_len);
                            continue;
                        } else {
                            LOGI(" [+] dex dump error \n");
                        }
                    }

                }
            }

            free(buffer);
        }
    }

    fclose(maps_file);
    return 1;
}

/*
 * Dump buffer from Mem to file.
 */
int dump_memory(const char *buffer, int offset, int len, char each_filename[]) {
    FILE *dump = fopen(each_filename, "wb");
    int result = fwrite(buffer + offset, sizeof(char), len, dump);
    LOGI("write file: %d", result);
    fclose(dump);
    return result != -1 ? len : -1;
}

// Perform all that ptrace magic
int attach_get_memory(uint32_t pid) {
    char mem[1024];
    bzero(mem, 1024);
    snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);

    // Attach to process so we can peek/dump
    int ret = -1;
    ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    int mem_file;

    if (0 != ret) {
        int err = errno;    //这时获取errno
        if (err == 1) {
            return -30903;    //代表已经被跟踪或无法跟踪
        } else {
            return -10201;    //其他错误(进程不存在或非法操作)
        }
    } else {
        if (!(mem_file = open(mem, O_RDONLY))) {
            return -20402;    //打开错误
        }
    }
    return mem_file;
}
