//
// Created by chan on 2017/12/11.
//
#include "dex_killer.h"
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

const size_t MAX_RETRY_COUNT = 20;

bool check_args(int argc, char *argv[]) {
    if (argc < 2) {
        return false;
    }

    return true;
}

int main(int argc, char *argv[]) {
    if (!check_args(argc, argv)) {
        std::cout << "invalid arguments" << std::endl;
        return 1;
    }

    std::string pkg = argv[1];
    std::cout << "package name: " << pkg << std::endl;
    pid_t pid = 0;
    size_t retry_count = 0;
    while ((pid = find_pid(pkg)) == 0 && retry_count <= MAX_RETRY_COUNT) {
        std::cout << "try to find pid, times: " << ++retry_count << std::endl;
    }
    std::cout << "pid: " << pid << std::endl;
    if (pid == 0) {
        return 1;
    }

    pid_t tid = find_tid(pid);
    std::cout << "tid: " << tid << std::endl;
    if (tid == 0) {
        return 1;
    }

    int mem_fd = find_mem_file(tid);
    std::cout << "mem fd: " << mem_fd << std::endl;
    if (mem_fd <= 0) {
        return 1;
    }

    const char* target_dir =  "/data/local/tmp/kill_dex";
    mkdir(target_dir, 0777);
    
    std::vector<DexFile> result_container;
    scan_memory(result_container, target_dir, tid, mem_fd);
    std::cout << "write dex to: " << target_dir << std::endl;
    for (int i = 0; i < result_container.size(); ++i) {
        std::cout << "get: " << result_container[i].file_name << std::endl;
    }
    close(mem_fd);

    return 0;
}
