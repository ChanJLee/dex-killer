//
// Created by chan on 2017/12/11.
//
#include "dex_killer.h"
#include <iostream>
#include <string>

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
    std::vector<std::string> result_container;
    scan_memory(result_container, "/sdcard/", tid, mem_fd);
    close(mem_fd);

    return 0;
}