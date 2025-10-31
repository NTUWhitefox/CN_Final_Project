#pragma once

#include <functional>
#include <queue>
#include <vector>
#include <pthread.h>

namespace server {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t worker_count);
    ~ThreadPool();

    void enqueue(std::function<void()> job);
    void shutdown();

private:
    static void *worker_entry(void *arg);
    void worker_loop();

    std::vector<pthread_t> workers_;
    std::queue<std::function<void()>> jobs_;
    pthread_mutex_t mutex_{};
    pthread_cond_t cond_{};
    bool stopping_{false};
};

} // namespace server
