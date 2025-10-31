#include "thread_pool.hpp"

#include <utility>

namespace server {

ThreadPool::ThreadPool(std::size_t worker_count) {
    pthread_mutex_init(&mutex_, nullptr);
    pthread_cond_init(&cond_, nullptr);
    workers_.resize(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i) {
        pthread_create(&workers_[i], nullptr, &ThreadPool::worker_entry, this);
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
    pthread_cond_destroy(&cond_);
    pthread_mutex_destroy(&mutex_);
}

void ThreadPool::enqueue(std::function<void()> job) {
    pthread_mutex_lock(&mutex_);
    if (stopping_) {
        pthread_mutex_unlock(&mutex_);
        return;
    }
    jobs_.push(std::move(job));
    pthread_cond_signal(&cond_);
    pthread_mutex_unlock(&mutex_);
}

void ThreadPool::shutdown() {
    pthread_mutex_lock(&mutex_);
    if (stopping_) {
        pthread_mutex_unlock(&mutex_);
        return;
    }
    stopping_ = true;
    pthread_cond_broadcast(&cond_);
    pthread_mutex_unlock(&mutex_);

    for (auto &worker : workers_) {
        pthread_join(worker, nullptr);
    }
    workers_.clear();
}

void *ThreadPool::worker_entry(void *arg) {
    auto *self = static_cast<ThreadPool *>(arg);
    self->worker_loop();
    return nullptr;
}

void ThreadPool::worker_loop() {
    while (true) {
        pthread_mutex_lock(&mutex_);
        while (!stopping_ && jobs_.empty()) {
            pthread_cond_wait(&cond_, &mutex_);
        }
        if (stopping_ && jobs_.empty()) {
            pthread_mutex_unlock(&mutex_);
            break;
        }
        auto job = std::move(jobs_.front());
        jobs_.pop();
        pthread_mutex_unlock(&mutex_);

        job();
    }
}

} // namespace server
