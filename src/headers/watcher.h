#ifndef WATCHER_H
#define WATCHER_H

typedef void (*watcher_cb)(const char *path, const char *filename, int deleted);

int  watcher_init(const char *path, watcher_cb cb);
void watcher_loop(void);  
void watcher_stop(void);

#endif


