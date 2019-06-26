#ifndef THREAD_RELATED_H
#define THREAD_RELATED_H

extern pthread_t g_scanner_thread;
extern pthread_t g_listener_thread;

/* used to identify thread */
enum threadType
{
	LISTENER_THREAD,
	SCANNER_THREAD,
};

void create_thread(enum threadType type);

#endif