#ifndef THREAD_RELATED
#define THREAD_RELATED

extern pthread_t g_listener_thread;
extern pthread_t g_scanner_thread;

/* used to identify thread */
enum threadType
{
	LISTENER_THREAD,
	SCANNER_THREAD,
};

void create_thread(enum threadType type);

#endif