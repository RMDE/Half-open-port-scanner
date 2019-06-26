#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../include/half_open_scan_tcp.h"
#include "../include/thread_related.h"

pthread_t g_listener_thread;
pthread_t g_scanner_thread;

/**
 * This is a wrapper to create threads which run the function passed in by the
 * caller.
 * @param thread_type   function to be run by the thread created.
 */
void create_thread(enum threadType type)
{
	int ret_v = -1;

	/* create a thread based on the type requested */
	switch (type)
	{
	case LISTENER_THREAD:
		ret_v = pthread_create(&g_listener_thread, NULL, &listener, NULL);
		if (ret_v == 0) {
			printf("[*] listener thread created successfully\n");
		}
		break;

	case SCANNER_THREAD:
		ret_v = pthread_create(&g_scanner_thread, NULL, &scanner, NULL);
		if (ret_v == 0) {
			printf("[*] hello_broadcaster thread created successfully\n");
		}
		break;

	default:
		printf("[#] Invalid thread type has been requested for creation\n");
		return;
	}

	if (ret_v == -1) {
		printf("pthread_create failed: %d\n", type);
		exit(EXIT_FAILURE);
	}
}