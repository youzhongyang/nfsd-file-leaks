/*
 * gcc -o readfile readfile.c -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

struct thread_data {
    char *path;
    int chunk_size;
    int loops;
    int index;
};

void *func_to_run(void *arg)
{
        struct thread_data *pd = (struct thread_data *)arg;
        int fd;
        void *buf = NULL;
        int cnt;
        ssize_t n;

        buf = malloc(pd->chunk_size);
        if (!buf) {
            printf("thread %u: out of memory.\n", (unsigned int)pthread_self());
            return NULL;
        }

        fd = open(pd->path, O_RDONLY | O_DIRECT, S_IREAD);
        if (fd < 0) {
           printf("thread %u: unable to open %s [%s].\n", (unsigned int)pthread_self(), pd->path, strerror(errno));
           return NULL;
        }

        for(cnt = 0; cnt < pd->loops; cnt++) {
            if(lseek(fd, pd->index * pd->chunk_size, SEEK_SET) < 0) {
                printf("thread %u: failed to lseek [%s].\n", (unsigned int)pthread_self(), strerror(errno));
                break;
            }
            n = read(fd, buf, pd->chunk_size);
            if (n < 0) {
                printf("thread %u: failed to read [%s]\n", (unsigned int)pthread_self(), strerror(errno));
                break;
            }
        }

        free(buf);
        close(fd);

        return NULL;
}

#define DEFAULT_THREADS 10
#define DEFAULT_LOOPS 100000
#define DEFAULT_CHUNKSIZE 1024*1024

void usage(char **argv)
{
        printf("Usage:\n");
        printf("  %s [-n <threads>] [-l <loops>] [-c <chunk_size>] <path to file>\n", argv[0]);
        printf("  -n <threads>: Number of threads to read the same file, default %d\n", DEFAULT_THREADS);
        printf("  -l <loops>: Number of loops to repeat the read op, default %d\n", DEFAULT_LOOPS);
        printf("  -c <chunk_size>: chunk size of the read op, default %d\n", DEFAULT_CHUNKSIZE);
}

int main(int argc, char **argv)
{
        if (argc < 2) {
                usage(argv);
                exit(1);
        }

        pthread_t *tids = NULL;
        struct thread_data *tdata = NULL;
        int nthreads = DEFAULT_THREADS;
        int i;
        int c;
        int ret = 0;
        char *path = NULL;
        int chunk_size = DEFAULT_CHUNKSIZE;
        int loops = DEFAULT_LOOPS;

        while ((c = getopt(argc, argv, "n:l:c:")) != -1) {
                switch(c) {
                case 'n':
                        nthreads = atoi(optarg);
                        break;
                case 'l':
                        loops = atoi(optarg);
                        break;
                case 'c':
                        chunk_size = atoi(optarg);
                        break;
                case ':':
                        printf("-%c without arg\n", optopt);
                        exit(1);
                        break;
                default:
                        exit(2);
                }
        }

        if (optind >= argc) {
                fprintf(stderr, "ERROR: missing path.\n");
                exit(1);
        }
        path = argv[optind];

        printf("threads = %d\n", nthreads);
        printf("loops = %d\n", loops);
        printf("chunk_size = %d\n", chunk_size);
        printf("path = %s\n", path);

        tids = calloc(nthreads, sizeof(pthread_t));
        tdata = calloc(nthreads, sizeof(struct thread_data));

        for(i = 0; i < nthreads; i++) {
                tdata[i].path = path;
                tdata[i].chunk_size = chunk_size;
                tdata[i].loops = loops;
                tdata[i].index = i;
                if(pthread_create(&tids[i], NULL, func_to_run, &tdata[i]) != 0) {
                        fprintf(stderr, "ERROR: failed to create thread\n");
                        ret = 3;
                        goto done;
                }
        }

        for(i = 0; i < nthreads; i++) {
                (void) pthread_join(tids[i], NULL);
        }

done:
        if(tids) free(tids);
        if(tdata) free(tdata);

        printf("DONE.\n");
        return(ret);
}
