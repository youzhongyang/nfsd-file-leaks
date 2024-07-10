# nfsd-file-leaks
Reproducing nfsd file leaks.

# Summary
  The C program readfile.c is created to start a number of threads, each one reads a chunk of file content at a different offset repeatedly (until the # of loops finishes).

# Prerequsites
* Two hosts (virtual or physical), one as nfs server, another nfs client.
* Add "slub_debug=U,nfsd_file" to the kernel cmdline of the server machine so it's easy to examine the 'nfsd_file' kmem_cache using utility like 'crash'.
* Enhanced version of crash utility for easy traversal of kmem_cache objects if you use it.
```
--- crash-8.0.4.orig/memory.c
+++ crash-8.0.4/memory.c
@@ -19745,7 +19745,7 @@ do_node_lists_slub(struct meminfo *si, u
                        return;
                }

-               if (!do_slab_slub(si, !VERBOSE))
+               if (!do_slab_slub(si, VERBOSE))
                        return;

                if (received_SIGINT())
@@ -19793,7 +19793,7 @@ do_node_lists_slub(struct meminfo *si, u
                                si->curname, si->slab);
                        return;
                }
-               if (!do_slab_slub(si, !VERBOSE))
+               if (!do_slab_slub(si, VERBOSE))
                        return;

                if (received_SIGINT())
```
# How to reproduce
* On the server, get nfs share and file ready.
```
mkfs.xfs /dev/sde
mount /dev/sde /mnt
cd /mnt
mkdir bse
cd bse
dd if=/dev/urandom of=file bs=$((1024*1024)) count=1024
exportfs *:/mnt
```
* On the server machine, run "exportfs -f" to try purging nfsd filecache repeatedly.
```
while true; do exportfs -f; sleep 1; done
```
* On the client machine, build the program.
```
gcc -o readfile readfile.c -lpthread
```
* On the client machine, mount nfs share and run the program.
```
# ./readfile
Usage:
  ./readfile [-n <threads>] [-l <loops>] [-c <chunk_size>] <path to file>
  -n <threads>: Number of threads to read the same file, default 10
  -l <loops>: Number of loops to repeat the read op, default 100000
  -c <chunk_size>: chunk size of the read op, default 1048576
```
```
# mount -t nfs -o vers=3,sec=sys,nconnect=16 <nfs server>:/mnt /mnt
# ./readfile -l 10000000 -n 100 -c 4096 /mnt/bse/file
```
After some time (10 minutes or more), kill the program.
* Examine /proc/slabinfo on the server machine, if the "active_objs" of nfsd_file does not drop to 0, most likely it reproduces!
```
grep nfsd_file /proc/slabinfo
```
* Run crash utility to examine the 'nfsd_file' kmem_cache:
```
crash> kmem -S nfsd_file | grep '\[ffff'
  [ffff888176381200]
crash> struct nfsd_file ffff888176381200
struct nfsd_file {
  nf_rlist = {
    rhead = {
      next = 0xffff8881237891b9
    },
    next = 0x0
  },
  nf_inode = 0xffff88817866b138,
  nf_file = 0xffff8881075b6800,
  nf_cred = 0xffff8881c5357980,
  nf_net = 0xffffffff83d41600 <init_net>,
  nf_flags = 12,
  nf_ref = {
    refs = {
      counter = 1
    }
  },
  nf_may = 4 '\004',
  nf_mark = 0xffff88812c3dd6e0,
  nf_lru = {
    next = 0xffff888176381248,
    prev = 0xffff888176381248
  },
  nf_gc = {
    next = 0xffff888176381258,
    prev = 0xffff888176381258
  },
  nf_rcu = {
    next = 0xffff88811041f3a8,
    func = 0x0
  },
  nf_birthtime = 666161145360
}

crash> struct file.f_path.mnt,f_count.counter 0xffff8881075b6800
  f_path.mnt = 0xffff8881062556a0,
  f_count.counter = 1

crash> struct mount.mnt_devname 0xffff888106255680
  mnt_devname = 0xffff888111479c30 "/dev/sde",

crash> struct vfsmount.mnt_sb 0xffff8881062556a0
  mnt_sb = 0xffff88810a09c000,

crash> struct super_block.s_type 0xffff88810a09c000
  s_type = 0xffffffffc162ff80 <xfs_fs_type>,
```
* Repeat a few times until it reproduces. You may need to tweak the arguments to the 'readfile' program.

* I tried to use only one VM for reproduction but no success. The two VMs used for successful reproduction have the following spec:
  - 16 vCPUs
  - 48GiB memory

# Patches
The following patch has been tested in-house and no leak has been found and identified after a few days of heavy nfs load.
```
# cat 0001-nfsd-fix-nfsd_file-leaking-due-to-mixed-use-of-nf-nf.patch
From d6b5ebffc77ad1f0a9473f36ee53fb68382659bf Mon Sep 17 00:00:00 2001
From: Youzhong Yang <********@gmail.com>
Date: Thu, 4 Jul 2024 11:25:40 -0400
Subject: [PATCH] nfsd: fix nfsd_file leaking due to mixed use of nf->nf_lru

nfsd_file_put() in one thread can race with another thread doing
garbage collection (running nfsd_file_gc() -> list_lru_walk() ->
nfsd_file_lru_cb()):

  * In nfsd_file_put(), nf->nf_ref is 1, so it tries to do nfsd_file_lru_add().
  * nfsd_file_lru_add() returns true (with NFSD_FILE_REFERENCED bit set)
  * garbage collector kicks in, nfsd_file_lru_cb() clears REFERENCED bit and
    returns LRU_ROTATE.
  * garbage collector kicks in again, nfsd_file_lru_cb() now decrements nf->nf_ref
    to 0, runs nfsd_file_unhash(), removes it from the LRU and adds to the dispose
    list [list_lru_isolate_move(lru, &nf->nf_lru, head)]
  * nfsd_file_put() detects NFSD_FILE_HASHED bit is cleared, so it tries to remove
    the 'nf' from the LRU [if (!nfsd_file_lru_remove(nf))]. The 'nf' has been added
    to the 'dispose' list by nfsd_file_lru_cb(), so nfsd_file_lru_remove(nf) simply
    treats it as part of the LRU and removes it, which leads to its removal from
    the 'dispose' list.
  * At this moment, 'nf' is unhashed with its nf_ref being 0, and not on the LRU.
    nfsd_file_put() continues its execution [if (refcount_dec_and_test(&nf->nf_ref))],
    as nf->nf_ref is already 0, nf->nf_ref is set to REFCOUNT_SATURATED, and the 'nf'
    gets no chance of being freed.

nfsd_file_put() can also race with nfsd_file_cond_queue():
  * In nfsd_file_put(), nf->nf_ref is 1, so it tries to do nfsd_file_lru_add().
  * nfsd_file_lru_add() sets REFERENCED bit and returns true.
  * Some userland application runs 'exportfs -f' or something like that, which triggers
    __nfsd_file_cache_purge() -> nfsd_file_cond_queue().
  * In nfsd_file_cond_queue(), it runs [if (!nfsd_file_unhash(nf))], unhash is done
    successfully.
  * nfsd_file_cond_queue() runs [if (!nfsd_file_get(nf))], now nf->nf_ref goes to 2.
  * nfsd_file_cond_queue() runs [if (nfsd_file_lru_remove(nf))], it succeeds.
  * nfsd_file_cond_queue() runs [if (refcount_sub_and_test(decrement, &nf->nf_ref))]
    (with "decrement" being 2), so the nf->nf_ref goes to 0, the 'nf' is added to the
    dispose list [list_add(&nf->nf_lru, dispose)]
  * nfsd_file_put() detects NFSD_FILE_HASHED bit is cleared, so it tries to remove
    the 'nf' from the LRU [if (!nfsd_file_lru_remove(nf))], although the 'nf' is not
    in the LRU, but it is linked in the 'dispose' list, nfsd_file_lru_remove() simply
    treats it as part of the LRU and removes it. This leads to its removal from
    the 'dispose' list!
  * Now nf->ref is 0, unhashed. nfsd_file_put() continues its execution and set
    nf->nf_ref to REFCOUNT_SATURATED.

As shown in the above analysis, using nf_lru for both the LRU list and dispose list
can cause the leaks. This patch adds a new list_head nf_gc in struct nfsd_file, and uses
it for the dispose list. It's not expected to have a nfsd_file unhashed but it's not 
added to the dispose list, so in nfsd_file_cond_queue() and nfsd_file_lru_cb() nfsd_file 
is unhashed after being added to the dispose list.

Signed-off-by: Youzhong Yang <********@gmail.com>
---
 fs/nfsd/filecache.c | 23 ++++++++++++++---------
 fs/nfsd/filecache.h |  1 +
 2 files changed, 15 insertions(+), 9 deletions(-)

diff --git a/fs/nfsd/filecache.c b/fs/nfsd/filecache.c
index ad9083ca144b..3aef2ddfce94 100644
--- a/fs/nfsd/filecache.c
+++ b/fs/nfsd/filecache.c
@@ -216,6 +216,7 @@ nfsd_file_alloc(struct net *net, struct inode *inode, unsigned char need,
                return NULL;

        INIT_LIST_HEAD(&nf->nf_lru);
+       INIT_LIST_HEAD(&nf->nf_gc);
        nf->nf_birthtime = ktime_get();
        nf->nf_file = NULL;
        nf->nf_cred = get_current_cred();
@@ -393,8 +394,8 @@ nfsd_file_dispose_list(struct list_head *dispose)
        struct nfsd_file *nf;

        while (!list_empty(dispose)) {
-               nf = list_first_entry(dispose, struct nfsd_file, nf_lru);
-               list_del_init(&nf->nf_lru);
+               nf = list_first_entry(dispose, struct nfsd_file, nf_gc);
+               list_del_init(&nf->nf_gc);
                nfsd_file_free(nf);
        }
 }
@@ -411,12 +412,12 @@ nfsd_file_dispose_list_delayed(struct list_head *dispose)
 {
        while(!list_empty(dispose)) {
                struct nfsd_file *nf = list_first_entry(dispose,
-                                               struct nfsd_file, nf_lru);
+                                               struct nfsd_file, nf_gc);
                struct nfsd_net *nn = net_generic(nf->nf_net, nfsd_net_id);
                struct nfsd_fcache_disposal *l = nn->fcache_disposal;

                spin_lock(&l->lock);
-               list_move_tail(&nf->nf_lru, &l->freeme);
+               list_move_tail(&nf->nf_gc, &l->freeme);
                spin_unlock(&l->lock);
                svc_wake_up(nn->nfsd_serv);
        }
@@ -502,8 +503,10 @@ nfsd_file_lru_cb(struct list_head *item, struct list_lru_one *lru,
        }

        /* Refcount went to zero. Unhash it and queue it to the dispose list */
+       list_lru_isolate(lru, &nf->nf_lru);
+       list_add(&nf->nf_gc, head);
+       /* Unhash after removing from LRU and adding to dispose list */
        nfsd_file_unhash(nf);
-       list_lru_isolate_move(lru, &nf->nf_lru, head);
        this_cpu_inc(nfsd_file_evictions);
        trace_nfsd_file_gc_disposed(nf);
        return LRU_REMOVED;
@@ -565,7 +568,7 @@ nfsd_file_cond_queue(struct nfsd_file *nf, struct list_head *dispose)
        int decrement = 1;

        /* If we raced with someone else unhashing, ignore it */
-       if (!nfsd_file_unhash(nf))
+       if (!test_bit(NFSD_FILE_HASHED, &nf->nf_flags))
                return;

        /* If we can't get a reference, ignore it */
@@ -578,7 +581,9 @@ nfsd_file_cond_queue(struct nfsd_file *nf, struct list_head *dispose)

        /* If refcount goes to 0, then put on the dispose list */
        if (refcount_sub_and_test(decrement, &nf->nf_ref)) {
-               list_add(&nf->nf_lru, dispose);
+               list_add(&nf->nf_gc, dispose);
+               /* Unhash after adding to dispose list */
+               nfsd_file_unhash(nf);
                trace_nfsd_file_closing(nf);
        }
 }
@@ -654,8 +659,8 @@ nfsd_file_close_inode_sync(struct inode *inode)

        nfsd_file_queue_for_close(inode, &dispose);
        while (!list_empty(&dispose)) {
-               nf = list_first_entry(&dispose, struct nfsd_file, nf_lru);
-               list_del_init(&nf->nf_lru);
+               nf = list_first_entry(&dispose, struct nfsd_file, nf_gc);
+               list_del_init(&nf->nf_gc);
                nfsd_file_free(nf);
        }
 }
diff --git a/fs/nfsd/filecache.h b/fs/nfsd/filecache.h
index c61884def906..3fbec24eea6c 100644
--- a/fs/nfsd/filecache.h
+++ b/fs/nfsd/filecache.h
@@ -44,6 +44,7 @@ struct nfsd_file {

        struct nfsd_file_mark   *nf_mark;
        struct list_head        nf_lru;
+       struct list_head        nf_gc;
        struct rcu_head         nf_rcu;
        ktime_t                 nf_birthtime;
 };
--
2.34.1
```

Reordering of the 'unhash' and adding to dispose list is rejected unfortunately.

So the following patch which adds list_head nf_gc only is likely to be accepted:
```
diff --git a/fs/nfsd/filecache.c b/fs/nfsd/filecache.c
index ad9083ca144b..22ebd7fb8639 100644
--- a/fs/nfsd/filecache.c
+++ b/fs/nfsd/filecache.c
@@ -216,6 +216,7 @@ nfsd_file_alloc(struct net *net, struct inode *inode, unsigned char need,
                return NULL;

        INIT_LIST_HEAD(&nf->nf_lru);
+       INIT_LIST_HEAD(&nf->nf_gc);
        nf->nf_birthtime = ktime_get();
        nf->nf_file = NULL;
        nf->nf_cred = get_current_cred();
@@ -393,8 +394,8 @@ nfsd_file_dispose_list(struct list_head *dispose)
        struct nfsd_file *nf;

        while (!list_empty(dispose)) {
-               nf = list_first_entry(dispose, struct nfsd_file, nf_lru);
-               list_del_init(&nf->nf_lru);
+               nf = list_first_entry(dispose, struct nfsd_file, nf_gc);
+               list_del_init(&nf->nf_gc);
                nfsd_file_free(nf);
        }
 }
@@ -411,12 +412,12 @@ nfsd_file_dispose_list_delayed(struct list_head *dispose)
 {
        while(!list_empty(dispose)) {
                struct nfsd_file *nf = list_first_entry(dispose,
-                                               struct nfsd_file, nf_lru);
+                                               struct nfsd_file, nf_gc);
                struct nfsd_net *nn = net_generic(nf->nf_net, nfsd_net_id);
                struct nfsd_fcache_disposal *l = nn->fcache_disposal;

                spin_lock(&l->lock);
-               list_move_tail(&nf->nf_lru, &l->freeme);
+               list_move_tail(&nf->nf_gc, &l->freeme);
                spin_unlock(&l->lock);
                svc_wake_up(nn->nfsd_serv);
        }
@@ -503,7 +504,8 @@ nfsd_file_lru_cb(struct list_head *item, struct list_lru_one *lru,

        /* Refcount went to zero. Unhash it and queue it to the dispose list */
        nfsd_file_unhash(nf);
-       list_lru_isolate_move(lru, &nf->nf_lru, head);
+       list_lru_isolate(lru, &nf->nf_lru);
+       list_add(&nf->nf_gc, head);
        this_cpu_inc(nfsd_file_evictions);
        trace_nfsd_file_gc_disposed(nf);
        return LRU_REMOVED;
@@ -578,7 +580,7 @@ nfsd_file_cond_queue(struct nfsd_file *nf, struct list_head *dispose)

        /* If refcount goes to 0, then put on the dispose list */
        if (refcount_sub_and_test(decrement, &nf->nf_ref)) {
-               list_add(&nf->nf_lru, dispose);
+               list_add(&nf->nf_gc, dispose);
                trace_nfsd_file_closing(nf);
        }
 }
@@ -654,8 +656,8 @@ nfsd_file_close_inode_sync(struct inode *inode)

        nfsd_file_queue_for_close(inode, &dispose);
        while (!list_empty(&dispose)) {
-               nf = list_first_entry(&dispose, struct nfsd_file, nf_lru);
-               list_del_init(&nf->nf_lru);
+               nf = list_first_entry(&dispose, struct nfsd_file, nf_gc);
+               list_del_init(&nf->nf_gc);
                nfsd_file_free(nf);
        }
 }
diff --git a/fs/nfsd/filecache.h b/fs/nfsd/filecache.h
index c61884def906..3fbec24eea6c 100644
--- a/fs/nfsd/filecache.h
+++ b/fs/nfsd/filecache.h
@@ -44,6 +44,7 @@ struct nfsd_file {

        struct nfsd_file_mark   *nf_mark;
        struct list_head        nf_lru;
+       struct list_head        nf_gc;
        struct rcu_head         nf_rcu;
        ktime_t                 nf_birthtime;
 };
```

The above patch and [the following patch](https://patchwork.kernel.org/project/linux-nfs/cover/20240710-nfsd-next-v1-0-21fca616ac53@kernel.org/) together also fix the leaks - tested with heavy nfs load and this reproducer too.
```
---
Jeff Layton (3):
      nfsd: fix refcount leak when failing to hash nfsd_file
      nfsd: fix refcount leak when file is unhashed after being found
      nfsd: count nfsd_file allocations
---
 fs/nfsd/filecache.c | 14 +++++++++++---
 1 file changed, 11 insertions(+), 3 deletions(-)

diff --git a/fs/nfsd/filecache.c b/fs/nfsd/filecache.c
index 4159411dee22..add5125e58dc 100644
--- a/fs/nfsd/filecache.c
+++ b/fs/nfsd/filecache.c
@@ -56,6 +56,7 @@
 
 static DEFINE_PER_CPU(unsigned long, nfsd_file_cache_hits);
 static DEFINE_PER_CPU(unsigned long, nfsd_file_acquisitions);
+static DEFINE_PER_CPU(unsigned long, nfsd_file_allocations);
 static DEFINE_PER_CPU(unsigned long, nfsd_file_releases);
 static DEFINE_PER_CPU(unsigned long, nfsd_file_total_age);
 static DEFINE_PER_CPU(unsigned long, nfsd_file_evictions);
@@ -222,6 +223,7 @@ nfsd_file_alloc(struct net *net, struct inode *inode, unsigned char need,
 		return NULL;
 	}
 
+	this_cpu_inc(nfsd_file_allocations);
 	INIT_LIST_HEAD(&nf->nf_lru);
 	INIT_LIST_HEAD(&nf->nf_gc);
 	nf->nf_birthtime = ktime_get();
@@ -917,6 +919,7 @@ nfsd_file_cache_shutdown(void)
 	for_each_possible_cpu(i) {
 		per_cpu(nfsd_file_cache_hits, i) = 0;
 		per_cpu(nfsd_file_acquisitions, i) = 0;
+		per_cpu(nfsd_file_allocations, i) = 0;
 		per_cpu(nfsd_file_releases, i) = 0;
 		per_cpu(nfsd_file_total_age, i) = 0;
 		per_cpu(nfsd_file_evictions, i) = 0;
@@ -1034,7 +1037,7 @@ nfsd_file_do_acquire(struct svc_rqst *rqstp, struct svc_fh *fhp,
 	if (unlikely(nf)) {
 		spin_unlock(&inode->i_lock);
 		rcu_read_unlock();
-		nfsd_file_slab_free(&new->nf_rcu);
+		nfsd_file_free(new);
 		goto wait_for_construction;
 	}
 	nf = new;
@@ -1045,8 +1048,10 @@ nfsd_file_do_acquire(struct svc_rqst *rqstp, struct svc_fh *fhp,
 	if (likely(ret == 0))
 		goto open_file;
 
-	if (ret == -EEXIST)
+	if (ret == -EEXIST) {
+		nfsd_file_free(nf);
 		goto retry;
+	}
 	trace_nfsd_file_insert_err(rqstp, inode, may_flags, ret);
 	status = nfserr_jukebox;
 	goto construction_err;
@@ -1062,6 +1067,7 @@ nfsd_file_do_acquire(struct svc_rqst *rqstp, struct svc_fh *fhp,
 			status = nfserr_jukebox;
 			goto construction_err;
 		}
+		nfsd_file_put(nf);
 		open_retry = false;
 		fh_put(fhp);
 		goto retry;
@@ -1213,7 +1219,7 @@ nfsd_file_acquire_opened(struct svc_rqst *rqstp, struct svc_fh *fhp,
  */
 int nfsd_file_cache_stats_show(struct seq_file *m, void *v)
 {
-	unsigned long releases = 0, evictions = 0;
+	unsigned long allocations = 0, releases = 0, evictions = 0;
 	unsigned long hits = 0, acquisitions = 0;
 	unsigned int i, count = 0, buckets = 0;
 	unsigned long lru = 0, total_age = 0;
@@ -1238,6 +1244,7 @@ int nfsd_file_cache_stats_show(struct seq_file *m, void *v)
 	for_each_possible_cpu(i) {
 		hits += per_cpu(nfsd_file_cache_hits, i);
 		acquisitions += per_cpu(nfsd_file_acquisitions, i);
+		allocations += per_cpu(nfsd_file_allocations, i);
 		releases += per_cpu(nfsd_file_releases, i);
 		total_age += per_cpu(nfsd_file_total_age, i);
 		evictions += per_cpu(nfsd_file_evictions, i);
@@ -1248,6 +1255,7 @@ int nfsd_file_cache_stats_show(struct seq_file *m, void *v)
 	seq_printf(m, "lru entries:   %lu\n", lru);
 	seq_printf(m, "cache hits:    %lu\n", hits);
 	seq_printf(m, "acquisitions:  %lu\n", acquisitions);
+	seq_printf(m, "allocations:   %lu\n", allocations);
 	seq_printf(m, "releases:      %lu\n", releases);
 	seq_printf(m, "evictions:     %lu\n", evictions);
 	if (releases)
-- 
GitLab
```
