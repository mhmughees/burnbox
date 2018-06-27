#include "config.h"
#include "params.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
//#include "UtilCrypto.h"
#include "BurnboxApi.h"

#ifdef HAVE_SYS_XATTR_H

#include <sys/xattr.h>

#endif

#include "log.h"
#include "bbfs.h"


namespace mymomo {

    std::string file_prf;

    std::map<std::string, string> mapoffiles;

    SecByteBlock contentkey;

    BurnboxApi *b1 = new BurnboxApi();


//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
    static void bb_fullpath(char fpath[PATH_MAX], const char *path) {
        //strcpy(fpath, BB_DATA->rootdir);

        strcpy(fpath,
               "/Users/harismughees/Documents/Cornell_Research/Secure_Delete/c++implementation/b2/cmake-build-debug/src/newfuse");

        if (path[0] == '/') {
            strncat(fpath, path, PATH_MAX);
        } else {


            strcat(fpath, "/");
            strncat(fpath, path, PATH_MAX);
        }
        log_msg("    bb_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
                BB_DATA->rootdir, path, fpath);
    }

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
    int bb_getattr(const char *path, struct stat *statbuf) {
        int retstat;
        char fpath[PATH_MAX];


        log_msg("\nbb_getattr(path=\"%s\", statbuf=0x%08x)\n",
                path, statbuf);

        string prf;
        getprf(path, prf);


        bb_fullpath(fpath, prf.data());


        retstat = log_syscall("lstat", lstat(fpath, statbuf), 0);


        if (S_ISREG(statbuf->st_mode)) {


            /////////////////////// uncomment for non chunking /////////////////////
//            if (statbuf->st_size > (MAC_SIZE + AES::DEFAULT_BLOCKSIZE))
//                statbuf->st_size -= (MAC_SIZE + AES::DEFAULT_BLOCKSIZE);

            off_t actual;
            cal_underlying_sz(statbuf->st_size, actual);
            statbuf->st_size = actual;


        }


        log_stat(statbuf);

        return retstat;
    }

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */

    int bb_readlink(const char *path, char *link, size_t size) {
        int retstat;
        char fpath[PATH_MAX];

        log_msg("\nbb_readlink(path=\"%s\", link=\"%s\", size=%d)\n",
                path, link, size);

        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        retstat = log_syscall("readlink", readlink(fpath, link, size - 1), 0);
        if (retstat >= 0) {
            link[retstat] = '\0';
            retstat = 0;
            log_msg("    link=\"%s\"\n", link);
        }

        return retstat;
    }

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
    int bb_mknod(const char *path, mode_t mode, dev_t dev) {
        int retstat;
        char fpath[PATH_MAX];


        log_msg("\nbb_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n",
                path, mode, dev);


        string prf;
        createprf(path, prf);
        bb_fullpath(fpath, prf.data());


        if (S_ISREG(mode)) {

            retstat = log_syscall("open", open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode), 0);

            cout << "created file: " << path << endl;

            if (retstat >= 0)
                retstat = log_syscall("close", close(retstat), 0);

        } else if (S_ISFIFO(mode))
            retstat = log_syscall("mkfifo", mkfifo(fpath, mode), 0);
        else
            retstat = log_syscall("mknod", mknod(fpath, mode, dev), 0);

        close(retstat);
        return retstat;
    }

/** Create a directory */
    int bb_mkdir(const char *path, mode_t mode) {
        char fpath[PATH_MAX];

        log_msg("\nbb_mkdir(path=\"%s\", mode=0%3o)\n",
                path, mode);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        return log_syscall("mkdir", mkdir(fpath, mode), 0);
    }

/** Remove a file */
    int bb_unlink(const char *path) {
        char fpath[PATH_MAX];

        log_msg("bb_unlink(path=\"%s\")\n",
                path);
        string prf;
        getprf(path, prf);
        bb_fullpath(fpath, prf.data());

        if (strncmp(path, "/", 1) != 0 && strncmp(path, "/.", 2) != 0) {
            rmvname(path);// first remove entry from in memory list
        }

        return log_syscall("unlink", unlink(fpath), 0);
    }

/** Remove a directory */
    int bb_rmdir(const char *path) {
        char fpath[PATH_MAX];

        log_msg("bb_rmdir(path=\"%s\")\n",
                path);
        bb_fullpath(fpath, path);

        return log_syscall("rmdir", rmdir(fpath), 0);
    }

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
    int bb_symlink(const char *path, const char *link) {
        char flink[PATH_MAX];

        log_msg("\nbb_symlink(path=\"%s\", link=\"%s\")\n",
                path, link);
        bb_fullpath(flink, link);

        //log_syscall("symlink", symlink(path, flink), 0);
        return 0;
    }

/** Rename a file */
// both path and newpath are fs-relative
    int bb_rename(const char *path, const char *newpath) {
        char fpath[PATH_MAX];
        char fnewpath[PATH_MAX];

        log_msg("\nbb_rename(fpath=\"%s\", newpath=\"%s\")\n",
                path, newpath);
        bb_fullpath(fpath, path);
        bb_fullpath(fnewpath, newpath);

        return log_syscall("rename", rename(fpath, fnewpath), 0);
    }

/** Create a hard link to a file */
    int bb_link(const char *path, const char *newpath) {
        char fpath[PATH_MAX], fnewpath[PATH_MAX];

        log_msg("\nbb_link(path=\"%s\", newpath=\"%s\")\n",
                path, newpath);
        bb_fullpath(fpath, path);
        bb_fullpath(fnewpath, newpath);

        return log_syscall("link", link(fpath, fnewpath), 0);
    }

/** Change the permission bits of a file */
    int bb_chmod(const char *path, mode_t mode) {
        char fpath[PATH_MAX];

        log_msg("\nbb_chmod(fpath=\"%s\", mode=0%03o)\n",
                path, mode);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        return log_syscall("chmod", chmod(fpath, mode), 0);
    }

/** Change the owner and group of a file */
    int bb_chown(const char *path, uid_t uid, gid_t gid) {
        char fpath[PATH_MAX];

        log_msg("\nbb_chown(path=\"%s\", uid=%d, gid=%d)\n",
                path, uid, gid);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        return log_syscall("chown", chown(fpath, uid, gid), 0);
    }

/** Change the size of a file */
    int bb_truncate(const char *path, off_t newsize) {
        char fpath[PATH_MAX];

        log_msg("\nbb_truncate(path=\"%s\", newsize=%lld)\n",
                path, newsize);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        return log_syscall("truncate", truncate(fpath, newsize), 0);
    }

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
    int bb_utime(const char *path, struct utimbuf *ubuf) {
        char fpath[PATH_MAX];

        log_msg("\nbb_utime(path=\"%s\", ubuf=0x%08x)\n",
                path, ubuf);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        return log_syscall("utime", utime(fpath, ubuf), 0);
    }

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
    int bb_open(const char *path, struct fuse_file_info *fi) {
        int retstat = 0;
        int fd;
        char fpath[PATH_MAX];


        log_msg("\nbb_open(path\"%s\", fi=0x%08x)\n",
                path, fi);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        fd = log_syscall("open", open(fpath, fi->flags), 0);
        if (fd < 0)
            retstat = log_error("open");

        fi->fh = fd;

        log_fi(fi);

        return retstat;
    }

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */

    int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {


        log_msg("\nbb_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
                path, buf, size, offset, fi);
        // no need to get fpath on this one, since I work from fi->fh not the path
        log_fi(fi);

        //return read_underlying(buf, size, offset, fi);


        //cout << "reading:" <<path<< endl;


        //return log_syscall("read", pread(fi->fh, buf, size, offset), 0);

        string filename(path, PATH_MAX);
        b1->NameToCK(filename, contentkey);

        return read_underlying(path, buf, size, offset, fi);

        //return encrypted_read(path, buf, size, offset, fi);

    }


    int bb_write(const char *path, const char *buf, size_t size, off_t offset,
                 struct fuse_file_info *fi) {



        //cout << "writing " << size << " at " << offset << ":" << path << endl;

        log_msg("\nbb_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
                path, buf, size, offset, fi
        );
        // no need to get fpath on this one, since I work from fi->fh not the path
        log_fi(fi);


        char rand[MAC_SIZE + AES::DEFAULT_BLOCKSIZE];

        memset(rand, 0, MAC_SIZE + AES::DEFAULT_BLOCKSIZE);


//       int i= log_syscall("pwrite", pwrite(fi->fh, buf, size, offset), 0);
//
//        pwrite(fi->fh, rand, MAC_SIZE+ AES::DEFAULT_BLOCKSIZE, size);
//
//        return i;

        string filename(path, PATH_MAX);
        b1->NameToCK(filename, contentkey);

//        if(b1->NameToCK(filename,contentkey)) {
//
//            return write_underlying(path, buf, size, offset, fi);
//        }else{
//            return log_syscall("pwrite", pwrite(fi->fh, buf, size, offset), 0);
//        }
        return write_underlying(path, buf, size, offset, fi);

        //////////remove for unchunking ////////////////
        //return encrypted_write(path, buf, size, offset, fi);
    }

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
    int bb_statfs(const char *path, struct statvfs *statv) {
        int retstat = 0;
        char fpath[PATH_MAX];

        log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n",
                path, statv);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        // get stats for underlying filesystem
        retstat = log_syscall("statvfs", statvfs(fpath, statv), 0);

        log_statvfs(statv);

        return retstat;
    }

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in BBFS.  It just logs the call and returns success
    int bb_flush(const char *path, struct fuse_file_info *fi) {
        log_msg("\nbb_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
        // no need to get fpath on this one, since I work from fi->fh not the path
        log_fi(fi);

        return 0;
    }

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
    int bb_release(const char *path, struct fuse_file_info *fi) {
        log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n",
                path, fi);
        log_fi(fi);

        // We need to close the file.  Had we allocated any resources
        // (buffers etc) we'd need to free them here as well.
        return log_syscall("close", close(fi->fh), 0);
    }

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
    int bb_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
        log_msg("\nbb_fsync(path=\"%s\", datasync=%d, fi=0x%08x)\n",
                path, datasync, fi);
        log_fi(fi);

//        // some unix-like systems (notably freebsd) don't have a datasync call
//#ifdef HAVE_FDATASYNC
//        if (datasync)
//
//            //return log_syscall("fdatasync", fdatasync(fi->fh), 0);
//        else
//#endif
        return log_syscall("fsync", fsync(fi->fh), 0);
    }

#ifdef HAVE_SYS_XATTR_H

#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
    int bb_opendir(const char *path, struct fuse_file_info *fi) {
        DIR *dp;
        int retstat = 0;
        char fpath[PATH_MAX];

        log_msg("\nbb_opendir(path=\"%s\", fi=0x%08x)\n",
                path, fi);
        bb_fullpath(fpath, path);

        // since opendir returns a pointer, takes some custom handling of
        // return status.
        dp = opendir(fpath);
        log_msg("    opendir returned 0x%p\n", dp);
        if (dp == NULL)
            retstat = log_error("bb_opendir opendir");

        fi->fh = (intptr_t) dp;

        log_fi(fi);

        return retstat;
    }

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */

    int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                   struct fuse_file_info *fi) {
        int retstat = 0;
        DIR *dp;
        struct dirent *de;

        log_msg("\nbb_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
                path, buf, filler, offset, fi);
        // once again, no need for fullpath -- but note that I need to cast fi->fh
        dp = (DIR *) (uintptr_t) fi->fh;

        // Every directory contains at least two entries: . and ..  If my
        // first call to the system readdir() returns NULL I've got an
        // error; near as I can tell, that's the only condition under
        // which I can get an error from readdir()


        de = readdir(dp);
        log_msg("    readdir returned 0x%p\n", de);
        if (de == 0) {
            retstat = log_error("bb_readdir readdir");
            return retstat;
        }

        // This will copy the entire directory into the buffer.  The loop exits
        // when either the system readdir() returns NULL, or filler()
        // returns something non-zero.  The first case just means I've
        // read the whole directory; the second means the buffer is full.




        do {
            log_msg("calling filler with name %s\n", de->d_name);
            string name;

            char fpath[PATH_MAX];
            struct stat *statbuf = NULL;

            bb_fullpath(fpath, de->d_name);
            int lstat_out = lstat(fpath, statbuf);


            if (lstat_out == 0 && S_ISREG(statbuf->st_mode)) {

                //only for regular file we are evaluating actual length

                //////////////////without chunking ////////////////////////
                //statbuf->st_size = statbuf->st_size - (MAC_SIZE +AES::DEFAULT_BLOCKSIZE);

                off_t actual;
                cal_underlying_sz(statbuf->st_size, actual);

                statbuf->st_size = actual;


            }

            getname(de->d_name, name);


            if (filler(buf, name.c_str(), statbuf, 0) != 0) {
                log_msg("    ERROR bb_readdir filler:  buffer full");
                return -ENOMEM;
            }
        } while ((de = readdir(dp)) != NULL);

        log_fi(fi);


        return retstat;
    }

/** Release directory
 *
 * Introduced in version 2.3
 */
    int bb_releasedir(const char *path, struct fuse_file_info *fi) {
        int retstat = 0;

        log_msg("\nbb_releasedir(path=\"%s\", fi=0x%08x)\n",
                path, fi);
        log_fi(fi);

        closedir((DIR *) (uintptr_t) fi->fh);

        return retstat;
    }

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
    int bb_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi) {
        int retstat = 0;

        log_msg("\nbb_fsyncdir(path=\"%s\", datasync=%d, fi=0x%08x)\n",
                path, datasync, fi);
        log_fi(fi);

        return retstat;
    }

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
    void *bb_init(struct fuse_conn_info *conn) {
        log_msg("\nbb_init()\n");

        log_conn(conn);
        log_fuse_context(fuse_get_context());

        string err;
        b1->Init(err);

        return BB_DATA;
    }

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
    void bb_destroy(void *userdata) {
        log_msg("\nbb_destroy(userdata=0x%08x)\n", userdata);
    }

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
    int bb_access(const char *path, int mask) {
        int retstat = 0;
        char fpath[PATH_MAX];

        log_msg("\nbb_access(path=\"%s\", mask=0%o)\n",
                path, mask);
        string prf;
        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        retstat = access(fpath, mask);

        if (retstat < 0)
            retstat = log_error("bb_access access");

        return retstat;
    }

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
    int bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) {
        int retstat = 0;

        log_msg("\nbb_ftruncate(path=\"%s\", offset=%lld, fi=0x%08x)\n",
                path, offset, fi);
        log_fi(fi);

        retstat = ftruncate(fi->fh, offset);
        if (retstat < 0)
            retstat = log_error("bb_ftruncate ftruncate");

        return retstat;
    }

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
    int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
        int retstat = 0;

        log_msg("\nbb_fgetattr(path=\"%s\", statbuf=0x%08x, fi=0x%08x)\n",
                path, statbuf, fi);
        log_fi(fi);

        if (!strcmp(path, "/"))
            return bb_getattr(path, statbuf);

        retstat = fstat(fi->fh, statbuf);
        if (retstat < 0)
            retstat = log_error("bb_fgetattr fstat");

        log_stat(statbuf);

        return retstat;
    }


    void bb_usage() {
        fprintf(stderr, "usage:  bbfs [FUSE and mount options] rootDir mountPoint\n");
        abort();
    }

    int mymain(int argc, char *argv[]) {
        int fuse_stat;
        struct bb_state *bb_data;

        struct fuse_operations bb_oper{};
        bb_oper.getattr = bb_getattr;
        bb_oper.readlink = bb_readlink;
                // no .getdir -- that's deprecated
                bb_oper.getdir = NULL;
                bb_oper.mknod = bb_mknod;
                bb_oper.mkdir = bb_mkdir;
                bb_oper.unlink = bb_unlink;
                bb_oper.rmdir = bb_rmdir;
                bb_oper.symlink = bb_symlink;
                bb_oper.rename = bb_rename;
                bb_oper.link = bb_link;
                bb_oper.chmod = bb_chmod;
                bb_oper.chown = bb_chown;
                bb_oper.truncate = bb_truncate;
                bb_oper.utime = bb_utime;
                bb_oper.open = bb_open;
                bb_oper.read = bb_read;
                bb_oper.write = bb_write;
                /** Just a placeholder, don't set */ // huh???
                bb_oper.statfs = bb_statfs;
                bb_oper.flush = bb_flush;
                bb_oper.release = bb_release;
                bb_oper.fsync = bb_fsync;
                bb_oper.opendir = bb_opendir;
                bb_oper.readdir = bb_readdir;
                bb_oper.releasedir = bb_releasedir;
                bb_oper.fsyncdir = bb_fsyncdir;
                bb_oper.init = bb_init;
                bb_oper.destroy = bb_destroy;
                bb_oper.access = bb_access;
                bb_oper.ftruncate = bb_ftruncate;
                bb_oper.fgetattr = bb_fgetattr;
        //.create= bb_create



        create_master_key();


        if ((getuid() == 0) || (geteuid() == 0)) {
            fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
            return 1;
        }

        // See which version of fuse we're running
        fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

        // Perform some sanity checking on the command line:  make sure
        // there are enough arguments, and that neither of the last two
        // start with a hyphen (this will break if you actually have a
        // rootpoint or mountpoint whose name starts with a hyphen, but so
        // will a zillion other programs)
        if ((argc < 3) || (argv[argc - 2][0] == '-') || (argv[argc - 1][0] == '-'))
            bb_usage();

        bb_data = static_cast<bb_state *>(malloc(sizeof(struct bb_state)));
        if (bb_data == NULL) {
            perror("main calloc");
            abort();
        }

        // Pull the rootdir out of the argument list and save it in my
        // internal data
        bb_data->rootdir = realpath(argv[argc - 2], NULL);

        cout << bb_data->rootdir << endl;
        argv[argc - 2] = argv[argc - 1];
        argv[argc - 1] = NULL;
        argc--;

        bb_data->logfile = log_open();

        // turn over control to fuse
        fprintf(stderr, "about to call fuse_main\n");
        fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
        fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

        return fuse_stat;
    }

    void createprf(const char *path, string &prf) {


        //create new prf
        SecByteBlock tmp_prf;
        string filename(path, PATH_MAX);
        string prf_string;

        if (strncmp(filename.data(), "/", filename.size()) != 0 && strncmp(filename.data(), "/._", 3) != 0 &&
            strncmp(filename.data(), "/.", filename.size()) != 0 &&
            strncmp(filename.data(), "/..", filename.size()) != 0) {
            UtilCrypto::_creatkey(tmp_prf);
            UtilCrypto::b64encode((char *) tmp_prf.data(), tmp_prf.size(), prf);


            string pname, err;
            b1->AddFile(filename, pname, err);

            prf = pname;

            string ppname;
            b1->NameToPrf(filename, ppname);

            prf = "/" + prf;
        } else if (strncmp(filename.data(), "/._", 3) == 0) {
            b1->NameToPrf(filename, prf);
        } else {
            prf = filename;
        }

        mapoffiles[filename.data()] = prf.data();

    }

    void getprf(const char *path, string &prf) {

        //returns prf for name
        string filename(path, PATH_MAX);
        //string n1;



        if (strncmp(filename.data(), "/", filename.size()) != 0) {

            //prf = mapoffiles[filename.data()];

            string ppname;

            b1->NameToPrf(filename, prf);


        } else {
            prf = "/";

        }

        if (prf.empty()) {
            prf = filename;

        }


    }

    void getname(const char *path, string &name) {

        //return name associated with prf

        name.clear();

        string filename(path, PATH_MAX);

        if (strncmp(filename.data(), "/", filename.size()) != 0) {
            b1->PrfToName(filename, name);
        } else {
            name = "/";
        }

        if (name.empty()) {
            name = filename;

        }


    }


    int bb_create(const char *path, mode_t mode, struct fuse_file_info *info) {

        int retstat = 6;
        char fpath[PATH_MAX];


        log_msg("\nbb_create(path=\"%s\", mode=0%3o, dev=%lld)\n",
                path, mode, info);
        string prf;
        createprf(path, prf);
        bb_fullpath(fpath, prf.data());

        cout << "creating " << path << " as " << fpath << endl;


        //retstat = log_syscall("open", open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode), 0);

        cout << "status " << open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode) << endl;


        return retstat;
    }

    void rmvname(const char *path) {

        string filename(path, PATH_MAX);

        b1->DeleteFile(filename);

        //auto it = mapoffiles.find(filename.data());

        //if (it != mapoffiles.end())
        //    mapoffiles.erase(it);


    }


    void cal_underlying_sz(off_t underlying_size, off_t &actual_size) {

        //this function calculates fake file size from actual encrypted file


        auto underlying_block_size = ENC_FILE_BLK_SZ;
        auto num_blocks = underlying_size / underlying_block_size;
        auto residue = underlying_size % underlying_block_size;
        actual_size = num_blocks * FILE_BLK_SZ
                      +
                      (residue > (AES::DEFAULT_BLOCKSIZE + MAC_SIZE) ? residue - AES::DEFAULT_BLOCKSIZE - MAC_SIZE : 0);


    }


    int write_underlying(const char *path, const char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {


        //this function is a driver for writing blocks




        size_t length = size;

        int written_size = 0;


        while (length > 0) {

            off_t blk_num = offset / FILE_BLK_SZ;
            auto blk_start = blk_num * FILE_BLK_SZ; // overall offset of blk start
            off_t blk_offset = offset - blk_start; // offset inside the blk
            off_t blk_sz = std::min<off_t>(FILE_BLK_SZ, (offset + length) - blk_start);

            assert(blk_offset <= FILE_BLK_SZ && blk_sz <= FILE_BLK_SZ);

            if (blk_offset == 0 && blk_sz == FILE_BLK_SZ) {

                write_block(blk_num, buf, FILE_BLK_SZ, fi);

                auto data_sz = blk_sz - blk_offset;// size of data added to blk
                buf = (buf) + data_sz;
                offset += data_sz;
                length -= data_sz;
                written_size += data_sz;


                continue;
            }
            if (blk_offset >= blk_sz)
                return 0;

            char buffer[FILE_BLK_SZ];


            auto rc = read_block(path, blk_num, buffer);// read buff data may be less than ENC_FILE_BLK_SZ
            //assert(rc == blk_offset);// checking bytes read


            memcpy(buffer + blk_offset, buf, blk_sz - blk_offset);//putting remaining data in buffer



            write_block(blk_num, buffer, std::max<size_t>(rc, blk_sz), fi);


            auto data_sz = blk_sz - blk_offset;// size of data added to blk
            buf = (buf) + data_sz;
            offset += data_sz;
            length -= data_sz;
            written_size += data_sz;

        }


        assert(size == (size_t) written_size);
        return written_size;

    }


    void
    read_then_write_block(const char *path, off_t block_number, const char *input, off_t begin, off_t end,
                          struct fuse_file_info *fi) {

        // this function reads incomplete buffer and add remaining data also it adds buffer directly to file



        assert(begin <= FILE_BLK_SZ && end <= FILE_BLK_SZ);
        //sanity check on begin and end

        if (begin == 0 && end == FILE_BLK_SZ) {

            return write_block(block_number, input, FILE_BLK_SZ, fi);
        }
        if (begin >= end)
            return;


        char buffer[FILE_BLK_SZ];


        auto rc = read_block(path, block_number, buffer);// read buff data may be less than ENC_FILE_BLK_SZ
        assert(rc == (unsigned long) begin);// checking bytes read

        memcpy(buffer + begin, input, end - begin);//putting remaining data in buffer



        write_block(block_number, buffer, std::max<size_t>(rc, end), fi);
    }

    size_t read_block(const char *path, off_t block_number, char *output) {


        char fpath[PATH_MAX];
        int fd;


        //char *cipher_content;
        string prf;

        //opening file as read only, can not use fd given by fuse because its opened as write only

        //cout<<"reading"<<endl;
        getprf(path, prf);
        //cout<<"readed"<<endl;


        bb_fullpath(fpath, prf.data());


        fd = open(fpath, O_RDONLY);


        if (fd < 0) {
            cerr << "file could not be opened" << endl;
        }


        auto underlying_offset = block_number * ENC_FILE_BLK_SZ;
        char block_buffer[ENC_FILE_BLK_SZ];


        ssize_t rc = pread(fd, block_buffer, ENC_FILE_BLK_SZ, underlying_offset);

        close(fd);

        //assert(rc == ENC_FILE_BLK_SZ);

        if (rc <= MAC_SIZE + AES::DEFAULT_BLOCKSIZE)
            //close(fd);
            return 0;

        auto out_size = rc - MAC_SIZE - AES::DEFAULT_BLOCKSIZE;




        //decrypting read cypher
        string plaintext;
        string adata;
        string cipher(block_buffer, rc);

        UtilCrypto::_decrypt(contentkey, cipher, adata, plaintext);


        //loading it into output buffer
        memcpy(output, plaintext.data(), plaintext.size());


        return out_size;
    }

    size_t read_block(off_t block_number, char *output, struct fuse_file_info *fi) {

        //this function reads each block and decrypt it

        auto underlying_offset = block_number * ENC_FILE_BLK_SZ;
        char block_buffer[ENC_FILE_BLK_SZ];


        size_t rc = pread(fi->fh, block_buffer, ENC_FILE_BLK_SZ, underlying_offset);

        //assert(rc == ENC_FILE_BLK_SZ);

        if (rc <= MAC_SIZE + AES::DEFAULT_BLOCKSIZE)
            return 0;

        auto out_size = rc - MAC_SIZE - AES::DEFAULT_BLOCKSIZE;


        string plaintext;
        string adata;

        string cipher(block_buffer, rc);


        UtilCrypto::_decrypt(contentkey, cipher, adata, plaintext);


        memcpy(output, plaintext.data(), plaintext.size());

        return out_size;


    }

    //off_t block_number, const char *input, size_t size, struct fuse_file_info *fi

    void write_block(off_t block_number, const char *input, size_t size, struct fuse_file_info *fi) {


        //this function encrypt each data and write it as whole block to file

        auto underlying_offset = block_number * ENC_FILE_BLK_SZ;
        auto underlying_size = size + MAC_SIZE + AES::DEFAULT_BLOCKSIZE;//size of data to be written



        //char block_buffer[ENC_FILE_BLK_SZ];



        string cipher, adata;
        string plaintext(input, size);

        UtilCrypto::_encryptfile(contentkey, plaintext, adata, cipher);

        assert(cipher.size() == underlying_size);

        ssize_t wc = pwrite(fi->fh, cipher.data(), underlying_size, underlying_offset);

        (void) wc;

//assert(wc == underlying_size);

    }


    size_t read_underlying(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {


        int ss = 0;

        int start_s = clock();
        size_t length = size;

        size_t total_read = 0;

        while (length > 0) {
            off_t blk_num = offset / FILE_BLK_SZ;
            auto blk_start = blk_num * FILE_BLK_SZ; // overall offset of blk start
            off_t blk_offset = offset - blk_start; // offset inside the blk
            off_t blk_sz = std::min<off_t>(FILE_BLK_SZ, (offset + length) - blk_start);


            int ss_start = clock();
            auto rc = read_block(blk_num, buf, blk_offset, blk_sz,
                                 fi);// off_t block_number, char *output, struct fuse_file_info *fi
            int ss_end = clock();
            ss = ss + (ss_end - ss_start);

            if (rc < (unsigned long) (blk_sz - blk_offset))
                return total_read;
            buf = buf + rc;
            offset += rc;
            length -= rc;
            total_read += rc;
        }


        int stop_s = clock();
        double t = (stop_s - start_s - ss) * 1.0 / (CLOCKS_PER_SEC / 1000);
        FILE *f = fopen("2bb_file_read_time.txt", "a");
        fprintf(f, "%.5f-%s\n", t, path);
        fclose(f);

        t = (ss) * 1.0 / (CLOCKS_PER_SEC / 1000);
        f = fopen("2bb_file_read_enc_time.txt", "a");
        fprintf(f, "%.5f-%s\n", t, path);
        fclose(f);


        assert(total_read == size);
        return total_read;


    }

    size_t read_block(off_t block_number, char *output, off_t begin, off_t end, struct fuse_file_info *fi) {


        //overiding function that
        assert(begin <= FILE_BLK_SZ && end <= FILE_BLK_SZ);
        if (begin == 0 && end == FILE_BLK_SZ)
            return read_block(block_number, output, fi);

        char buffer[FILE_BLK_SZ];

        auto rc = read_block(block_number, buffer, fi);


        end = std::min<off_t>(end, rc);

        memcpy(output, buffer + begin, end - begin);


        return end - begin;;
    }


    void create_master_key() {

        UtilCrypto::_creatkey(contentkey);


    }

    void get_master_key(SecByteBlock key) {

        key = contentkey;
    }


    size_t encrypted_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
        //dirty implementation of encrypted read
        char fpath[PATH_MAX];
        string prf;
        getprf(path, prf);
        bb_fullpath(fpath, prf.data());

        //memset(buf,0,size);


        struct stat sb;

        //off_t  rahul_off = lseek( fi->fh , 0, SEEK_SET ) ;



        if (lstat(fpath, &sb) != 0) {
            cerr << "unable to lstat for " << prf.data() << endl;
        }
        char *cipher_content = (char *) malloc((size_t) sb.st_size);


        //int rc = (int) pread(fi->fh, cipher_content, sb.st_size,offset);

        lseek((int) fi->fh, 0, SEEK_SET);
        ssize_t rc = read((int) fi->fh, cipher_content, (size_t) sb.st_size);

        if (rc < 0) {
            cerr << "unable to read: " << path << endl;
            return 0;
        }

        string cipher, plaintext, adata;


        if (rc > 0) {
            //assert(rc == sb.st_size);
            cipher.assign(cipher_content, rc);

            UtilCrypto::_decryptfile(contentkey, cipher, adata, plaintext);

        }

        string content_read = plaintext.substr(offset, size);


        memcpy(buf, content_read.data(), content_read.size());

        string file_test = "/Users/harismughees/Documents/Cornell_Research/Secure_Delete/c++implementation/b2/cmake-build-debug/src/test.pdf";

        if (strncmp(path, "/e2.pdf", 6) == 0) {
            cout << offset << " " << size << endl;
            int fd2 = open(file_test.data(), O_WRONLY);
            pwrite(fd2, buf, content_read.size(), offset);

            close(fd2);
        }



        //assert(content_read.size() == size);

        return size;


    }


    int encrypted_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
        //dirty implementation of write

        char fpath[PATH_MAX];
        int fd;

        char *cipher_content;
        string prf;

        getprf(path, prf);

        bb_fullpath(fpath, prf.data());

        fd = open(fpath, O_RDONLY);

        if (fd < 0) {
            cerr << "file could not be opened" << endl;
        }


        struct stat sb;

        if (lstat(fpath, &sb) != 0) {
            cerr << "unable to lstat for " << prf.data() << endl;
        }


        cipher_content = (char *) malloc(sb.st_size);


        ssize_t rc = read(fd, cipher_content, sb.st_size);

        assert(rc == sb.st_size);


        string cipher, plaintext, adata;


        if (rc > 0) {

            //if some data is read
            cipher.assign(cipher_content, rc);
            UtilCrypto::_decryptfile(contentkey, cipher, adata, plaintext);

            cout << "plaintext=" << plaintext.size() << endl;
            cout << "size" << size << endl;
            cout << "offset=" << offset << endl;

            //assert(plaintext.size() == (rc - MAC_SIZE - AES::DEFAULT_BLOCKSIZE));
            //assert(plaintext.size() == offset);


        }

        //plaintext.insert(offset, size,buf);// adding to plaintext

        string plain_text2 = plaintext;



        //unsigned long j = plain_text2.size();


//        if(offset>0){
//            offset-= 1;
//
//        }
        plain_text2.insert(offset, buf, size);

        string appended_cipher;

        UtilCrypto::_encrypt(contentkey, plain_text2, adata, appended_cipher);


        //unsigned long k = appended_cipher.size();

        assert(appended_cipher.size() == plain_text2.size() + MAC_SIZE +
                                         AES::DEFAULT_BLOCKSIZE); // check if correct amount of data is being written

        assert(lseek(fi->fh, 0, SEEK_SET) != -1);


        int wc = (int) write(fi->fh, appended_cipher.data(), appended_cipher.size());

        (void) wc;

        //pwrite(fi->fh, buf, size, offset)
        // return log_syscall("write", size, 0);// can return size as well
        return size;
    }


}