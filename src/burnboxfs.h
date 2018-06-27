//
// Created by Haris Mughees on 3/29/18.
//

#ifndef BURNBOX_BURNBOXFS_H
#define BURNBOX_BURNBOXFS_H

#include <fuse.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <iostream>
#include <cstring>
#include <string>
#include <dirent.h>
#include <boost/filesystem.hpp>
#include "BurnboxApi.h"


using namespace std;

namespace burnboxfs {

#define ENCCDIR "/Users/harismughees/Documents/Cornell_Research/Secure_Delete/c++implementation/b2/cmake-build-debug/src/newfuse"


    typedef struct {
        std::string bgdir;
    } bgdata;


    void init_fuse_operations(struct fuse_operations *opt, bool xattr);

    int start_fs(int argc, char **argv);

    bool sanity_check(const string &path);

    bool transalte_path(const string &path, string &fpath);


    void *init(struct fuse_conn_info *conn);

    int getattr(const char *path, struct stat *statbuf);

    int getattr2(const char *path, struct stat *statbuf);

    int bb_opendir(const char *path, struct fuse_file_info *fi);

    int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                   struct fuse_file_info *fi);


    int bb_releasedir(const char *path, struct fuse_file_info *fi);

    int bb_open(const char *path, struct fuse_file_info *fi);

    int bb_utime(const char *path, struct utimbuf *ubuf);

    int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

    int bb_statfs(const char *path, struct statvfs *statv);

    int bb_fsync(const char *path, int datasync, struct fuse_file_info *fi);

    int bb_access(const char *path, int mask);


    int bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi);

    int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi);


    int bb_write(const char *path, const char *buf, size_t size, off_t offset,
                 struct fuse_file_info *fi);

    int bb_release(const char *path, struct fuse_file_info *fi);

    int bb_mknod(const char *path, mode_t mode, dev_t dev);

    int bb_rename(const char *path, const char *newpath);

    int bb_create(const char *path, mode_t mode, struct fuse_file_info *info);

    //int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi);

    int bb_readlink(const char *path, char *link, size_t size);

    int bb_unlink(const char *path);


    int bb_link(const char *path, const char *newpath);

    int bb_chmod(const char *path, mode_t mode);

    int bb_chown(const char *path, uid_t uid, gid_t gid);

    int bb_truncate(const char *path, off_t newsize);

    int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);


    bool bb_nametoprf(string &name, string &prf);

    bool bb_prftoname(string &prf, string &name);


}


#endif //BURNBOX_BURNBOXFS_H
