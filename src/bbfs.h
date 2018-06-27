//
// Created by Haris Mughees on 4/8/18.
//



//Ian: idea allow access to a file, default mode is not to allow

#ifndef BURNBOX_BBFS_H
#define BURNBOX_BBFS_H

#include "UtilCrypto.h"


namespace mymomo {
#define FILE_BLK_SZ 4096 ///reading 500 bytes
#define ENC_FILE_BLK_SZ (FILE_BLK_SZ+MAC_SIZE+AES::DEFAULT_BLOCKSIZE)
#define AUTH_DATA_SZ (MAC_SIZE+AES::DEFAULT_BLOCKSIZE)


    //per file context

    struct bb_fctx {
        int fd;            /* open file descriptor to backend file */
        off_t vsize;        /* virtual file size, without header/nonce */

    };

    void createprf(const char *path, string &prf);

    void getprf(const char *path, string &prf);

    void getname(const char *path, string &name);

    void rmvname(const char *path);

    void cal_underlying_sz(off_t underlying_size, off_t& actual_size);


    void create_master_key();

    int encrypted_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);


    size_t encrypted_read(const char *path,  char *buf, size_t size, off_t offset, struct fuse_file_info *fi);


    template <class Iterator, class T>
    inline bool is_all_zeros(Iterator begin, Iterator end, const T & value)
    {
        while (begin != end)
        {
            if (*begin != value)
                return false;
            ++begin;
        }
        return true;
    }


    void get_master_key(SecByteBlock key);

    int write_underlying(const char *path, const char *buf, size_t size, off_t offset,
                          struct fuse_file_info *fi);

    size_t read_underlying(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);


    void write_block(off_t block_number, const char *input, size_t size, struct fuse_file_info *fi);

    size_t read_block(off_t block_number, char *output, struct fuse_file_info *fi);

    size_t read_block(const char *path, off_t block_number, char *output);


    size_t read_block(off_t block_number, char *output, off_t begin, off_t end, struct fuse_file_info *fi);


    void read_then_write_block(const char *path, off_t block_number, const char *input, off_t begin, off_t end, struct fuse_file_info *fi);




    void *init(struct fuse_conn_info *conn);

    int bb_getattr(const char *path, struct stat *statbuf);

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

    int mymain(int argc, char *argv[]);

}
#endif //BURNBOX_BBFS_H
