//
// Created by Haris Mughees on 3/29/18.
//

#include "burnboxfs.h"


void burnboxfs::init_fuse_operations(fuse_operations *opt, bool xattr __attribute__((unused))) {

    memset(opt, 0, sizeof(*opt));

    opt->init = &burnboxfs::init;
    opt->getattr = &burnboxfs::getattr;
    opt->opendir = &bb_opendir;
    opt->readdir = &bb_readdir;
    opt->open = &bb_open;
    opt->mknod = &bb_mknod;
    opt->utime = &bb_utime;
    opt->read = &bb_read;
    opt->statfs = &bb_statfs;
    opt->fsync = &bb_fsync;
    opt->access = &bb_access;
    opt->chmod = &bb_chmod;

    opt->ftruncate = &bb_ftruncate;
    opt->fgetattr = &bb_fgetattr;
    opt->write = &bb_write;
    opt->release = &bb_release;
    //  opt->create = &bb_create;
    opt->readlink = &bb_readlink;
    opt->rename = &bb_rename;
    opt->chown = &bb_chown;
    opt->unlink = &bb_unlink;
    opt->link = &bb_link;
//
//    opt->releasedir = &bb_releasedir;
//
    opt->truncate = &bb_truncate;


}


bool burnboxfs::bb_nametoprf(string &name, string &fpath) {

    BurnboxApi *b1 = (BurnboxApi *) fuse_get_context()->private_data;

    string err, list;
    //b1->ListAllFiles(list, err);
    //printf("init->%s", list.data());

    string prf;
    if (strncmp(name.data(), "/", name.size()) != 0) {
        b1->NameToPrf(name, prf);
        if (name.empty()) {
            cout << "no prf entry for-->" << prf.data() << name.data() << endl;
            return false;
        }
        //first translate it to prf
    } else {
        prf = name;
    }


    transalte_path(prf, fpath);

    return true;


}

bool burnboxfs::bb_prftoname(string &prf, string &fpatth) {


    BurnboxApi *b1 = (BurnboxApi *) fuse_get_context()->private_data;

    string name;
    //first converting each prf to its corresponding name

    if (strncmp(name.data(), "/", name.size()) != 0) {
        b1->PrfToName(prf, name);

        if (name.empty()) {
            cout << "no name entry for-->" << prf.data() << name.data() << endl;
            return false;
        }
    } else {
        name = prf;
        //handling root directory
    }

    transalte_path(name, fpatth);
    return true;

}

bool burnboxfs::transalte_path(const string &path, string &fpath) {


    fpath = ENCCDIR;


    if (path.find("/") != 0) {


        fpath.append("/");


    };


    fpath.append(path.data());

    //cout << fpath.data() << endl;


    return true;
}


int burnboxfs::start_fs(int argc, char **argv) {

    bgdata *bkground_fs = new bgdata();

    bkground_fs->bgdir.clear();
    bkground_fs->bgdir.assign(ENCCDIR, sizeof(ENCCDIR));

    //sanity checks if directory exist

    sanity_check(bkground_fs->bgdir);

    fuse_operations operations;

    init_fuse_operations(&operations, false);

    fuse_main(argc, argv, &operations, bkground_fs);


//return fuse_main(argc, argv, &operations, NULL);
    return 0;

}


bool burnboxfs::sanity_check(const string &path) {

    boost::filesystem::path dir(path);
    if (boost::filesystem::create_directory(dir)) {
        std::cerr << "Directory Created: " << path.data() << std::endl;
    }


    return false;
}

void *burnboxfs::init(struct fuse_conn_info *conn __attribute__((unused))) {

    //bgdata *bkground_fs = (bgdata *) fuse_get_context()->private_data;

    BurnboxApi *b1 = new BurnboxApi();
    string err, list;
    b1->Init(err);

    cout << "init done" << endl;

    return b1;
}


int burnboxfs::getattr(const char *path, struct stat *statbuf) {

    string name, fpath;



    name.assign(path, PATH_MAX);

    transalte_path(name, fpath);
    int ret = lstat(fpath.data(), statbuf);

    statbuf->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
    statbuf->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
    statbuf->st_atime = time(NULL); // The last "a"ccess of the file/directory is right now
    statbuf->st_mtime = time(NULL); // The last "m"odification of the file/directory is right now

//    if ( strcmp( path, "/" ) == 0 )
//    {
//        statbuf->st_mode = S_IFDIR | 0755;
//        statbuf->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
//    }
//    else
//    {
//        statbuf->st_mode = S_IFREG | 0644;
//        statbuf->st_nlink = 1;
//        statbuf->st_size = 1024;
//    }

    return ret;

}


int burnboxfs::getattr2(const char *path, struct stat *statbuf __attribute__((unused))) {


    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    struct stat *mystbuf=NULL;


    int ret = lstat(
            "/Users/harismughees/Documents/Cornell_Research/Secure_Delete/c++implementation/b2/cmake-build-debug/src/newfuse/myfile.pdf",
            mystbuf);

    //mystbuf=mystbuf;

    cout << "hello hello-->" << fpath.c_str() << ret << endl;

    return ret;


}

int burnboxfs::bb_opendir(const char *path, struct fuse_file_info *fi) {

    //cout<<"opening directory"<<path<<endl;

    if (strncmp(path, "/", PATH_MAX) == 0) {

        string apath, fpath;

        apath.assign(path, PATH_MAX);

        transalte_path(apath, fpath);

        auto dp = opendir(fpath.data());


        fi->fh = (intptr_t) dp;

    }
    return 0;

}

int
burnboxfs::bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset __attribute__((unused)), struct fuse_file_info *fi) {

    if (strcmp(path, "/") == 0) {
        //only if root dir

        BurnboxApi *b1 = (BurnboxApi *) fuse_get_context()->private_data;

        (void)b1;

        DIR *dp;
        struct dirent *de;

        dp = (DIR *) fi->fh;

        de = readdir(dp);


        //filler(buf, de->d_name, NULL, 0);



        if (de == NULL) {
            //cerr << "error in dir entry: " << de << endl;
            return 0;
        }

        do {


            struct stat *statbuf;


            //if (getattr2(de->d_name, statbuf) == 0) {


            if (filler(buf, de->d_name, statbuf, 0) != 0) {
                cerr << "filler error in readdir" << endl;
                return -ENOMEM;

            }
            // }


        } while ((de = readdir(dp)) != NULL);

    }

    return 0;
}

int burnboxfs::bb_open(const char *path, struct fuse_file_info *fi) {


    //BurnboxApi *b1 = (BurnboxApi *) fuse_get_context()->private_data;

    cout << "open" << path << endl;

    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    int fd = open(fpath.data(), fi->flags);
    if (fd < 0) { cerr << "file can not be opened" << endl; }
    fi->fh = fd;


    return 0;
}

int burnboxfs::bb_utime(const char *path, struct utimbuf *ubuf) {

    //cout << "bb_utime" << endl;

    cout << "bb_utime" << "::>" << path << endl;

    string name, fpath;
    name.assign(path, PATH_MAX);


    transalte_path(name, fpath);

    utime(fpath.data(), ubuf);

    return 0;
}

int burnboxfs::bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {


    int retstat = 0;
    cout << "bb_read" << path << endl;


    if (pread(fi->fh, buf, size, offset) != (long)size) {
        cerr << "read error" << endl;
    };

    (void) retstat;

    return size;

}

int burnboxfs::bb_statfs(const char *path, struct statvfs *statv) {


    //cout<<"bb_statfs"<<"::>" <<path<<endl;
    //cout << "bb_statfs " << path << endl;
    string name, fpath;

    name.assign(path, PATH_MAX);

    transalte_path(name, fpath);


    statvfs(fpath.data(), statv);

    return 0;
}

int burnboxfs::bb_fsync(const char *path __attribute__((unused)), int datasync __attribute__((unused)), struct fuse_file_info *fi) {

    //cout << "bb_fsync" << endl;


    fsync(fi->fh);

    return 0;
}

int burnboxfs::bb_access(const char *path, int mask) {

    //cout<<"bb_access"<<"::>" <<path<<endl;


    string name, ppath, fpath;

    name.assign(path, PATH_MAX);
    transalte_path(name, fpath);

    if (strcmp(path, "/") != 0) {
        cout << "bb_access" << "::>" << path << "--" << access(fpath.data(), mask) << endl;
    }

    return access(fpath.data(), mask);
}

int burnboxfs::bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) {


    cout << "bb_ftruncate" << "::>" << path << endl;
    //cout << "bb_ftruncate" << endl;
    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    //access(fpath.data(), mask);

    ftruncate(fi->fh, offset);

    return 0;
}

int burnboxfs::bb_fgetattr(const char *path __attribute__((unused)), struct stat *statbuf, struct fuse_file_info *fi) {


    //cout << "bb_fgetattr" << endl;
    return fstat(fi->fh, statbuf);

}

int burnboxfs::bb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {


    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    int fd = open(path, O_WRONLY);

    (void)fd;



    if (pwrite(fi->fh, buf, size, offset) != (long)size) {
        cerr << "write is less than size. Might be an error" << endl;
        return 0;
    }
    return size;
}

int burnboxfs::bb_release(const char *path __attribute__((unused)), struct fuse_file_info *fi) {

    close(fi->fh);
    return 0;
}

int burnboxfs::bb_mknod(const char *path, mode_t mode, dev_t dev __attribute__((unused))) {


    cout << "bb_mknod" << "::>" << path << endl;


    string name, fpath;

    name.assign(path, PATH_MAX);

    transalte_path(name, fpath);


    if (S_ISREG(mode)) {
        open(fpath.data(), O_CREAT | O_EXCL | O_WRONLY, mode);

    }


    return 0;
}

int burnboxfs::bb_rename(const char *path __attribute__((unused)), const char *newpath __attribute__((unused))) {

    cout << "bb_rename" << endl;

    return 0;
}

int burnboxfs::bb_create(const char *path, mode_t mode, struct fuse_file_info *fi) {


    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    cout << "--->open" << endl;

    int fd = open(fpath.data(), O_CREAT | O_EXCL | O_WRONLY, mode);

    if (fd < 0) { cerr << "file can not be opened" << endl; }
    fi->fh = fd;

    return 0;
}

int burnboxfs::bb_readlink(const char *path, char *link, size_t size) {

    cout << "bb_readlink" << "::>" << path << endl;

    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    readlink(fpath.data(), link, size - 1);


    return 0;
}


int burnboxfs::bb_unlink(const char *path) {

    cout << "bb_unlink" << "::>" << path << endl;

    string name, fpath;
    name.assign(path, PATH_MAX);
    transalte_path(name, fpath);


    return unlink(fpath.data());
}

int burnboxfs::bb_link(const char *path __attribute__((unused)), const char *newpath __attribute__((unused))) {

    cout << "bb_link" << endl;
    return 0;
}

int burnboxfs::bb_chmod(const char *path, mode_t mode) {

    cout << "bb_chmod" << "::>" << path << endl;

    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    chmod(fpath.data(), mode);
    return 0;
}

int burnboxfs::bb_chown(const char *path, uid_t uid, gid_t gid) {

    cout << "bb_chown" << "::>" << path << endl;

    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    chown(fpath.data(), uid, gid);

    return 0;
}

int burnboxfs::bb_truncate(const char *path, off_t newsize) {


    cout << "bb_truncate" << "::>" << path << endl;
    string apath, fpath;

    apath.assign(path, PATH_MAX);

    transalte_path(apath, fpath);

    truncate(fpath.data(), newsize);

    return 0;
}

int burnboxfs::bb_setxattr(const char *path, const char *name __attribute__((unused)), const char *value __attribute__((unused)), size_t size __attribute__((unused)), int flags __attribute__((unused))) {

    cout << "bb_setxattr" << "::>" << path << endl;
    string apath, fpath;
    apath.assign(path, PATH_MAX);
    transalte_path(apath, fpath);


    return 0;
}

int burnboxfs::bb_releasedir(const char *path, struct fuse_file_info *fi) {

    cout << "bb_releasedir" << "::>" << path << endl;
    closedir((DIR *) (uintptr_t) fi->fh);

    return 0;
}


#ifdef HAVE_SYS_XATTR_H


int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_setxattr(path=\"%s\", name=\"%s\", value=\"%s\", size=%d, flags=0x%08x)\n",
        path, name, value, size, flags);
    bb_fullpath(fpath, path);

    return log_syscall("lsetxattr", lsetxattr(fpath, name, value, size, flags), 0);
}

/** Get extended attributes */
int bb_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_getxattr(path = \"%s\", name = \"%s\", value = 0x%08x, size = %d)\n",
        path, name, value, size);
    bb_fullpath(fpath, path);

    retstat = log_syscall("lgetxattr", lgetxattr(fpath, name, value, size), 0);
    if (retstat >= 0)
    log_msg("    value = \"%s\"\n", value);

    return retstat;
}

/** List extended attributes */
int bb_listxattr(const char *path, char *list, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char *ptr;

    log_msg("\nbb_listxattr(path=\"%s\", list=0x%08x, size=%d)\n",
        path, list, size
        );
    bb_fullpath(fpath, path);

    retstat = log_syscall("llistxattr", llistxattr(fpath, list, size), 0);
    if (retstat >= 0) {
    log_msg("    returned attributes (length %d):\n", retstat);
    if (list != NULL)
        for (ptr = list; ptr < list + retstat; ptr += strlen(ptr)+1)
        log_msg("    \"%s\"\n", ptr);
    else
        log_msg("    (null)\n");
    }

    return retstat;
}

/** Remove extended attributes */
int bb_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_removexattr(path=\"%s\", name=\"%s\")\n",
        path, name);
    bb_fullpath(fpath, path);

    return log_syscall("lremovexattr", lremovexattr(fpath, name), 0);
}


#endif





