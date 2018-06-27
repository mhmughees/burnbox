//
// Created by Haris Mughees on 3/13/18.
//


#include <string>

using std::string;

#include <unistd.h>

using namespace std;

#ifndef B2_UTIL_H
#define B2_UTIL_H


namespace util {

    inline bool FileExistsTest(const string &filename) {
        return (access(filename.c_str(), F_OK) == 0);
    }

    inline bool FileExistsTest(const char * filename) {
        return (access(filename, F_OK) == 0);
    }

    inline bool CreateFile(const string &filename, const string &err) {
        //utility function to create a file

        int fd = open(filename.data(), O_CREAT, 0666);
        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }

        close(fd);

        return true;
    }


    inline bool WrtieToFile(const string &filename, const string &data, const int &len, const string &err) {

        //always write whole after truncating the file


        int fd = open(filename.data(), O_TRUNC | O_WRONLY);


        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }
        if (write(fd, data.data(), len) != len) {
            printf("%s", err.data());
            return false;
        };
        return true;


    }


    inline bool WriteToFileEnd(const string &filename, const string &data, const int &len, const string &err) {

        //always write at the end

        int fd = open(filename.data(), O_APPEND | O_WRONLY);
        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }
        if (write(fd, data.data(), len) != len) {
            printf("%s", err.data());
            return false;
        };

        close(fd);
        return true;


    }


    inline bool WriteToFileIdx(const string &filename, const int &seek_offset, const string &data, const int &len,
                               const string &err) {

        //always write at the end

        int fd = open(filename.data(), O_WRONLY);
        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }

        lseek(fd, seek_offset, 0);

        if (write(fd, data.data(), len) != len) {
            printf("%s", err.data());
            return false;
        };
        close(fd);
        return true;


    }


    inline bool ReadFromFile(const string &filename, string &data, const string &err) {
        int fd = open(filename.data(), O_RDONLY);

        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }

        data.clear();
        char buff[100];
        int t = 0;

        do {
            t = (int) read(fd, buff, sizeof(buff));
            data.append(buff, sizeof(buff));

        } while (t > 0);

        close(fd);
        return true;

    };


    inline bool ReadFromFileIdx(const string &filename, const int &seek_offset, char *data, const int &len, const string &err) {
        int fd = open(filename.data(), O_RDONLY);

        if (fd < 0) {
            printf("%s", err.data());
            return false;
        }

        lseek(fd, seek_offset, 0);
        if (read(fd, data, len)< len){
            printf("%s", err.data());
            return false;
        };
        close(fd);
        return true;

    };


    template<class T>
    static void _structostr(const T &t, string &str) {
        string str_tmp((char *) &t, sizeof(T));
        str = str_tmp;
    };


/**
*
* @tparam T type of struct
* @param str string
* @param t struct output
*
* this function converts any str to struct. String should be valid
*/
    template<class T>
    static void _strtostruct(const string &str, T &t) {
        memcpy(&t, str.data(), str.size());
    };


};


#endif //B2_UTIL_H
