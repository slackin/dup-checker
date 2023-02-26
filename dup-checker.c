#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define MAX_FILES 1024
#define MAX_FILENAME_LEN 256
#define SHA256_HASH_LEN 65

int verbose_out = 0, debug_out = 0, remove_mode = 0, future_mode = 0;

typedef struct file_info {
    char *filename;
    off_t filesize;
    char *dirpath;
} file_info_t;

typedef struct file_hash_info {
    char *filename;
    off_t filesize;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *dirpath;
} file_hash_info_t;

int compare_file_hash(const void *a, const void *b) {
    const file_hash_info_t *fa = *(const file_hash_info_t **)a;
    const file_hash_info_t *fb = *(const file_hash_info_t **)b;
    return strcmp(fa->hash, fb->hash);
}

int compare_file_size(const void *a, const void *b) {
    const file_info_t *fa = *(const file_info_t **)a;
    const file_info_t *fb = *(const file_info_t **)b;
    return (fa->filesize - fb->filesize);
}

void debug_output(const char *output) {
    if (debug_out == 1) {
	printf("DEBUG: %s\n", output);
    }
}

void verbose_output(const char *output) {
    if (verbose_out == 1 || debug_out == 1) {
	printf("VERB: %s\n", output);
    }
}

int calculate_sha256_hash(const char *filename, unsigned char hash[]) {
    int w = 0;
    FILE *file;
    SHA256_CTX sha256;
    unsigned char buffer[1024];
    int bytes_read, i;
    if ((file = fopen(filename, "rb")) == NULL) {
        perror("fopen");
        return -1;
    }
    SHA256_Init(&sha256);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
        if (w > 10000) {
    	    printf(".");
    	    w = 0;
    	    fflush(stdout);
    	} else {
    	    w++;
    	}
    }
    printf("\n");
    SHA256_Final(hash, &sha256);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    char debug_s[1024] = "";
    char *dir_path;
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    int file_limit = 800000;
    int i = 0, d = 0, j = 0, g = 0, num_files = 0, num_duplicates = 0, num_dirs = 0;
    file_info_t** file_info = (file_info_t**) malloc(file_limit * sizeof(struct file_info));
    if (argc < 2) {
        printf("Usage: %s directory_path\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Check for flags
    if (argc > 2) {
	for (int f = 1; f < argc; f++) {
	    if (strcmp(argv[f], "-d") == 0) {
		printf("DEBUG OUTPUT ENABLED.\n");
		debug_out = 1;
	    } else if (strcmp(argv[f], "-v") == 0) {
		printf("VERBOSE OUTPUT ENABLED.\n");
		verbose_out = 1;
	    } else if (strcmp(argv[f], "-r") == 0) {
		printf("REMOVE MODE ENABLED.\n");
		remove_mode = 1;
	    } else if (strcmp(argv[f], "-f") == 0) {
		printf("FUTURE MODE ENABLED.\n");
		future_mode = 1;
	    }
	}
	argv[1] = argv[argc-1];
    }

    dir_path = argv[1];
    if ((dir = opendir(dir_path)) == NULL) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }
    // Allocate memory for sub_dir
    char** sub_dir = (char**) malloc(file_limit * MAX_FILENAME_LEN * sizeof(char*));
    for (int i = 0; i < file_limit; i++) {
        sub_dir[i] = (char*) malloc(MAX_FILENAME_LEN * sizeof(char));
    }
    while ((entry = readdir(dir)) != NULL) {
        char path[MAX_FILENAME_LEN];
        snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_path, entry->d_name);
        if (lstat(path, &statbuf) == -1) {
            perror("lstat");
            sprintf(debug_s, "PATH: %s", path);
            debug_output(debug_s);
            continue;
        }
        if (S_ISREG(statbuf.st_mode)) {
            file_info[num_files] = malloc(sizeof(struct file_info));
            file_info[num_files]->filename = strdup(entry->d_name);
            file_info[num_files]->filesize = statbuf.st_size;
            file_info[num_files]->dirpath = dir_path;
            sprintf(debug_s, "HASHING: %s", file_info[num_files]->filename);
            debug_output(debug_s);
            sprintf(debug_s, "TYPE: %d  HASHING: %s/%s", entry->d_type, dir_path, file_info[num_files]->filename);
            debug_output(debug_s);
            /* SHA 256 HASH
            if (calculate_sha256_hash(path, file_info[num_files]->hash) == -1) {
                printf("Failed to calculate hash for %s\n", entry->d_name);
            }
            */
            num_files++;
        } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            snprintf(sub_dir[num_dirs], MAX_FILENAME_LEN, "%s/%s", dir_path, entry->d_name);
	    num_dirs++;
            sprintf(debug_s, "NUM: %d  DIR: %s", num_dirs, sub_dir[num_dirs]);
            debug_output(debug_s);
        } else {
    	    char entry_d_name_string[255];
    	    sprintf(entry_d_name_string, "TYPE: %d  ERROR (FS TYPE CHECK): %s", entry->d_type, entry->d_name);
    	    debug_output(entry_d_name_string);
    	}
    }
    sprintf(debug_s, "NUM_DIRS: %i", num_dirs);
    debug_output(debug_s);
    closedir(dir);
    debug_output("BREAK 1");
    while (d < num_dirs) {
	debug_output("BREAK 5");
        sprintf(debug_s, "DIR: %i  SUB_DIR: %s", d, sub_dir[d]);
        debug_output(debug_s);
        dir_path = sub_dir[d];
        sprintf(debug_s, "DIR_PATH: %s", dir_path);
        debug_output(debug_s);
        if ((dir = opendir(dir_path)) == NULL) {
            debug_output("ERROR, opendir");
        }
        while ((entry = readdir(dir)) != NULL) {
            char path[MAX_FILENAME_LEN];
            sprintf(debug_s, "PATH: %s DIR_PATH: %s", path, dir_path);
	    debug_output(debug_s);
            snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_path, entry->d_name);
            if (lstat(path, &statbuf) == -1) {
                sprintf(debug_s, "ERROR, lstat; PATH: %s", path);
                debug_output(debug_s);
                continue;
            }
            if (S_ISREG(statbuf.st_mode)) {
                file_info[num_files] = (file_info_t *) malloc(sizeof(file_info_t));
                file_info[num_files]->filename = strdup(entry->d_name);
                file_info[num_files]->filesize = statbuf.st_size;
                file_info[num_files]->dirpath = dir_path;
                sprintf(debug_s, "NUM_FILES: %d  FILING: %s", num_files, file_info[num_files]->filename);
                debug_output(debug_s);
                num_files++;
            } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                sprintf(debug_s, "dir_path; %s", dir_path);
                debug_output(debug_s);
                sprintf(debug_s, "sub_dir; %s", sub_dir[num_dirs]);
                debug_output(debug_s);
                sprintf(debug_s, "d_name; %s", entry->d_name);
                debug_output(debug_s);
                sprintf(debug_s, "num_dirs; %d", num_dirs);
                debug_output(debug_s);
                snprintf(sub_dir[num_dirs], MAX_FILENAME_LEN, "%s/%s", dir_path, entry->d_name);
	            num_dirs++;
            } else {
    	        char entry_d_name_string[255];
    	        sprintf(entry_d_name_string, "ERROR (FS TYPE CHECK): %s", entry->d_name);
    	        debug_output(entry_d_name_string);
    	    }
        }
	
        closedir(dir);
        d++;
    }
    file_hash_info_t** file_hash_info = (file_hash_info_t**) malloc(num_files * sizeof(struct file_hash_info) + 1);
    qsort(file_info, num_files, sizeof(file_info_t *), compare_file_size);
    for (i = 0; i < num_files - 1; i++) {
        char path[MAX_FILENAME_LEN];
	char file_size_str[32];
	char file_size_str_b[32];
	sprintf(file_size_str, "%ld", file_info[i+1]->filesize);
	sprintf(file_size_str_b, "%ld", file_info[i]->filesize);
        sprintf(debug_s, "fz_str: %s file; %s/%s", file_size_str, file_info[i+1]->dirpath, file_info[i+1]->filename);
        debug_output(debug_s);
        sprintf(debug_s, "fz_str: %s file; %s/%s", file_size_str_b, file_info[i]->dirpath,  file_info[i]->filename);
        debug_output(debug_s);
	
        //if (file_info[i]->filesize == file_info[i+1]->filesize) {
            file_hash_info[num_duplicates] = (file_hash_info_t *) malloc(sizeof(file_hash_info_t));
            file_hash_info[num_duplicates]->filename = strdup(file_info[i]->filename);
            file_hash_info[num_duplicates]->filesize = file_info[i]->filesize;
            file_hash_info[num_duplicates]->dirpath = file_info[i]->dirpath;
            sprintf(debug_s, "NUM_DUPS: %d  NEXT: %s/%s", num_duplicates, file_hash_info[num_duplicates]->dirpath, file_hash_info[num_duplicates]->filename);
            debug_output(debug_s);
	    // SHA 256 HASH
            sprintf(debug_s, "HASHING: %s/%s", file_hash_info[num_duplicates]->dirpath, file_hash_info[num_duplicates]->filename);
            verbose_output(debug_s);
            snprintf(path, MAX_FILENAME_LEN, "%s/%s", file_hash_info[num_duplicates]->dirpath, file_hash_info[num_duplicates]->filename);
            if (calculate_sha256_hash(path, file_hash_info[num_duplicates]->hash) == -1) {
                printf("Failed to calculate hash for %s\n", file_hash_info[num_duplicates]->filename);
            }
            
            num_duplicates++;
        //}
    }
    for (i = 0; i < num_files; i++) {
        free(file_info[i]->filename);
        free(file_info[i]);
    }

    qsort(file_hash_info, num_duplicates, sizeof(file_hash_info_t *), compare_file_hash);
    for (i = 0; i < num_duplicates - 1; i++) {
        sprintf(debug_s, "NUM_DUPS: %d  I: %d  COMP: %s/%s", num_duplicates, i, file_hash_info[i]->dirpath, file_hash_info[i]->filename);
        debug_output(debug_s);
        if (memcmp(file_hash_info[i]->hash, file_hash_info[i+1]->hash, SHA256_DIGEST_LENGTH) == 0) {
    	    sprintf(debug_s, "I: %d  FILE: %s", i, file_hash_info[i]->filename);
    	    //debug_output(debug_s);
            sprintf(debug_s, "I: %d  FILE: %s", i+1, file_hash_info[i+1]->filename);
            //debug_output(debug_s);
            char hash_s[SHA256_HASH_LEN] = "";
            char hash_t[SHA256_HASH_LEN] = "";
	    for (g = 0; g < SHA256_DIGEST_LENGTH; g++) {
		sprintf(hash_s, "%02x", file_hash_info[i+1]->hash[g]);
		strcat(hash_t, hash_s);
	    }
            char hash_r[SHA256_HASH_LEN] = "";
            char hash_u[SHA256_HASH_LEN] = "";
	    //printf("%s\n", hash_s);

	    //printf("hash_r; %s\n", hash_r);
	    for (g = 0; g < SHA256_DIGEST_LENGTH; g++) {
		sprintf(hash_r, "%02x", file_hash_info[i]->hash[g]);
		strcat(hash_u, hash_r);
	    }
	    //printf("hash_u; %s\n", hash_u);
	    //printf("%s\n", hash_r);
            sprintf(debug_s, "HASH: %s  FILE: %s/%s  MATCHES", hash_t, file_hash_info[i+1]->dirpath, file_hash_info[i+1]->filename);
            verbose_output(debug_s);
            sprintf(debug_s, "HASH: %s  FILE: %s/%s", hash_u, file_hash_info[i]->dirpath, file_hash_info[i]->filename);
            verbose_output(debug_s);
            if (remove_mode == 1) {
        	char rem_file[MAX_FILENAME_LEN] = "";
        	snprintf(rem_file, MAX_FILENAME_LEN, "%s/%s", file_hash_info[i]->dirpath, file_hash_info[i]->filename);
        	remove(rem_file);
        	printf("Removed file: %s\n", rem_file);
    	    }
        }
    }
    for (i = 0; i < num_duplicates; i++) {
        free(file_hash_info[i]->filename);
        free(file_hash_info[i]);
    }

    free(sub_dir[0]);
    free(sub_dir);
    return EXIT_SUCCESS;
}