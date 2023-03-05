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
    int *onetwo;
} file_info_t;

typedef struct file_hash_info {
    char *filename;
    off_t filesize;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *dirpath;
    int *onetwo;
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

int countfiles(char *path) {
    DIR *dir_ptr = NULL;
    struct dirent *direntp;
    char *npath;
    if (!path) return 0;
    if( (dir_ptr = opendir(path)) == NULL ) return 0;

    int count=0;
    while( (direntp = readdir(dir_ptr)))
    {
        if (strcmp(direntp->d_name,".")==0 ||
            strcmp(direntp->d_name,"..")==0) continue;
        switch (direntp->d_type) {
            case DT_REG:
                ++count;
                break;
            case DT_DIR:            
                npath=malloc(strlen(path)+strlen(direntp->d_name)+2);
                sprintf(npath,"%s/%s",path, direntp->d_name);
                count += countfiles(npath);
                free(npath);
                break;
        }
    }
    closedir(dir_ptr);
    return count;
}

int countdirs(char *path){
    DIR *dir = NULL;
    struct dirent *entry;
    char *npath;
    int count = 0;

    if (!(dir = opendir(path))) {  
        perror ("opendir-path not found");
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {  
        char *name = entry->d_name;
        if (entry->d_type == DT_DIR) {
            if (!strcmp(name, ".") || !strcmp(name, ".."))
                continue;
            count++;
            npath=malloc(strlen(path)+strlen(entry->d_name)+2);
            sprintf(npath,"%s/%s",path, entry->d_name);
            count += countdirs(npath);
            free(npath);
        }
    }
    closedir (dir); 
    return count;
}

int main(int argc, char *argv[]) {
    char debug_s[1024] = "";
    char *dir_one_path;
    DIR *dir_one;
    char *dir_two_path;
    DIR *dir_two;
    struct dirent *entry;
    struct stat statbuf;
    int file_limit = 800000;
    int i = 0, d = 0, j = 0, g = 0, total_dirs_one = 0, total_dirs_two = 0, dir_one_set = 0, dir_two_set = 0, total_files_one = 0, total_files_two = 0, num_files = 0, num_duplicates = 0, num_dirs_one = 0, num_dirs_two = 0;
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
	    } else if (dir_one_set == 0) {
		if ((dir_one = opendir(argv[f])) != NULL) {
		    dir_one_set = 1;
		    dir_one_path = argv[f];
		} else {
		    printf("Unknown argument: %s", argv[f]);
		    exit(EXIT_FAILURE);
		}
	    } else if (dir_two_set == 0 && dir_one_set == 1) {
		if ((dir_two = opendir(argv[f])) != NULL) {
		    dir_two_set = 1;
		    dir_two_path = argv[f];
		} else {
		    printf("Unknown argument: %s", argv[f]);
		    exit(EXIT_FAILURE);
		}
	    }
	}
	argv[1] = argv[argc-1];
    } else if ((dir_one = opendir(argv[1])) != NULL) {
	dir_one_set = 1;
	dir_one_path = argv[1];
    } else {
	printf("Unknown argument: %s", argv[1]);
	exit(EXIT_FAILURE);
    }

    total_dirs_one = countdirs(dir_one_path);
    printf("Total dirs found %d\n", total_dirs_one);
    total_files_one = countfiles(dir_one_path);
    printf("Total files found %d\n", total_files_one);
    
    if (dir_two_set == 1) {
        total_dirs_two = countdirs(dir_two_path);
	printf("Total dirs found %d\n", total_dirs_two);
        total_files_two = countfiles(dir_two_path);
	printf("Total files found %d\n", total_files_two);
    }
    
    file_info_t** file_info = (file_info_t**) malloc(total_files_one * sizeof(struct file_info));

    // Allocate memory for sub_dir
    char** sub_dir_one = (char**) malloc(total_dirs_one * MAX_FILENAME_LEN * sizeof(char*));
    for (int i = 0; i < total_dirs_one; i++) {
        sub_dir_one[i] = (char*) malloc(MAX_FILENAME_LEN * sizeof(char));
    }
    while ((entry = readdir(dir_one)) != NULL) {
        char path[MAX_FILENAME_LEN];
        snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_one_path, entry->d_name);
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
            file_info[num_files]->dirpath = dir_one_path;
            file_info[num_files]->onetwo = &dir_one_set;
            num_files++;
        } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            snprintf(sub_dir_one[num_dirs_one], MAX_FILENAME_LEN, "%s/%s", dir_one_path, entry->d_name);
	    num_dirs_one++;
        } else {
    	    char entry_d_name_string[255];
    	    sprintf(entry_d_name_string, "TYPE: %d  ERROR (FS TYPE CHECK): %s", entry->d_type, entry->d_name);
    	    debug_output(entry_d_name_string);
    	}
    }
    closedir(dir_one);
    while (d < num_dirs_one) {
        dir_one_path = sub_dir_one[d];
        if ((dir_one = opendir(dir_one_path)) == NULL) {
            debug_output("ERROR, opendir");
        }
        while ((entry = readdir(dir_one)) != NULL) {
            char path[MAX_FILENAME_LEN];
            snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_one_path, entry->d_name);
            if (lstat(path, &statbuf) == -1) {
                sprintf(debug_s, "ERROR, lstat; PATH: %s", path);
                debug_output(debug_s);
                continue;
            }
            if (S_ISREG(statbuf.st_mode)) {
                file_info[num_files] = (file_info_t *) malloc(sizeof(file_info_t));
                file_info[num_files]->filename = strdup(entry->d_name);
                file_info[num_files]->filesize = statbuf.st_size;
                file_info[num_files]->dirpath = dir_one_path;
        	file_info[num_files]->onetwo = &dir_one_set;
                num_files++;
            } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                snprintf(sub_dir_one[num_dirs_one], MAX_FILENAME_LEN, "%s/%s", dir_one_path, entry->d_name);
	        num_dirs_one++;
            } else {
    	        char entry_d_name_string[255];
    	        sprintf(entry_d_name_string, "ERROR (FS TYPE CHECK): %s", entry->d_name);
    	        debug_output(entry_d_name_string);
    	    }
        }
	
        closedir(dir_one);
        d++;
    }

    /// BEGIN DIR TWO
    if (dir_two_set == 1) {
	// Allocate memory for sub_dir
        char** sub_dir_two = (char**) malloc(total_dirs_two * MAX_FILENAME_LEN * sizeof(char*) + 1);
	for (int i = 0; i < total_dirs_two; i++) {
    	    sub_dir_two[i] = (char*) malloc(MAX_FILENAME_LEN * sizeof(char));
        }
        int two = 2;
        printf("BREAK 10\n");
	while ((entry = readdir(dir_two)) != NULL) {
	    printf("BREAK 20\n");
	    char path[MAX_FILENAME_LEN];
	    snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_two_path, entry->d_name);
	    printf("%s\n", path);
	    if (lstat(path, &statbuf) == -1) {
	        perror("lstat");
        	sprintf(debug_s, "PATH: %s", path);
                debug_output(debug_s);
	        continue;
	    }
	    printf("BREAK 30\n");
            if (S_ISREG(statbuf.st_mode)) {
		printf("BREAK 40\n");
	        file_info[num_files] = malloc(sizeof(struct file_info));
	        file_info[num_files]->filename = strdup(entry->d_name);
        	file_info[num_files]->filesize = statbuf.st_size;
                file_info[num_files]->dirpath = dir_two_path;
	        file_info[num_files]->onetwo = &two;
	        printf("path; %s, file; %s, onetwo; %d\n", file_info[num_files]->filename, file_info[num_files]->dirpath, *file_info[num_files]->onetwo);
	        num_files++;
            } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
		printf("BREAK 50\n");
	        snprintf(sub_dir_two[num_dirs_two], MAX_FILENAME_LEN, "%s/%s", dir_two_path, entry->d_name);
	        num_dirs_two++;
            } else {
		printf("BREAK 60\n");
		char entry_d_name_string[255];
	        sprintf(entry_d_name_string, "TYPE: %d  ERROR (FS TYPE CHECK): %s", entry->d_type, entry->d_name);
        	debug_output(entry_d_name_string);
	    }
	    printf("BREAK 70\n");
	}
        printf("BREAK 80\n");
	closedir(dir_two);
	d = 0;
        while (d < num_dirs_two) {
	    printf("BREAK 90\n");
	    dir_two_path = sub_dir_two[d];
	    if ((dir_two = opendir(dir_two_path)) == NULL) {
		debug_output("ERROR, opendir");
	    }
	    printf("BREAK 100\n");
	    while ((entry = readdir(dir_two)) != NULL) {
		printf("BREAK 110\n");
	        char path[MAX_FILENAME_LEN];
		snprintf(path, MAX_FILENAME_LEN, "%s/%s", dir_two_path, entry->d_name);
	        if (lstat(path, &statbuf) == -1) {
	            sprintf(debug_s, "ERROR, lstat; PATH: %s", path);
	            debug_output(debug_s);
		    continue;
	        }
	        if (S_ISREG(statbuf.st_mode)) {
		    printf("BREAK 120\n");
	            file_info[num_files] = (file_info_t *) malloc(sizeof(file_info_t));
		    file_info[num_files]->filename = strdup(entry->d_name);
		    file_info[num_files]->filesize = statbuf.st_size;
                    file_info[num_files]->dirpath = dir_two_path;
		    file_info[num_files]->onetwo = &two;
		    printf("path; %s, file; %s, onetwo; %d\n", file_info[num_files]->filename, file_info[num_files]->dirpath, *file_info[num_files]->onetwo);
		    num_files++;
                } else if (S_ISDIR(statbuf.st_mode) && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
		    printf("BREAK 130\n");
	            snprintf(sub_dir_two[num_dirs_two], MAX_FILENAME_LEN, "%s/%s", dir_two_path, entry->d_name);
	            num_dirs_two++;
		} else {
		    printf("BREAK 140\n");
		    char entry_d_name_string[255];
		    sprintf(entry_d_name_string, "ERROR (FS TYPE CHECK): %s", entry->d_name);
		    debug_output(entry_d_name_string);
		}
		printf("BREAK 150\n");
	    }
	    printf("BREAK 160\n");
	
	    closedir(dir_two);
	    d++;
	}
    }
    /// END OF DIR 2

    file_hash_info_t** file_hash_info = (file_hash_info_t**) malloc(num_files * sizeof(struct file_hash_info) + 1);
    qsort(file_info, num_files, sizeof(file_info_t *), compare_file_size);
    for (i = 0; i < num_files - 1; i++) {
        char path[MAX_FILENAME_LEN];
        file_hash_info[num_duplicates] = (file_hash_info_t *) malloc(sizeof(file_hash_info_t));
        file_hash_info[num_duplicates]->filename = strdup(file_info[i]->filename);
        file_hash_info[num_duplicates]->filesize = file_info[i]->filesize;
        file_hash_info[num_duplicates]->dirpath = file_info[i]->dirpath;
        file_hash_info[num_duplicates]->onetwo = file_info[i]->onetwo;
        //printf("[%d/%d] %d/%d HASHING: %s/%s\n", num_duplicates + 1, num_files, i, *file_info[i]->onetwo, file_info[i]->dirpath, file_info[i]->filename);
        printf("[%d/%d] %d/%d HASHING: %s/%s", num_duplicates + 1, num_files, i, *file_hash_info[num_duplicates]->onetwo, file_hash_info[num_duplicates]->dirpath, file_hash_info[num_duplicates]->filename);
        snprintf(path, MAX_FILENAME_LEN, "%s/%s", file_hash_info[num_duplicates]->dirpath, file_hash_info[num_duplicates]->filename);
        if (calculate_sha256_hash(path, file_hash_info[num_duplicates]->hash) == -1) {
            printf("Failed to calculate hash for %s\n", file_hash_info[num_duplicates]->filename);
        }
        num_duplicates++;
    }
    printf("BREAK A10\n");
    qsort(file_hash_info, num_duplicates, sizeof(file_hash_info_t *), compare_file_hash);
    int v = 1;
    int *vp = &v;
    printf("BREAK A20\n");
    for (i = 0; i < num_duplicates - 1; i++) {
	printf("BREAK A30\n");
        if (memcmp(file_hash_info[i]->hash, file_hash_info[i+1]->hash, SHA256_DIGEST_LENGTH) == 0) {
            /*char hash_s[SHA256_HASH_LEN] = "";
            char hash_t[SHA256_HASH_LEN] = "";
	    for (g = 0; g < SHA256_DIGEST_LENGTH; g++) {
		sprintf(hash_s, "%02x", file_hash_info[i+1]->hash[g]);
		strcat(hash_t, hash_s);
	    }
            char hash_r[SHA256_HASH_LEN] = "";
            char hash_u[SHA256_HASH_LEN] = "";
	    for (g = 0; g < SHA256_DIGEST_LENGTH; g++) {
		sprintf(hash_r, "%02x", file_hash_info[i]->hash[g]);
		strcat(hash_u, hash_r);
	    }
	    */
            sprintf(debug_s, "%d FILE: %s/%s  MATCHES", *file_hash_info[i]->onetwo, file_hash_info[i]->dirpath, file_hash_info[i]->filename);
            printf("%s\n", debug_s);
            sprintf(debug_s, "%d FILE: %s/%s", *file_hash_info[i+1]->onetwo, file_hash_info[i+1]->dirpath, file_hash_info[i+1]->filename);
            printf("%s\n", debug_s);
            sprintf(debug_s, "vp; %d, v; %d, onetwo; %d, remove_mode; %d", *vp, v, *file_hash_info[i]->onetwo, remove_mode);
            debug_output(debug_s);
            if (remove_mode == 1 && *file_hash_info[i]->onetwo == *vp) {
        	printf("IF TRUE");
        	char rem_file[MAX_FILENAME_LEN] = "";
        	snprintf(rem_file, MAX_FILENAME_LEN, "%s/%s", file_hash_info[i]->dirpath, file_hash_info[i]->filename);
        	remove(rem_file);
        	printf("Removed file: %s\n", rem_file);
    	    }
        }
	printf("BREAK A40\n");
    }
    for (i = 0; i < num_duplicates; i++) {
        free(file_hash_info[i]->filename);
        free(file_hash_info[i]);
    }

    for (i = 0; i < num_files; i++) {
        free(file_info[i]->filename);
        free(file_info[i]);
    }

    free(sub_dir_one[0]);
    free(sub_dir_one);
    return EXIT_SUCCESS;
}
