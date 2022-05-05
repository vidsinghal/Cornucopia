#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include "send_asm.h"

void mark_the_current_input_interesting();
void mark_the_current_input_uninteresting();
void set_input_weight(size_t weight);
static size_t callback(char *ptr, size_t size, size_t nmemb, void *userdata);
char *read_file(const char *fname);
char *get_asm_name_from_path(char *asm_path);
double send_asm_to_server(char *host, char *path_to_asm);

double returnVal = 0.0;

 static size_t callback(char *ptr, size_t size, size_t nmemb, void *userdata)
 {
   returnVal = atof(ptr);
   return size * nmemb;
 }

long get_file_size(const char *fname) {
    FILE *pFile;
    long lSize;
    size_t result;
    char *buffer;

    pFile = fopen(fname, "r");
    if (pFile == NULL)
    {
        fputs("File error", stderr);
        exit(1);
    }

    // obtain file size:
    fseek(pFile, 0, SEEK_END);
    lSize = ftell(pFile);
    rewind(pFile);

    // terminate
    fclose(pFile);
    return lSize;
}

char *read_file(const char *fname)
{

    FILE *pFile;
    long lSize = get_file_size(fname);
    size_t result;
    char *buffer;

    pFile = fopen(fname, "r");
    // allocate memory to contain the whole file:
    buffer = (char *)malloc(sizeof(char) * lSize);
    if (buffer == NULL)
    {
        fputs("Memory error", stderr);
        exit(2);
    }

    // copy the file into the buffer:
    result = fread(buffer, 1, lSize, pFile);
    if (result != lSize)
    {
        fputs("Reading error", stderr);
        exit(3);
    }

    // terminate
    fclose(pFile);
    return buffer;
}

char *get_asm_name_from_path(char *asm_path)
{
    char *ch = strtok(asm_path, "/");
    char *fname = asm_path;
    printf("%s\n", ch);
    while (ch != NULL)
    {
        fname = ch;
        ch = strtok(NULL, "/");
    }

    return fname;
}

double send_asm_to_server(char *host, char *path_to_asm)
{
    CURL *curl;
    CURLcode res;
    char url[2048];

    // get file size
    long file_size = get_file_size(path_to_asm);

    // copy content
    char *asm_content = read_file(path_to_asm);


    char *asm_fname = get_asm_name_from_path(path_to_asm);
    /* In windows, this will init the winsock stuff */
    /*curl_global_init(CURL_GLOBAL_ALL);*/

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl)
    {
        /* First set the URL that is about to receive our POST. This URL can
        just as well be a https:// URL if that is what should receive the
        data. */
        sprintf(url, "%s/upload/%s", host, asm_fname);
        // sprintf(url, "%s/", host);

        // headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: asm");

        // curl_easy_setopt(curlHandle, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // set url
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // set HTTP method to POST
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // set data size before copy
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, file_size);

        // set json data; I use EXACTLY the same string as in command line
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, asm_content);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);


        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    free(asm_content);

    return returnVal;
}

int main(int argc, char **argv) {
    
    char *input_file;
    char *host;
    
    if (argc < 3) {
        printf("Error: Expected: %s <path_to.s_file> <url_to_server>", argv[0]);
        return -1;
    }
    
    input_file = argv[1];
    
    //This is the url of the server
    host = argv[2];
    
    double is_file_interesting;
    
    is_file_interesting = send_asm_to_server(host, input_file);
    
    if (is_file_interesting > 0.0) {
        mark_the_current_input_interesting();
        set_input_weight(is_file_interesting);
    } else {
        mark_the_current_input_uninteresting();
    }
    
    return 0;
}
