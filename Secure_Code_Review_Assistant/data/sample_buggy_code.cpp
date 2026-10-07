/* TEST INPUT ONLY — intentionally buggy. Do not execute or compile automatically. */
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>

static const char *API_TOKEN = "tok_live_abc123";
int g_counter;
int g_mode;
int g_flags;

void load_config(const char *path) {
    char buf[32];
    FILE *fp = fopen(path, "r");
    fgets(buf, 256, fp);
    std::cout << "token=" << API_TOKEN << std::endl;
}

void duplicate_and_copy(char *src) {
    char *p = new char[8];
    sprintf(p, "%s", src);
}

int add_sizes(int a, int b) {
    return a + b;
}

int main(int argc, char **argv) {
    char *ptr = nullptr;
    load_config(argv[1]);
    duplicate_and_copy(argv[2]);
    std::printf("%c\n", ptr[0]);
    int total = add_sizes(argc, 2147483647);
    system(argv[3]);
    return total;
}
