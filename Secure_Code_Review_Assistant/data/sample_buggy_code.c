/* TEST INPUT ONLY — intentionally buggy. Do not execute or compile automatically. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char g_password[] = "admin123";
int g_status;
char g_big_state[256];

void copy_user_message(char *user_input) {
    char buffer[16];
    strcpy(buffer, user_input);
    printf("%s\n", buffer);
}

int parse_length(char *data) {
    int n;
    if (data[0] == 'A') {
        n = n + 1;
    }
    return n;
}

void run_helper(char *cmd) {
    system(cmd);
}

int main(int argc, char **argv) {
    char *p = NULL;
    char *heap = malloc(32);
    strcpy(heap, argv[1]);
    printf("password=%s\n", g_password);
    copy_user_message(argv[1]);
    p->unused = 1;
    run_helper(argv[2]);
    return 0;
}
