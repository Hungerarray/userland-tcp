#include "includes/tun.h"
#include <stdio.h>
#include <unistd.h>

int main() {
    char dev_name[20] = "tun1";
    int tund = tap_alloc(dev_name);
    sleep(20);
}