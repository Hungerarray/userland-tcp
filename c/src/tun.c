#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if_ether.h>

int tap_alloc(char *dev) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tap", O_RDWR)) < 0) {
    exit(-1);
  }
  ifr = (struct ifreq){
      .ifr_flags = IFF_TAP | IFF_NO_PI,
      // .ifr_flags = IFF_TUN | IFF_NO_PI,
  };
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    if (errno != 0) {
      close(fd);
      perror("[error]");
      return -1;
    }
  }
  strcpy(dev, ifr.ifr_name);

  fprintf(stdout, "successfully created tap device %s\n", dev);
  return fd;
}
