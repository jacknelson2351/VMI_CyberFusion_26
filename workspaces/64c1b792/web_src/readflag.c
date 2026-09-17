#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
  clearenv();

  if (setgid(0) != 0)
    err(1, "setgid");
  if (setuid(0) != 0)
    err(1, "setuid");

  if (argc != 2 ||
      strcmp(argv[1], "could you please give me the flag thank you so much") !=
          0) {
    printf("Access denied\n");
    return 1;
  }

  int fd = open("/flag.txt", O_RDONLY | O_NOFOLLOW);
  if (fd < 0)
    err(1, "open(/flag.txt)");

  char buf[4096];
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0)
    err(1, "read(flag)");

  if (write(STDOUT_FILENO, buf, n) != n)
    err(1, "write(stdout)");
  close(fd);
  return 0;
}
