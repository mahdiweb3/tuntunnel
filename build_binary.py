"""Build Linux native launcher embedding the current Python manager; needs gcc and Python 3 at runtime."""
from pathlib import Path
import subprocess
import platform

if platform.system() != 'Linux' or platform.machine() != 'x86_64':
    raise SystemExit('Build this amd64 artifact on Linux x86-64.')

root = Path(__file__).resolve().parent
script = (root / 'tunnel-extra.sh').read_text()
body = script.split("<<'__TUNNEL_EXTRA_PY__'\n", 1)[1].rsplit('\n__TUNNEL_EXTRA_PY__', 1)[0]
body = "import os\n__file__ = os.environ['TE_SOURCE']\n" + body
payload = ','.join(str(b) for b in body.encode())
build = root / 'build'
build.mkdir(exist_ok=True)
c = build / 'launcher.c'
c.write_text('''#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
static const unsigned char script[] = {''' + payload + '''};
int main(int argc, char **argv) {
    char self[PATH_MAX], path[64];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (n < 0) { perror("readlink"); return 1; }
    self[n] = 0;
    if (setenv("TE_SOURCE", self, 1)) { perror("setenv"); return 1; }
    int fd = memfd_create("tuntunnel", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }
    int source = fcntl(fd, F_DUPFD, 4);
    if (source < 0) { perror("fcntl"); return 1; }
    close(fd);
    fd = source;
    if (dup2(STDIN_FILENO, 3) < 0) { perror("dup2"); return 1; }
    size_t offset = 0;
    while (offset < sizeof(script)) {
        ssize_t written = write(fd, script + offset, sizeof(script) - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { perror("write"); return 1; }
        offset += written;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) { perror("lseek"); return 1; }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char **args = calloc(argc + 2, sizeof(char *));
    if (!args) { perror("calloc"); return 1; }
    args[0] = "python3";
    args[1] = path;
    for (int i = 1; i < argc; ++i) args[i+1] = argv[i];
    execvp(args[0], args);
    perror("Python 3 is required");
    return 1;
}
''')
subprocess.run(['gcc', '-Os', '-s', '-Wall', '-Wextra', '-Werror', '-o', str(build / 'tuntunnel-linux-amd64'), str(c)], check=True)
print(build / 'tuntunnel-linux-amd64')
