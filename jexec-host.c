#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/jail.h>

#include <jail.h>
#include <libelf.h>
#include <gelf.h>

/*
 * Chek if the given executable is dynamic
 */
static int is_dynamic(const char *executable) {
    size_t phnum = 0;
    int index = 0;
    int ret = 0;
    GElf_Phdr program_header;
    Elf *elf = NULL;
    int fd = -1;

    if ((fd = open(executable, O_RDONLY)) < 0)
        err(-1, "could not open executable");

    // Initialize libelf
    (void) elf_version(EV_CURRENT);

    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        warn("could not read ELF file");
        goto error;
    }

    if (elf_getphdrnum(elf, &phnum) != 0) {
        warn("could not read number of program headers");
        goto error;
    }

    for (index = 0; index < phnum; index ++) {
        if (gelf_getphdr(elf, index, &program_header) == NULL) {
            warn("could not get program header %i", index);
            goto error;
        }

        if (program_header.p_type == PT_DYNAMIC) {
            ret = 1;
            goto cleanup;
        }
    }

 cleanup:
    free(elf);
    return ret;

 error:
    free(elf);
    exit(-1);
}

static void jexec_static(int jid, char *const *argv, char *const *envp) {
    int fd = -1;

    if ((fd = open(argv[0], O_RDONLY | O_EXEC)) < 0)
        err(-1, "could not open static executable");

    if (jail_attach(jid) != 0)
        err(-1, "could not attach to jail");

    if (fexecve(fd, argv, envp) < 0)
        err(-1, "could not execute process");
}

static void jexec_dynamic(int jid, char *const *argv, char *const *envp) {
    errc(-1, ENOSYS, "Dynamic executables are not supported yet");
}

void jexec(int jid, char *const *argv, char *const *envp) {
    if (is_dynamic(argv[0]))
        jexec_dynamic(jid, argv, envp);
    else
        jexec_static(jid, argv, envp);
}

int main(int argc, char *const *argv, char *const *envp) {
    long jid = -1;

    if (argc < 3) {
        printf("usage: %s <jid> <command> <command arguments>\n", argv[0]);
        return -1;
    }

    if ((jid = jail_getid(argv[1])) == -1)
        errx(-1, "could not get JID (jail does not exist)");

    jexec(jid, &argv[2], envp);
}
