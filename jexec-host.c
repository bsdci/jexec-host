#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/elf.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <gelf.h>
#include <jail.h>
#include <libelf.h>

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
    close(fd);
    return ret;

 error:
    free(elf);
    close(fd);
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

typedef void (*func_ptr_type)(void);
typedef func_ptr_type (*_rtld_t)(Elf_Addr *sp, func_ptr_type *exit_proc, void **objp);

static void jexec_dynamic(int jid, char *const *argv, char *const *envp) {
#ifdef __x86_64__
    int fd = -1; /* File descriptor to the target executable */
    int loader_fd = -1;
    struct stat st;
    void *loader = MAP_FAILED;
    void *ld_elf; /* handle to the rtld */
    _rtld_t rtld = NULL; /* the rtld main function */

    /*
     * TODO: Implement loader.
     * 0. map ld-elf.so.1 somewhere R-X (does dlopen do this?)
     */

    if ((loader_fd = open("/libexec/ld-elf.so.1", O_RDONLY | O_EXEC)) < 0)
        err(-1, "could not open loader");

    if ((ld_elf = dlopen("/libexec/ld-elf.so.1", RTLD_NOW)) == NULL)
        err(-1, "could not fdlopen loader: %s", dlerror());

    if ((rtld = dlsym(ld_elf, "_rtld")) == NULL)
        err(-1, "could not find loader entry point: %s", dlerror());

    if (fstat(loader_fd, &st) != 0)
        err(-1, "could not stat loader");

    loader = mmap(NULL, st.st_size, PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (loader == MAP_FAILED)
        err(-1, "could not map loader");

    /*
     * 1. create new stack
     */

    /*
     * 2. set up auxinfo
     *    necessary:
     *    - auxp[AT_BASE] should point to interpreter
     *    - auxp[AT_EXECFD] should be the file descriptor of the executable
     *    - auxp[AT_PAGESIZES] == NULL, so that rtld queries sysctl hw.pagesize(s)
     *    optional:
     *    - auxp[AT_OSRELDATE]
     *    - auxp[AT_STACKPROT]
     */
    Elf_Auxinfo auxinfo [6] = {
        { .a_type = AT_BASE,
          .a_un.a_ptr = loader },
        { .a_type = AT_EXECFD,
          .a_un.a_val = fd },
        { .a_type = AT_PAGESIZES,
          .a_un.a_ptr = NULL },
        /* FIXME: get these */
        { .a_type = AT_OSRELDATE,
          .a_un.a_ptr = NULL },
        { .a_type = AT_STACKPROT,
          .a_un.a_ptr = NULL },
        { .a_type = AT_NULL,
          .a_un.a_ptr = NULL },
    };

    /*
     * 3. copy over envp, argv, argc
     */

    dlclose(ld_elf);
#endif

    errc(-1, ENOSYS, "Dynamic executables are not supported yet on this architecture");
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
