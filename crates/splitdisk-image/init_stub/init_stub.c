/* Phase 5 /init stub: no libc — raw x86_64 Linux syscalls only.
 * Prints SPLITDISK_INIT_REACHED then sleeps forever.
 */
void _start(void) {
    const char msg[] = "SPLITDISK_INIT_REACHED\n";
    /* write(1, msg, len) */
    __asm__ volatile(
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $22, %%rdx\n"
        "syscall\n"
        :
        : "r"(msg)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory");
    /* write(2, msg, len) */
    __asm__ volatile(
        "mov $1, %%rax\n"
        "mov $2, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $22, %%rdx\n"
        "syscall\n"
        :
        : "r"(msg)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory");
    for (;;) {
        /* pause() */
        __asm__ volatile(
            "mov $34, %%rax\n"
            "syscall\n"
            :
            :
            : "rax", "rcx", "r11", "memory");
    }
}
