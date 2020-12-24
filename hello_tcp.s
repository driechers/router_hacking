.text            
.global _start
_start:
    mov r0, #1
    ldr r1, =message
    ldr r2, =len
    // Write
    mov r7, #4
    swi 0

    // domain AF_INET
    mov r0, #2
    // type SOCK_STREAM
    mov r1, #1
    // protocol
    mov r2, #0
    // socket system call
    mov r7, #0x119
    swi 0

    // socket fd in to r4
    mov r4, r0

    // sockaddr
    ldr r1, =servaddr
    // addrlen
    mov r2, #16
    // connect system call
    mov r7, #0x11b
    swi 0

    cmp r0, #0
    blt error

    // Write to socket
    mov r0, r4
    ldr r1, =message
    ldr r2, =len
    // Write
    mov r7, #4
    swi 0

    // exit
    mov r7, #1
    swi 0

error:
    mov r0, #2
    ldr r1, =errmessage
    ldr r2, =errlen
    // Write
    mov r7, #4
    swi 0

    // exit
    mov r7, #1
    swi 0

.data
message:
    .asciz "hello world\n"
len = .-message
errmessage:
    .asciz "failed to connect\n"
errlen = .-errmessage
servaddr:
    // AF_INET
    .ascii "\x02\x00"
    // port 4444
    .ascii "\x11\x5c"
    // 192.168.1.85
    .byte 192,168,1,85
    .byte 0,0,0,0,0,0,0,0
