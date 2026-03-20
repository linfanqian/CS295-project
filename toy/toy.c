/*
 * toy_parser.c — Toy packet parser for fuzzer evaluation
 *
 * Packet format:
 *   [1 byte magic: 0xAA] [1 byte cmd] [2 bytes length (LE)] [N bytes payload]
 *
 * PLANTED BUGS (9 total, covering all 4 target bug classes):
 *
 *   CLASS: Stack/Heap Buffer Overflow
 *     Bug 1 (cmd=0x01) — Stack buffer overflow         [AFL: easy]
 *     Bug 2 (cmd=0x02) — Heap buffer overflow behind 8-byte magic  [needs SymCC]
 *
 *   CLASS: Integer Overflow/Underflow
 *     Bug 3 (cmd=0x03) — Integer underflow → heap overflow [AFL: medium]
 *
 *   CLASS: Null Pointer / Uninitialized Memory Dereference
 *     Bug 4 (cmd=0x04) — Null pointer dereference      [AFL: easy]
 *
 *   CLASS: Use-After-Free / Double Free
 *     Bug 5 (cmd=0x05) — Use-after-free behind arithmetic constraint [needs SymCC]
 *     Bug 6 (cmd=0x06) — Double free                   [AFL: medium]
 *
 *   --- SymCC-targeted additions (XOR/AND constraints) ---
 *     Bug 7 (cmd=0x07) — Heap overflow behind XOR constraints        [needs SymCC]
 *     Bug 8 (cmd=0x08) — OOB read behind bitwise AND + arithmetic constraint [needs SymCC]
 *     Bug 9 (cmd=0x09) — Double free via XOR state transition        [needs SymCC]
 *
 * Difficulty design:
 *   Bugs 1, 4     — shallow, AFL finds by simple mutation             [LOW]
 *   Bugs 3, 6     — boundary/bit-pattern conditions, AFL finds slowly [MEDIUM]
 *   Bugs 2, 5     — multi-byte magic / arithmetic sum constraints     [HIGH, needs SymCC]
 *   Bugs 7, 8, 9  — XOR/AND cross-byte constraints, AFL cannot solve  [VERY HIGH, needs SymCC]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/* ------------------------------------------------------------------ */
/* Bug 1: STACK BUFFER OVERFLOW                                        */
/*                                                                     */
/* What: payload is copied into a fixed 64-byte stack buffer with no  */
/*       length check. Any length > 64 overflows into the stack.      */
/* How AFL finds it: simply mutates the 2-byte length field upward.   */
/* Difficulty: LOW                                                     */
/* ------------------------------------------------------------------ */
static void handle_cmd1(const uint8_t *payload, uint16_t length)
{
    char local_buf[64];
    /* BUG 1: memcpy with caller-controlled length into fixed stack buffer */
    memcpy(local_buf, payload, length);
    printf("CMD1: processed %u bytes\n", length);
}


/* ------------------------------------------------------------------ */
/* Bug 2: HEAP BUFFER OVERFLOW (behind 8-byte magic sequence)         */
/*                                                                     */
/* What: a 16-byte heap buffer is overflowed when the payload starts  */
/*       with the exact 8-byte sequence DE AD BE EF CA FE BA BE.      */
/* How AFL finds it: must guess all 8 bytes exactly — probability     */
/*       1/2^64, statistically impossible by random mutation.         */
/*       SymCC solves each byte equality constraint in sequence and   */
/*       generates the exact triggering input directly.               */
/* Difficulty: VERY HIGH (requires SymCC)                             */
/* ------------------------------------------------------------------ */
static void handle_cmd2(const uint8_t *payload, uint16_t length)
{
    if (length < 9) return;

    if (payload[0] == 0xDE && payload[1] == 0xAD &&
        payload[2] == 0xBE && payload[3] == 0xEF &&
        payload[4] == 0xCA && payload[5] == 0xFE &&
        payload[6] == 0xBA && payload[7] == 0xBE) {

        char *heap_buf = malloc(16);
        /* BUG 2: copies (length-8) bytes into a 16-byte heap buffer */
        memcpy(heap_buf, payload + 8, length - 8);
        free(heap_buf);
    }
}


/* ------------------------------------------------------------------ */
/* Bug 3: INTEGER UNDERFLOW → HEAP OVERFLOW                           */
/*                                                                     */
/* What: payload[0] is a claimed header size. Subtracting it from the */
/*       total length (both uint16_t) underflows when header_size >   */
/*       length, wrapping data_size to a huge value. malloc gets that  */
/*       huge size but the subsequent memcpy reads far out of bounds.  */
/* How AFL finds it: needs payload[0] > length byte, AFL reaches this  */
/*       by mutating the first payload byte above the length value.   */
/* Difficulty: MEDIUM                                                  */
/* ------------------------------------------------------------------ */
static void handle_cmd3(const uint8_t *payload, uint16_t length)
{
    if (length < 2) return;

    uint16_t header_size = payload[0];
    /* BUG 3: integer underflow — if header_size > length, data_size wraps
       to a large value (e.g. length=4, header_size=10 → data_size=65530) */
    uint16_t data_size = length - header_size;

    char *buf = malloc(data_size ? data_size : 1);
    memcpy(buf, payload + header_size, data_size);
    free(buf);
}


/* ------------------------------------------------------------------ */
/* Bug 4: NULL POINTER DEREFERENCE                                     */
/*                                                                     */
/* What: ptr is set to NULL when payload[0] == 0x5E, and is          */
/*       dereferenced without a NULL check, causing SIGSEGV.          */
/* How AFL finds it: must hit the exact byte value 0x5E (1 out of    */
/*       256). AFL can find this but takes longer than a range check. */
/* Difficulty: MEDIUM                                                  */
/* ------------------------------------------------------------------ */
static void handle_cmd4(const uint8_t *payload, uint16_t length)
{
    if (length < 1) return;
    static int val = 42;
    int *ptr = (payload[0] != 0x5E) ? &val : NULL;
    /* BUG 4: no NULL check — crashes with SIGSEGV when payload[0] == 0x5E */
    printf("CMD4: value = %d\n", *ptr);
}


/* ------------------------------------------------------------------ */
/* Bug 5: USE-AFTER-FREE (behind arithmetic constraints)              */
/*                                                                     */
/* What: a buffer is allocated, freed, then read from after the free. */
/*       Reachable only when:                                         */
/*         payload[0] == 'F'                  (equality check)        */
/*         payload[1] + payload[2] == 0xFF    (arithmetic constraint) */
/*         payload[3] == 0x42                 (equality check)        */
/* How AFL finds it: the arithmetic constraint payload[1]+payload[2]  */
/*       ==0xFF requires two bytes that sum to 255 — AFL cannot       */
/*       satisfy this by random mutation. SymCC models addition as a  */
/*       linear arithmetic constraint and solves it directly.         */
/* Difficulty: VERY HIGH (requires SymCC)                             */
/* ------------------------------------------------------------------ */
static void handle_cmd5(const uint8_t *payload, uint16_t length)
{
    if (length < 5) return;

    /* Three chained constraints — SymCC solves all three; AFL cannot */
    if (payload[0] == 'F' &&
        (uint8_t)(payload[1] + payload[2]) == 0xFF &&
        payload[3] == 0x42) {

        char *buf = malloc(32);
        snprintf(buf, 32, "processing: %.20s", (const char *)payload + 4);
        free(buf);
        /* BUG 5: use-after-free — reads from freed buffer */
        printf("CMD5: %s\n", buf);
    }
}


/* ------------------------------------------------------------------ */
/* Bug 6: DOUBLE FREE                                                  */
/*                                                                     */
/* What: buf is conditionally freed twice. When payload[0] has both   */
/*       bit 4 and bit 7 set (i.e. payload[0] & 0x90 == 0x90), the   */
/*       two independent if-branches each call free(buf).             */
/* How AFL finds it: mutates payload[0] until bits 4+7 are both set   */
/*       (values like 0x90, 0x91, 0x92, ...). Medium difficulty.     */
/* Difficulty: MEDIUM                                                  */
/* ------------------------------------------------------------------ */
static void handle_cmd6(const uint8_t *payload, uint16_t length)
{
    if (length < 3) return;

    char *buf = malloc(64);
    uint16_t copy_len = (length - 2 > 64) ? 64 : length - 2;
    memcpy(buf, payload + 2, copy_len);

    /* BUG 6: double free when both bit 4 and bit 7 of payload[0] are set */
    if (payload[0] & 0x10) free(buf);
    if (payload[0] & 0x80) free(buf);

    if (!(payload[0] & 0x10) && !(payload[0] & 0x80)) free(buf);
}


/* ------------------------------------------------------------------ */
/* Bug 7: HEAP BUFFER OVERFLOW (behind XOR constraints)               */
/*                                                                     */
/* What: a small 8-byte heap buffer is overflowed. Reachable only     */
/*       when two XOR conditions are satisfied simultaneously:         */
/*         payload[0] ^ payload[1] == 0xAA                            */
/*         payload[2] ^ payload[3] == 0x55                            */
/* Why AFL fails: flipping any bit in payload[0] changes the XOR      */
/*       result unpredictably — AFL has no way to satisfy both XOR    */
/*       conditions at once through random mutation.                   */
/* Why SymCC succeeds: XOR is a standard bitwise constraint in Z3.    */
/*       SymCC picks payload[0]=0xFF, solves payload[1]=0xFF^0xAA,    */
/*       then solves payload[2]/[3] the same way. Direct solution.    */
/* Difficulty: VERY HIGH (requires SymCC)                             */
/* ------------------------------------------------------------------ */
static void handle_cmd7(const uint8_t *payload, uint16_t length)
{
    if (length < 5) return;

    if ((payload[0] ^ payload[1]) == 0xAA &&
        (payload[2] ^ payload[3]) == 0x55) {

        char *buf = malloc(8);
        /* BUG 7: copies up to length-4 bytes into an 8-byte heap buffer */
        memcpy(buf, payload + 4, length - 4);
        free(buf);
    }
}


/* ------------------------------------------------------------------ */
/* Bug 8: OUT-OF-BOUNDS READ (behind bitwise AND + arithmetic gate)   */
/*                                                                     */
/* What: payload[3] is used as an index into a 4-element array with   */
/*       no bounds check. Any index >= 4 reads out of bounds.         */
/*       Reachable only when two conditions are both satisfied:        */
/*         (1) (payload[0] & payload[1]) == 0x3C  (AND constraint)    */
/*         (2) payload[2] + 0x2E == 0x63          (arithmetic gate)   */
/*             i.e. payload[2] must be exactly 0x35                   */
/* Why AFL fails: condition (1) requires specific bits set in BOTH    */
/*       payload[0] and payload[1] simultaneously. AFL mutates bytes  */
/*       independently and cannot coordinate the AND relationship.    */
/* Why SymCC succeeds: SymCC models both constraints symbolically.    */
/*       It sets payload[0]=0xFF, solves payload[1]=0x3C for the AND, */
/*       sets payload[2]=0x35 (satisfies == 0x63), and sets           */
/*       payload[3]=5 to trigger the OOB read.                        */
/* Difficulty: VERY HIGH (requires SymCC)                             */
/* ------------------------------------------------------------------ */
static void handle_cmd8(const uint8_t *payload, uint16_t length)
{
    if (length < 4) return;

    static int table[4] = {10, 20, 30, 40};

    /* Bitwise AND constraint — AFL cannot coordinate two bytes to satisfy this */
    if ((payload[0] & payload[1]) == 0x3C) {
        if ((payload[2] + 0x2E) == 0x63) {
            /* BUG 8: no bounds check — any payload[3] >= 4 reads out of bounds */
            printf("CMD8: table[%u] = %d\n", payload[3], table[payload[3]]);
        }        
    }
}


/* ------------------------------------------------------------------ */
/* Bug 9: DOUBLE FREE (behind XOR state transition)                   */
/*                                                                     */
/* What: a buffer is allocated and immediately freed (step 1), then   */
/*       freed a second time if two more constraints are satisfied,   */
/*       causing a double free. Three conditions must all hold:       */
/*       Step 1: payload[0] == 'Z'         (enter active state,      */
/*               buf is allocated and freed here)                     */
/*       Step 2: payload[1] ^ payload[0] == 0x1B  (XOR transition)   */
/*               i.e. payload[1] must equal 'Z'^0x1B == 0x41 ('A')   */
/*       Step 3: (payload[2] & payload[3]) == 0x57  (AND constraint)  */
/*               e.g. payload[2]=0xFF, payload[3]=0x57                */
/* Why AFL fails: Steps 2 and 3 require coordinated byte values.      */
/*       AFL mutates bytes independently and cannot satisfy the XOR   */
/*       relationship between payload[0] and payload[1], nor the      */
/*       combined payload[2]/payload[3] AND condition.                */
/* Why SymCC succeeds: solves payload[0]=='Z', then payload[1] via    */
/*       XOR equation, then solves payload[2] & payload[3] == 0x57,  */
/*       reaching the double free in one pass.                        */
/* Difficulty: VERY HIGH (requires SymCC)                             */
/* ------------------------------------------------------------------ */
static void handle_cmd9(const uint8_t *payload, uint16_t length)
{
    if (length < 4) return;

    /* Step 1: enter active state */
    if (payload[0] == 'Z') {
        char *buf = malloc(32);
        free(buf);
        /* Step 2: XOR transition — payload[1] must be 'Z' ^ 0x1B = 'A' */
        if ((payload[1] ^ payload[0]) == 0x1B) {
            if ((payload[2] & payload[3]) != 0x57) {
                return;
            } else {
                /* BUG 9: double free — buf already freed in step 1 */
                free(buf);
            }
        }
    }
}


/* ------------------------------------------------------------------ */
/* Top-level parser                                                    */
/* ------------------------------------------------------------------ */
static int parse_packet(const uint8_t *data, size_t size)
{
    if (size < 4) return -1;

    if (data[0] != 0xAA) return -1;

    uint8_t  cmd    = data[1];
    uint16_t length = (uint16_t)(data[2]) | ((uint16_t)(data[3]) << 8);

    if (size < (size_t)(4 + length)) return -1;

    const uint8_t *payload = data + 4;

    switch (cmd) {
        case 0x01: handle_cmd1(payload, length); break;
        case 0x02: handle_cmd2(payload, length); break;
        case 0x03: handle_cmd3(payload, length); break;
        case 0x04: handle_cmd4(payload, length); break;
        case 0x05: handle_cmd5(payload, length); break;
        case 0x06: handle_cmd6(payload, length); break;
        case 0x07: handle_cmd7(payload, length); break;
        case 0x08: handle_cmd8(payload, length); break;
        case 0x09: handle_cmd9(payload, length); break;
        default:
            printf("Unknown cmd: 0x%02x\n", cmd);
            break;
    }

    return 0;
}


int main(void)
{
    uint8_t buf[65536];
    size_t  n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) return 1;

    parse_packet(buf, n);
    return 0;
}
