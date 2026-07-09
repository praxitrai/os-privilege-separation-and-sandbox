/*
 * authproto.h
 *
 * Shared wire format between frontend.c (untrusted-input collector) and
 * backend.c (privileged validator). Keeping this in one header ensures both
 * binaries agree on struct layout without either one linking the other.
 */
#ifndef AUTHPROTO_H
#define AUTHPROTO_H

#include <stdint.h>

#define AUTH_SOCK_PATH   "/tmp/authsvc/authsvc.sock"
#define AUTH_USER_MAX    32
#define AUTH_PASS_MAX    128

/* Request sent frontend -> backend. Fixed size, no pointers, no length
 * fields controlled by the sender that could be used to over-read memory.
 * The backend treats every byte of this as untrusted. */
typedef struct {
    uint32_t magic;                    /* protocol sanity check            */
    char     username[AUTH_USER_MAX];  /* NUL-terminated, backend enforces */
    char     password[AUTH_PASS_MAX];  /* NUL-terminated, backend enforces */
} auth_request_t;

/* Response sent backend -> frontend. */
typedef struct {
    uint32_t magic;
    int32_t  granted;      /* 1 = authenticated, 0 = denied              */
    int32_t  error_code;   /* 0 = ok, non-zero = protocol/policy error   */
    char     message[64];  /* short human-readable status, no secrets    */
} auth_response_t;



