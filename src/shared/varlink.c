/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/poll.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"
#include "socket-util.h"
#include "strv.h"
#include "time-util.h"
#include "user-util.h"
#include "varlink-validate.h"
#include "varlink.h"

#define VARLINK_DEFAULT_TIMEOUT_USEC (45U*USEC_PER_SEC)
#define VARLINK_BUFFER_MAX (16U*1024U*1024U)
#define VARLINK_READ_SIZE (64U*1024U)

typedef enum VarlinkState {
        /* Client side states */
        VARLINK_IDLE_CLIENT,
        VARLINK_AWAITING_REPLY,
        VARLINK_CALLING,
        VARLINK_CALLED,
        VARLINK_PROCESSING_REPLY,

        /* Server side states */
        VARLINK_IDLE_SERVER,
        VARLINK_PROCESSING_METHOD,
        VARLINK_PROCESSING_METHOD_MORE,
        VARLINK_PROCESSING_METHOD_ONEWAY,
        VARLINK_PROCESSED_METHOD,
        VARLINK_PROCESSED_METHOD_MORE,
        VARLINK_PENDING_METHOD,
        VARLINK_PENDING_METHOD_MORE,

        /* Common states (only during shutdown) */
        VARLINK_PENDING_DISCONNECT,
        VARLINK_PENDING_TIMEOUT,
        VARLINK_PROCESSING_DISCONNECT,
        VARLINK_PROCESSING_TIMEOUT,
        VARLINK_PROCESSING_FAILURE,
        VARLINK_DISCONNECTED,
} VarlinkState;

#define VARLINK_STATE_IS_CONNECTED(state)               \
        IN_SET(state,                                   \
               VARLINK_IDLE_CLIENT,                     \
               VARLINK_AWAITING_REPLY,                  \
               VARLINK_CALLING,                         \
               VARLINK_CALLED,                          \
               VARLINK_PROCESSING_REPLY,                \
               VARLINK_PROCESSING_FAILURE,              \
               VARLINK_IDLE_SERVER,                     \
               VARLINK_PROCESSING_METHOD,               \
               VARLINK_PROCESSING_METHOD_MORE,          \
               VARLINK_PROCESSED_METHOD,                \
               VARLINK_PROCESSED_METHOD_MORE)

struct Varlink {
        unsigned n_ref;

        VarlinkServer *server;

        VarlinkState state;
        unsigned n_pending;

        Set *groups;

        int fd;

        char *input_buffer;
        size_t input_buffer_allocated;
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned;

        char *output_buffer;
        size_t output_buffer_allocated;
        size_t output_buffer_size;
        size_t output_buffer_index;

        VarlinkReply reply_callback;

        JsonVariant *current;
        JsonVariant *reply;

        VarlinkConcept *method_concept;

        struct ucred ucred;
        bool ucred_acquired:1;

        bool write_disconnected:1;

        usec_t timestamp;
        usec_t timeout;

        void *userdata;

        sd_event *event;
        sd_event_source *io_event_source;
        sd_event_source *time_event_source;
        sd_event_source *quit_event_source;
        sd_event_source *defer_event_source;
};

typedef struct VarlinkServerSocket VarlinkServerSocket;

struct VarlinkServerSocket {
        VarlinkServer *server;

        int fd;
        char *address;

        sd_event_source *event_source;

        LIST_FIELDS(VarlinkServerSocket, sockets);
};

struct VarlinkServer {
        unsigned n_ref;

        LIST_HEAD(VarlinkServerSocket, sockets);

        Hashmap *methods;
        VarlinkConnect connect_callback;

        sd_event *event;

        void *userdata;

        char **interfaces;
        VarlinkValidator *validator;
};

/* struct VarlinkGroup { */
/*         unsigned n_ref; */

/*         Hashmap *links; */

/*         void *userdata; */

/*         VarlinkGroupEmpty empty; */
/* }; */

static int varlink_new(Varlink **ret) {
        Varlink *v;

        assert(ret);

        v = new0(Varlink, 1);
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->fd = -1;

        v->ucred.uid = UID_INVALID;
        v->ucred.gid = GID_INVALID;

        v->timestamp = USEC_INFINITY;
        v->timeout = VARLINK_DEFAULT_TIMEOUT_USEC;

        *ret = v;
        return 0;
}

int varlink_connect_address(Varlink **ret, const char *address) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sockaddr = {
                .sa.sa_family = AF_UNIX,
        };
        int r;

        assert_return(ret, -EINVAL);
        assert_return(address, -EINVAL);

        if (strlen(address) > sizeof(sockaddr.un.sun_path))
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        strncpy(sockaddr.un.sun_path, address, sizeof(sockaddr.un.sun_path));

        if (connect(fd, &sockaddr.sa, SOCKADDR_UN_LEN(sockaddr.un)) < 0)
                return -errno;

        r = varlink_connect_fd(ret, fd);
        if (r < 0)
                return r;

        fd = -1;
        return r;
}

int varlink_connect_fd(Varlink **ret, int fd) {
        Varlink *v;
        int r;

        assert(ret);
        assert(fd >= 0);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = varlink_new(&v);
        if (r < 0)
                return r;

        v->fd = fd;
        v->state = VARLINK_IDLE_CLIENT;

        *ret = v;

        return 0;
}

Varlink* varlink_ref(Varlink *v) {
        if (!v)
                return NULL;

        assert(v->n_ref > 0);
        v->n_ref++;

        return v;
}

static void varlink_detach_groups(Varlink *v) {
        assert(v);

        v->groups = set_free(v->groups);
}

static void varlink_detach_event_sources(Varlink *v) {

        if (v->io_event_source) {
                (void) sd_event_source_set_enabled(v->io_event_source, SD_EVENT_OFF);
                v->io_event_source = sd_event_source_unref(v->io_event_source);
        }

        if (v->time_event_source) {
                (void) sd_event_source_set_enabled(v->time_event_source, SD_EVENT_OFF);
                v->time_event_source = sd_event_source_unref(v->time_event_source);
        }

        if (v->quit_event_source) {
                (void) sd_event_source_set_enabled(v->quit_event_source, SD_EVENT_OFF);
                v->quit_event_source = sd_event_source_unref(v->quit_event_source);
        }

        if (v->defer_event_source) {
                (void) sd_event_source_set_enabled(v->defer_event_source, SD_EVENT_OFF);
                v->defer_event_source = sd_event_source_unref(v->defer_event_source);
        }
}

static Varlink* varlink_destroy(Varlink *v) {
        if (!v)
                return NULL;

        varlink_detach_event_sources(v);

        varlink_detach_groups(v);
        varlink_server_unref(v->server);

        safe_close(v->fd);

        free(v->input_buffer);
        free(v->output_buffer);

        json_variant_unref(v->current);
        json_variant_unref(v->reply);

        sd_event_unref(v->event);

        return mfree(v);
}

Varlink* varlink_unref(Varlink *v) {
        if (!v)
                return NULL;

        assert(v->n_ref > 0);
        v->n_ref--;

        if (v->n_ref > 0)
                return NULL;

        return varlink_destroy(v);
}

static void varlink_set_state(Varlink *v, VarlinkState state) {
        assert(v);

        v->state = state;
}

static int varlink_write(Varlink *v) {
        ssize_t n;

        assert(v);

        if (!VARLINK_STATE_IS_CONNECTED(v->state))
                return 0;
        if (v->output_buffer_size == 0)
                return 0;
        if (v->write_disconnected)
                return 0;

        assert(v->fd >= 0);

        n = write(v->fd, v->output_buffer + v->output_buffer_index, v->output_buffer_size);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        /* If we get informed about a disconnect on write, then let's remember that, but not act on it
                         * just yet. Let's wait for read() to report the issue first. */
                        v->write_disconnected = true;
                        return 0;
                }

                return -errno;
        }

        v->output_buffer_size -= n;

        if (v->output_buffer_size == 0)
                v->output_buffer_index = 0;
        else
                v->output_buffer_index += n;

        v->timestamp = now(CLOCK_MONOTONIC);
        return 1;
}

static int varlink_read(Varlink *v) {
        size_t rs;
        ssize_t n;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_CALLING, VARLINK_IDLE_SERVER))
                return 0;
        if (v->current)
                return 0;
        if (v->input_buffer_unscanned > 0)
                return 0;

        if (v->input_buffer_size >= VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        assert(v->fd >= 0);

        if (v->input_buffer_allocated <= v->input_buffer_index + v->input_buffer_size) {
                size_t add;

                add = MIN(VARLINK_BUFFER_MAX - v->input_buffer_size, VARLINK_READ_SIZE);

                if (v->input_buffer_index == 0) {

                        if (!GREEDY_REALLOC(v->input_buffer, v->input_buffer_allocated, v->input_buffer_size + add))
                                return -ENOMEM;

                } else {
                        char *b;

                        b = new(char, v->input_buffer_size + add);
                        if (!b)
                                return -ENOMEM;

                        memcpy(b, v->input_buffer + v->input_buffer_index, v->input_buffer_size);

                        free(v->input_buffer);
                        v->input_buffer = b;

                        v->input_buffer_allocated = v->input_buffer_size + add;
                        v->input_buffer_index = 0;
                }
        }

        rs = v->input_buffer_allocated - (v->input_buffer_index + v->input_buffer_size);

        n = read(v->fd, v->input_buffer + v->input_buffer_index + v->input_buffer_size, rs);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        varlink_set_state(v, VARLINK_PENDING_DISCONNECT);
                        return 1;
                }

                return -errno;
        }

        v->input_buffer_size += n;
        v->input_buffer_unscanned += n;

        return 1;
}

static int varlink_parse_message(Varlink *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        const char *e;
        size_t sz;
        int r;

        assert(v);

        if (v->current)
                return 0;
        if (v->input_buffer_unscanned <= 0)
                return 0;

        e = memchr(v->input_buffer + v->input_buffer_index + v->input_buffer_size - v->input_buffer_unscanned, 0, v->input_buffer_unscanned);
        if (!e) {
                v->input_buffer_unscanned = 0;
                return 0;
        }

        sz = e - (v->input_buffer + v->input_buffer_index) + 1;

        log_debug("New incoming message: %s", v->input_buffer + v->input_buffer_index);

        r = json_parse(v->input_buffer + v->input_buffer_index, &v->current, NULL);
        if (r < 0)
                return r;

        v->input_buffer_size -= sz;

        if (v->input_buffer_size == 0)
                v->input_buffer_index = 0;
        else
                v->input_buffer_index += sz;

        v->input_buffer_unscanned -= sz;

        return 1;
}

static int varlink_test_timeout(Varlink *v) {
        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_CALLING))
                return 0;
        if (v->timeout == USEC_INFINITY)
                return 0;

        if (now(CLOCK_MONOTONIC) < usec_add(v->timestamp, v->timeout))
                return 0;

        varlink_set_state(v, VARLINK_PENDING_TIMEOUT);

        return 1;
}

static int varlink_dispatch_local_error(Varlink *v, const char *error) {
        int r;

        assert(v);
        assert(error);

        if (!v->reply_callback)
                return 0;

        r = v->reply_callback(v, NULL, error, VARLINK_REPLY_ERROR|VARLINK_REPLY_LOCAL, v->userdata);
        if (r < 0)
                log_debug_errno(r, "Reply callback returned error, ignoring: %m");

        return 1;
}

static int varlink_dispatch_timeout(Varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_TIMEOUT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_TIMEOUT);
        varlink_dispatch_local_error(v, VARLINK_ERROR_TIMEOUT);
        varlink_close(v);

        return 1;
}

static int varlink_dispatch_disconnect(Varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_DISCONNECT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_DISCONNECT);
        varlink_dispatch_local_error(v, VARLINK_ERROR_DISCONNECTED);
        varlink_close(v);

        return 1;
}

static int varlink_sanitize_parameters(JsonVariant **v) {
        assert(v);

        /* Varlink always wants a parameters list, hence make one if the caller doesn't want any */
        if (!*v)
                *v = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
        else if (!json_variant_is_object(*v))
                return -EINVAL;

        return 0;
}

static int varlink_dispatch_reply(Varlink *v) {
        const char *error;
        JsonVariant *p, *parameters;
        VarlinkReplyFlags flags = 0;
        int r;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_CALLING))
                return 0;
        if (!v->current)
                return 0;

        assert(v->n_pending > 0);

        p = json_variant_by_key(v->current, "error");
        if (p) {
                if (!json_variant_is_string(p))
                        goto invalid;

                error = json_variant_string(p);
                flags |= VARLINK_REPLY_ERROR;
        } else
                error = NULL;

        parameters = json_variant_by_key(v->current, "parameters");
        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                goto invalid;

        p = json_variant_by_key(v->current, "continues");
        if (p) {
                if (!json_variant_is_boolean(p))
                        goto invalid;

                if (json_variant_boolean(p))
                        flags |= VARLINK_REPLY_CONTINUE;
        }

        if (v->state == VARLINK_AWAITING_REPLY) {
                varlink_set_state(v, VARLINK_PROCESSING_REPLY);

                if (v->reply_callback) {
                        r = v->reply_callback(v, parameters, error, flags, v->userdata);
                        if (r < 0)
                                log_debug_errno(r, "Reply callback returned error, ignoring: %m");
                }

                v->current = json_variant_unref(v->current);

                if (v->state == VARLINK_PROCESSING_REPLY) {
                        assert(v->n_pending > 0);
                        v->n_pending--;

                        if (v->n_pending == 0)
                                v->state = VARLINK_IDLE_CLIENT;
                        else
                                v->state = VARLINK_AWAITING_REPLY;
                }

        } else {
                assert(v->state == VARLINK_CALLING);
                varlink_set_state(v, VARLINK_CALLED);
        }

        return 1;

invalid:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, VARLINK_ERROR_PROTOCOL);
        varlink_close(v);

        return 1;
}

static int varlink_dispatch_method(Varlink *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *transformed = NULL;
        JsonVariant *p, *parameters;
        VarlinkMethodFlags flags = 0;
        VarlinkMethod callback;
        const char *method;
        int r;

        assert(v);

        if (v->state != VARLINK_IDLE_SERVER)
                return 0;
        if (!v->current)
                return 0;

        p = json_variant_by_key(v->current, "method");
        if (!p)
                goto invalid;
        if (!json_variant_is_string(p))
                goto invalid;

        method = json_variant_string(p);

        parameters = json_variant_by_key(v->current, "parameters");
        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                goto invalid;

        p = json_variant_by_key(v->current, "oneway");
        if (p) {
                if (!json_variant_is_boolean(p))
                        goto invalid;

                if (json_variant_boolean(p))
                        flags |= VARLINK_METHOD_ONEWAY;
        }

        p = json_variant_by_key(v->current, "more");
        if (p) {
                if (!json_variant_is_boolean(p))
                        goto invalid;

                if (json_variant_boolean(p)) {

                        if (flags & VARLINK_METHOD_ONEWAY)
                                goto invalid;

                        flags |= VARLINK_METHOD_MORE;
                }
        }

        v->state =
                (flags & VARLINK_METHOD_MORE)   ? VARLINK_PROCESSING_METHOD_MORE :
                (flags & VARLINK_METHOD_ONEWAY) ? VARLINK_PROCESSING_METHOD_ONEWAY :
                                                  VARLINK_PROCESSING_METHOD;

        if (v->server) {
                assert(!v->method_concept);

                r = varlink_server_validate(v->server);
                if (r < 0) {
                        r = varlink_reply_error(v, NULL, "io.systemd.CannotValidate");
                        if (r < 0)
                                return r;

                        goto done;
                }

                r = varlink_validator_find_method(v->server->validator, method, &v->method_concept);
                if (r < 0) {
                        r = varlink_reply_error(v, NULL, "io.systemd.UnknownMethod");
                        if (r < 0)
                                return r;

                        goto done;
                }

                r = varlink_validate_method(v->method_concept, parameters, &transformed);
                if (r < 0) {
                        r = varlink_reply_error(v, NULL, "io.systemd.ValidationFailed");
                        if (r < 0)
                                return r;

                        goto done;
                }

                parameters = transformed;

                callback = hashmap_get(v->server->methods, method);
        } else
                callback = NULL;

        if (callback) {
                r = callback(v, parameters, flags, v->userdata);
                if (r < 0) {
                        log_debug_errno(r, "Callback for %s returned error: %m", method);

                        /* We got an error back from the callback. Propagate it to the client if the method call remains unanswered. */
                        if (IN_SET(v->state, VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE)) {
                                r = varlink_reply_error(v, NULL, "io.systemd.SystemError");
                                if (r < 0)
                                        return r;
                        }
                }

        } else if (IN_SET(v->state, VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE)) {
                r = varlink_reply_error(v, NULL, "io.systemd.MethodNotImplemented");
                if (r < 0)
                        return r;
        }

done:

        switch (v->state) {

        case VARLINK_PROCESSED_METHOD: /* Method call is fully processed */
        case VARLINK_PROCESSING_METHOD_ONEWAY: /* dito */
                v->current = json_variant_unref(v->current);
                v->method_concept = NULL;
                v->state = VARLINK_IDLE_SERVER;
                break;

        case VARLINK_PROCESSING_METHOD: /* Method call wasn't replied to, will be replied to later */
                v->state = VARLINK_PENDING_METHOD;
                break;

        case VARLINK_PROCESSED_METHOD_MORE:  /* One reply for a "more" message was sent, more to come */
        case VARLINK_PROCESSING_METHOD_MORE: /* No reply for a "more" message was sent, more to come */
                v->state = VARLINK_PENDING_METHOD_MORE;
                break;

        default:
                assert_not_reached("Unexpected state");

        }

        return r;

invalid:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, VARLINK_ERROR_PROTOCOL);
        varlink_close(v);

        return r;
}

int varlink_process(Varlink *v) {
        int r;

        if (!v)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;

        varlink_ref(v);

        r = varlink_write(v);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_reply(v);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_method(v);
        if (r != 0)
                goto finish;

        r = varlink_parse_message(v);
        if (r != 0)
                goto finish;

        r = varlink_read(v);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_disconnect(v);
        if (r != 0)
                goto finish;

        r = varlink_test_timeout(v);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_timeout(v);
        if (r != 0)
                goto finish;

finish:
        if (r >= 0 && v->defer_event_source) {
                int q;

                /* If we did some processing, make sure we are called again soon */
                q = sd_event_source_set_enabled(v->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0)
                        r = q;
        }

        if (r < 0)
                varlink_close(v);

        varlink_unref(v);
        return r;
}

int varlink_wait(Varlink *v, usec_t timeout) {
        struct timespec ts;
        usec_t t;
        int r, fd, events;

        if (!v)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (v->server)
                return -ENOTTY;

        if (timeout == 0)
                return 0;

        r = varlink_get_timeout(v, &t);
        if (r < 0)
                return r;
        if (t != USEC_INFINITY) {
                usec_t n;

                n = now(CLOCK_MONOTONIC);
                if (t < n)
                        return 0;

                t = usec_sub_unsigned(t, n);
                if (t == 0)
                        return 0;
        }

        if (timeout != USEC_INFINITY &&
            (t == USEC_INFINITY || timeout < t))
                t = timeout;

        fd = varlink_get_fd(v);
        if (fd < 0)
                return fd;

        events = varlink_get_events(v);
        if (events < 0)
                return events;

        r = ppoll(&(struct pollfd) {
                        .fd = fd,
                        .events = events,
                  },
                  1,
                  t == USEC_INFINITY ? NULL : timespec_store(&ts, t),
                  NULL);
        if (r < 0)
                return -errno;

        return r > 0 ? 1 : 0;
}

int varlink_get_fd(Varlink *v) {

        if (!v)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (v->fd < 0)
                return -EBADF;

        return v->fd;
}

int varlink_get_events(Varlink *v) {
        int ret = 0;

        if (!v)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_CALLING, VARLINK_IDLE_SERVER) &&
            !v->current &&
            v->input_buffer_unscanned <= 0)
                ret |= EPOLLIN;

        if (!v->write_disconnected &&
            v->output_buffer_size > 0)
                ret |= EPOLLOUT;

        return ret;
}

int varlink_get_timeout(Varlink *v, usec_t *ret) {
        if (!v)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_CALLING) &&
            v->timeout != USEC_INFINITY) {
                *ret = usec_add(v->timestamp, v->timeout);
                return 1;
        } else {
                *ret = USEC_INFINITY;
                return 0;
        }
}

int varlink_flush(Varlink *v) {
        int ret = 0, r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;

        for (;;) {

                if (v->output_buffer_size == 0)
                        break;
                if (v->write_disconnected)
                        return -ECONNRESET;

                r = varlink_write(v);
                if (r < 0)
                        return r;
                if (r > 0) {
                        ret = 1;
                        continue;
                }

                if (poll(&(struct pollfd) {
                                 .fd = v->fd,
                                 .events = POLLOUT
                         }, 1, -1) < 0)
                        return -errno;
        }

        return ret;
}

int varlink_close(Varlink *v) {
        if (!v)
                return -EINVAL;

        if (v->state == VARLINK_DISCONNECTED)
                return 0;

        varlink_set_state(v, VARLINK_DISCONNECTED);

        varlink_detach_event_sources(v);

        v->fd = safe_close(v->fd);
        v->current = json_variant_unref(v->current);
        v->method_concept = NULL;
        v->reply = json_variant_unref(v->reply);

        /* If this is a connection associated to a server, then let's disconnect the server and the connection from each other. */
        if (v->server) {
                v->server = varlink_server_unref(v->server);
                varlink_unref(v);
        }

        return 1;
}

Varlink* varlink_flush_close_unref(Varlink *v) {
        if (!v)
                return NULL;

        (void) varlink_flush(v);
        (void) varlink_close(v);

        return varlink_unref(v);
}

static int varlink_enqueue_json(Varlink *v, JsonVariant *m) {
        _cleanup_free_ char *text = NULL;
        int r;

        assert(v);
        assert(m);

        r = json_variant_format(m, 0, &text);
        if (r < 0)
                return r;

        if (v->output_buffer_size + r + 1 > VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        log_debug("Sending message: %s", text);

        if (v->output_buffer_size == 0) {

                free(v->output_buffer);
                v->output_buffer = text;

                v->output_buffer_size = v->output_buffer_allocated = r + 1;
                v->output_buffer_index = 0;

                text = NULL;

        } else if (v->output_buffer_index == 0) {

                if (!GREEDY_REALLOC(v->output_buffer, v->output_buffer_allocated, v->output_buffer_size + r + 1))
                        return -ENOMEM;

                memcpy(v->output_buffer + v->output_buffer_size, text, r + 1);
                v->output_buffer_size += r + 1;

        } else {
                char *n;

                n = new(char, v->output_buffer_size + r + 1);
                if (!n)
                        return -ENOMEM;

                memcpy(mempcpy(n, v->output_buffer + v->output_buffer_index, v->output_buffer_size), text, r + 1);

                free(v->output_buffer);
                v->output_buffer = n;
                v->output_buffer_size += r + 1;
                v->output_buffer_index = 0;
        }

        return 0;
}

int varlink_send(Varlink *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert(v);
        assert(method);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters)),
                                       JSON_BUILD_PAIR("oneway", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return r;

        return varlink_enqueue_json(v, m);
}

int varlink_invoke(Varlink *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        if (!v)
                return -EINVAL;
        if (!method)
                return -EINVAL;
        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return r;

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return r;

        varlink_set_state(v, VARLINK_AWAITING_REPLY);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        return 0;
}

int varlink_call(
                Varlink *v,
                const char *method,
                JsonVariant *parameters,
                JsonVariant **ret_parameters,
                const char **ret_error_id,
                VarlinkReplyFlags *ret_flags) {

        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (v->state != VARLINK_IDLE_CLIENT)
                return -EBUSY;

        assert(v->n_pending == 0);

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return r;

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return r;

        varlink_set_state(v, VARLINK_CALLING);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        while (v->state == VARLINK_CALLING) {

                r = varlink_process(v);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = varlink_wait(v, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        switch (v->state) {

        case VARLINK_CALLED:
                assert(v->current);

                json_variant_unref(v->reply);
                v->reply = v->current;
                v->current = NULL;

                varlink_set_state(v, VARLINK_IDLE_CLIENT);
                assert(v->n_pending == 1);
                v->n_pending--;

                if (ret_parameters)
                        *ret_parameters = json_variant_by_key(v->reply, "parameters");
                if (ret_error_id)
                        *ret_error_id = json_variant_string(json_variant_by_key(v->reply, "error"));
                if (ret_flags)
                        *ret_flags = 0;

                return 1;

        case VARLINK_DISCONNECTED:
        case VARLINK_PENDING_DISCONNECT:
                varlink_set_state(v, VARLINK_DISCONNECTED);
                return -ECONNRESET;

        case VARLINK_PENDING_TIMEOUT:
                varlink_set_state(v, VARLINK_DISCONNECTED);
                return -ETIME;
        default:
                assert_not_reached("Unexpected state after method call.");
        }

}

int varlink_reply(Varlink *v, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL, *transformed = NULL;
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (!IN_SET(v->state, VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE))
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        assert(v->method_concept);
        r = varlink_validate_reply(v->method_concept, parameters, &transformed);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(transformed))));
        if (r < 0)
                return r;

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return r;

        varlink_set_state(v, VARLINK_PROCESSED_METHOD);
        return 1;
}

int varlink_reply_error(Varlink *v, JsonVariant *parameters, const char *error_id) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL, *transformed = NULL;
        VarlinkConcept *error_concept;
        int r;

        assert_return(v, -EINVAL);
        assert_return(error_id, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (!IN_SET(v->state, VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE))
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        assert(v->server);
        assert(v->server->validator);

        r = varlink_validator_find_error(v->server->validator, error_id, &error_concept);
        if (r < 0)
                return r;

        r = varlink_validate_error(error_concept, parameters, &transformed);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("error", JSON_BUILD_STRING(error_id)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(transformed))));
        if (r < 0)
                return r;

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return r;

        varlink_set_state(v, VARLINK_IDLE_SERVER);
        return 1;
}

int varlink_notify(Varlink *v, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL, *transformed = NULL;
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (v->state != VARLINK_PROCESSING_METHOD_MORE)
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return r;

        assert(v->method_concept);
        r = varlink_validate_reply(v->method_concept, parameters, &transformed);
        if (r < 0)
                return r;

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(transformed)),
                                       JSON_BUILD_PAIR("continues", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return r;

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return r;

        varlink_set_state(v, VARLINK_PROCESSED_METHOD_MORE);
        return 1;
}

int varlink_bind_reply(Varlink *v, VarlinkReply callback) {
        assert_return(v, -EINVAL);

        if (callback && v->reply_callback && callback != v->reply_callback)
                return -EBUSY;

        v->reply_callback = callback;

        return 0;
}

void* varlink_set_userdata(Varlink *v, void *userdata) {
        void *old;

        assert(v);
        old = v->userdata;
        v->userdata = userdata;

        return old;
}

void* varlink_get_userdata(Varlink *v) {
        assert(v);

        return v->userdata;
}

static int varlink_acquire_ucred(Varlink *v) {
        socklen_t l;
        assert(v);

        if (v->ucred_acquired)
                return 0;

        l = sizeof(v->ucred);
        if (getsockopt(v->fd, SOL_SOCKET, SO_PEERCRED, &v->ucred, &l) < 0)
                return -errno;

        assert(l == sizeof(v->ucred));
        v->ucred_acquired = true;

        return 0;
}

int varlink_get_peer_uid(Varlink *v, uid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return r;

        if (!uid_is_valid(v->ucred.uid))
                return -ENODATA;

        *ret = v->ucred.uid;
        return 0;
}

int varlink_get_peer_pid(Varlink *v, pid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return r;

        if (!pid_is_valid(v->ucred.pid))
                return -ENODATA;

        *ret = v->ucred.pid;
        return 0;
}

int varlink_set_relative_timeout(Varlink *v, usec_t timeout) {
        assert_return(v, -EINVAL);

        if (timeout == 0)
                return -EINVAL;

        v->timeout = timeout;
        return 0;
}

VarlinkServer *varlink_get_server(Varlink *v) {
        assert_return(v, NULL);

        return v->server;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Varlink *v = userdata;
        int r;

        assert(s);
        assert(v);

        r = varlink_process(v);
        if (r < 0)
                return r;

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        Varlink *v = userdata;
        int r;

        assert(s);
        assert(v);

        r = varlink_process(v);
        if (r < 0)
                return r;

        return 1;
}

static int defer_callback(sd_event_source *s, void *userdata) {
        Varlink *v = userdata;
        int r;

        assert(s);
        assert(v);

        r = varlink_process(v);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        Varlink *v = userdata;
        int r, e;
        usec_t until;

        assert(s);
        assert(v);

        e = varlink_get_events(v);
        if (e < 0)
                return e;

        r = sd_event_source_set_io_events(v->io_event_source, e);
        if (r < 0)
                return r;

        r = varlink_get_timeout(v, &until);
        if (r < 0)
                return r;
        if (r > 0) {
                r = sd_event_source_set_time(v->time_event_source, until);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(v->time_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
        if (r < 0)
                return r;

        return 1;
}

static int quit_callback(sd_event_source *event, void *userdata) {
        Varlink *v = userdata;

        assert(event);
        assert(v);

        varlink_flush(v);
        varlink_close(v);

        return 1;
}

int varlink_attach_event(Varlink *v, sd_event *e, int64_t priority) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(!v->event, -EBUSY);

        if (e)
                v->event = sd_event_ref(e);
        else {
                r = sd_event_default(&v->event);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_time(v->event, &v->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->time_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->time_event_source, "varlink-time");

        r = sd_event_add_exit(v->event, &v->quit_event_source, quit_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->quit_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->quit_event_source, "varlink-quit");

        r = sd_event_add_io(v->event, &v->io_event_source, v->fd, 0, io_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(v->io_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->io_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->io_event_source, "varlink-io");

        r = sd_event_add_defer(v->event, &v->defer_event_source, defer_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->defer_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->io_event_source, "varlink-defer");

        return 0;

fail:
        varlink_detach_event(v);
        return r;
}


void varlink_detach_event(Varlink *v) {
        if (!v)
                return;

        varlink_detach_event_sources(v);

        v->event = sd_event_unref(v->event);
}

sd_event *varlink_get_event(Varlink *v) {
        assert_return(v, NULL);

        return v->event;
}

int varlink_server_new(VarlinkServer **ret) {
        VarlinkServer *s;

        assert_return(ret, -EINVAL);

        s = new0(VarlinkServer, 1);
        if (!s)
                return -ENOMEM;

        s->n_ref = 1;

        *ret = s;
        return 0;
}

VarlinkServer* varlink_server_ref(VarlinkServer *s) {

        if (!s)
                return NULL;

        assert(s->n_ref > 0);
        s->n_ref++;

        return s;
}

static VarlinkServer* varlink_server_destroy(VarlinkServer *s) {
        char *m;

        if (!s)
                return NULL;

        varlink_server_shutdown(s);

        while ((m = hashmap_steal_first_key(s->methods)))
                free(m);

        hashmap_free(s->methods);

        sd_event_unref(s->event);

        strv_free(s->interfaces);
        varlink_validator_unref(s->validator);

        return mfree(s);
}

VarlinkServer* varlink_server_unref(VarlinkServer *s) {
        if (!s)
                return NULL;

        assert(s->n_ref > 0);
        s->n_ref--;

        if (s->n_ref > 0)
                return NULL;

        return varlink_server_destroy(s);
}

static int connect_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        VarlinkServerSocket *ss = userdata;
        _cleanup_close_ int cfd = -1;
        Varlink *v;
        int64_t priority;
        int r;

        assert(source);
        assert(ss);

        log_debug("New incoming connection.");

        r = sd_event_source_get_priority(source, &priority);
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire event source priority: %m");

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0)
                return log_debug_errno(errno, "Failed to accept incoming socket: %m");

        r = varlink_new(&v);
        if (r < 0) {
                log_debug_errno(r, "Failed to allocate connection object: %m");
                return 0;
        }

        v->state = VARLINK_IDLE_SERVER;
        v->server = varlink_server_ref(ss->server);
        v->userdata = ss->server->userdata;

        v->fd = cfd;
        cfd = -1;

        r = varlink_attach_event(v, ss->server->event, priority);
        if (r < 0) {
                varlink_destroy(v);
                log_debug_errno(r, "Failed to attach new connection: %m");
                return 0;
        }

        if (ss->server->connect_callback) {
                varlink_server_ref(ss->server);
                varlink_ref(v);

                r = ss->server->connect_callback(ss->server, v, ss->server->userdata);
                if (r < 0) {
                        log_debug_errno(r, "Connection callback returned error, disconnecting client: %m");
                        varlink_close(v);
                }

                varlink_unref(v);
                varlink_server_unref(ss->server);
        }

        return 0;
}

int varlink_server_listen_fd(VarlinkServer *s, int fd) {
        VarlinkServerSocket *ss;
        int r;

        assert_return(s, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        ss = new0(VarlinkServerSocket, 1);
        if (!ss)
                return -ENOMEM;

        ss->server = s;
        ss->fd = fd;

        if (s->event) {
                r = sd_event_add_io(s->event, &ss->event_source, fd, EPOLLIN, connect_callback, ss);
                if (r < 0) {
                        free(ss);
                        return r;
                }
        }

        LIST_PREPEND(sockets, s->sockets, ss);
        return 0;
}

int varlink_server_listen_address(VarlinkServer *s, const char *address) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sockaddr = {
                .sa.sa_family = AF_UNIX,
        };
        int r;

        assert_return(s, -EINVAL);
        assert_return(address, -EINVAL);

        if (strlen(address) > sizeof(sockaddr.un.sun_path))
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        strncpy(sockaddr.un.sun_path, address, sizeof(sockaddr.un.sun_path));

        (void) unlink(address);

        if (bind(fd, &sockaddr.sa, SOCKADDR_UN_LEN(sockaddr.un)) < 0)
                return -errno;

        if (listen(fd, SOMAXCONN) < 0)
                return -errno;

        r = varlink_server_listen_fd(s, fd);
        if (r < 0)
                return r;

        fd = -1;
        return 0;
}

void* varlink_server_set_userdata(VarlinkServer *s, void *userdata) {
        void *ret;

        assert_return(s, NULL);

        ret = s->userdata;
        s->userdata = userdata;

        return ret;
}

void* varlink_server_get_userdata(VarlinkServer *s) {
        assert_return(s, NULL);

        return s->userdata;
}

static VarlinkServerSocket* varlink_server_socket_destroy(VarlinkServerSocket *ss) {
        if (!ss)
                return NULL;

        if (ss->server)
                LIST_REMOVE(sockets, ss->server->sockets, ss);

        if (ss->event_source) {
                sd_event_source_set_enabled(ss->event_source, SD_EVENT_OFF);
                sd_event_source_unref(ss->event_source);
        }

        free(ss->address);
        safe_close(ss->fd);

        return mfree(ss);
}

int varlink_server_shutdown(VarlinkServer *s) {
        assert_return(s, -EINVAL);

        while (s->sockets)
                varlink_server_socket_destroy(s->sockets);

        return 0;
}

int varlink_server_attach_event(VarlinkServer *s, sd_event *e, int64_t priority) {
        VarlinkServerSocket *ss;
        int r;

        assert_return(s, -EINVAL);
        assert_return(!s->event, -EBUSY);

        if (e)
                s->event = sd_event_ref(e);
        else {
                r = sd_event_default(&s->event);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(sockets, ss, s->sockets) {
                assert(!ss->event_source);

                r = sd_event_add_io(s->event, &ss->event_source, ss->fd, EPOLLIN, connect_callback, ss);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        varlink_server_detach_event(s);
        return r;
}

int varlink_server_detach_event(VarlinkServer *s) {
        VarlinkServerSocket *ss;

        assert_return(s, -EINVAL);

        LIST_FOREACH(sockets, ss, s->sockets) {

                if (!ss->event_source)
                        continue;

                (void) sd_event_source_set_enabled(ss->event_source, SD_EVENT_OFF);
                ss->event_source = sd_event_source_unref(ss->event_source);
        }

        sd_event_unref(s->event);
        return 0;
}

sd_event *varlink_server_get_event(VarlinkServer *s) {
        assert_return(s, NULL);

        return s->event;
}

int varlink_server_validate(VarlinkServer *s) {
        int r;

        assert_return(s, -EINVAL);

        if (s->validator)
                return 0;

        r = varlink_validator_parse(&s->validator, s->interfaces);
        if (r < 0)
                return r;

        return 1;
}

int varlink_server_bind_method(VarlinkServer *s, const char *method, VarlinkMethod callback) {
        char *m;
        int r;

        assert_return(s, -EINVAL);
        assert_return(method, -EINVAL);
        assert_return(callback, -EINVAL);

        r = varlink_server_validate(s);
        if (r < 0)
                return r;

        r = varlink_validator_find_method(s->validator, method, NULL);
        if (r < 0)
                return log_debug_errno(r, "Can't register method callback for %s: %m", method);

        r = hashmap_ensure_allocated(&s->methods, &string_hash_ops);
        if (r < 0)
                return r;

        m = strdup(method);
        if (!m)
                return -ENOMEM;

        r = hashmap_put(s->methods, m, callback);
        if (r < 0) {
                free(m);
                return r;
        }

        return 0;
}

int varlink_server_bind_connect(VarlinkServer *s, VarlinkConnect callback) {
        assert_return(s, -EINVAL);

        if (callback && s->connect_callback && callback != s->connect_callback)
                return -EBUSY;

        s->connect_callback = callback;
        return 0;
}

int varlink_server_add_interface(VarlinkServer *s, const char *text) {
        assert_return(s, -EINVAL);
        assert_return(text, -EINVAL);

        if (s->validator)
                return -EBUSY;

        return strv_extend(&s->interfaces, text);
}

int varlink_server_add_interface_many(VarlinkServer *s, const char *first, ...) {
        char **l;

        assert_return(s, -EINVAL);

        if (s->validator)
                return -EBUSY;

        l = strv_from_stdarg_alloca(first);

        return strv_extend_strv(&s->interfaces, l, false);
}
