#pragma once

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

#include "sd-event.h"
#include "json.h"

typedef struct Varlink Varlink;
typedef struct VarlinkServer VarlinkServer;
typedef struct VarlinkGroup VarlinkGroup;

typedef enum VarlinkReplyFlags {
        VARLINK_REPLY_ERROR = 1,
        VARLINK_REPLY_CONTINUE = 2,
        VARLINK_REPLY_LOCAL = 4,
} VarlinkReplyFlags;

typedef enum VarlinkMethodFlags {
        VARLINK_METHOD_ONEWAY = 1,
        VARLINK_METHOD_MORE = 2,
} VarlinkMethodFlags;

typedef int (*VarlinkMethod)(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata);
typedef int (*VarlinkReply)(Varlink *link, JsonVariant *parameters, const char *error_id, VarlinkReplyFlags flags, void *userdata);
typedef int (*VarlinkConnect)(VarlinkServer *server, Varlink *link, void *userdata);

/* typedef void (*varlinkGroupEmpty)(VarlinkGroup *group, void *userdata); */

int varlink_connect_address(Varlink **ret, const char *address);
int varlink_connect_fd(Varlink **ret, int fd);
Varlink* varlink_ref(Varlink *link);
Varlink* varlink_unref(Varlink *v);

int varlink_get_fd(Varlink *v);
int varlink_get_events(Varlink *v);
int varlink_get_timeout(Varlink *v, usec_t *ret);

int varlink_attach_event(Varlink *v, sd_event *e, int64_t priority);
void varlink_detach_event(Varlink *v);
sd_event *varlink_get_event(Varlink *v);

int varlink_process(Varlink *v);
int varlink_wait(Varlink *v, usec_t timeout);

int varlink_flush(Varlink *v);
int varlink_close(Varlink *v);

Varlink* varlink_flush_close_unref(Varlink *v);

/* Enqueue method call, not expecting a reply */
int varlink_send(Varlink *v, const char *method, JsonVariant *parameters);

/* Send method call and wait for reply */
int varlink_call(Varlink *v, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters, const char **ret_error_id, VarlinkReplyFlags *ret_flags);

/* Enqueue method call, expect a reply, which is eventually delivered to the reply callback */
int varlink_invoke(Varlink *v, const char *method, JsonVariant *parameters);

/* Enqueue a final reply */
int varlink_reply(Varlink *v, JsonVariant *parameters);

/* Enqueue a (final) error */
int varlink_reply_error(Varlink *v, JsonVariant *parameters, const char *error_id);

/* Enqueue a "more" reply */
int varlink_notify(Varlink *v, JsonVariant *parameters);

/* Bind a disconnect, reply or timeout callback */
int varlink_bind_reply(Varlink *v, VarlinkReply reply);

void* varlink_set_userdata(Varlink *v, void *userdata);
void* varlink_get_userdata(Varlink *v);

int varlink_get_peer_uid(Varlink *v, uid_t *ret);
int varlink_get_peer_pid(Varlink *v, pid_t *ret);

int varlink_set_relative_timeout(Varlink *v, usec_t usec);

VarlinkServer* varlink_get_server(Varlink *v);

/* Create a varlink server */
int varlink_server_new(VarlinkServer **ret);
VarlinkServer *varlink_server_ref(VarlinkServer *s);
VarlinkServer *varlink_server_unref(VarlinkServer *s);

/* Add addresses or fds to listen on */
int varlink_server_listen_address(VarlinkServer *s, const char *address);
int varlink_server_listen_fd(VarlinkServer *s, int fd);

/* Bind introspection data */
int varlink_server_add_interface(VarlinkServer *s, const char *text);
int varlink_server_add_interface_many(VarlinkServer *s, const char *first, ...);
int varlink_server_validate(VarlinkServer *s);

/* Bind callbacks */
int varlink_server_bind_method(VarlinkServer *s, const char *method, VarlinkMethod callback);
int varlink_server_bind_method_many(VarlinkServer *s, ...);
int varlink_server_bind_connect(VarlinkServer *s, VarlinkConnect connect);

void* varlink_server_set_userdata(VarlinkServer *s, void *userdata);
void* varlink_server_get_userdata(VarlinkServer *s);

int varlink_server_attach_event(VarlinkServer *v, sd_event *e, int64_t priority);
int varlink_server_detach_event(VarlinkServer *v);
sd_event *varlink_server_get_event(VarlinkServer *v);

int varlink_server_shutdown(VarlinkServer *server);

/* int varlink_group_new(VarlinkGroup **ret); */
/* VarlinkGroup *varlink_group_ref(VarlinkGroup *group); */
/* VarlinkGroup *varlink_group_unref(VarlinkGroup *group); */

/* int varlink_group_add(VarlinkGroup *g, Varlink *v); */
/* int varlink_group_remove(VarlinkGroup *g, Varlink *v); */
/* int varlink_group_contains(VarlinkGroup *g, Varlink *v); */
/* int varlink_group_size(VarlinkGroup *g); */

/* int varlink_group_reply(VarlinkGroup *g, JsonVariant *parameters); */
/* int varlink_group_replyb(VarlinkGroup *g, ...); */

/* int varlink_group_notify(VarlinkGroup *g, JsonVariant *parameters); */
/* int varlink_group_notifyb(VarlinkGroup *g, JsonVariant *parameters); */

/* int varlink_group_bind_empty(VarlinkGroup *g, VarlinkEmpty empty); */

/* void* varlink_group_set_userdata(VarlinkGroup *g, void *userdata); */
/* void* varlink_group_get_userdata(VarlinkGroup *g); */

DEFINE_TRIVIAL_CLEANUP_FUNC(Varlink *, varlink_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Varlink *, varlink_flush_close_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkServer *, varlink_server_unref);

#define VARLINK_ERROR_DISCONNECTED "io.systemd.Disconnected"
#define VARLINK_ERROR_TIMEOUT "io.systemd.TimedOut"
#define VARLINK_ERROR_PROTOCOL "io.systemd.Protocol"
