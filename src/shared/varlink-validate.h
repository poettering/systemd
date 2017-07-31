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

#include <stdio.h>

#include "json.h"

typedef struct VarlinkConcept VarlinkConcept;
typedef struct VarlinkValidator VarlinkValidator;

int varlink_validator_parse(VarlinkValidator **ret, char **texts);
VarlinkValidator *varlink_validator_unref(VarlinkValidator *validator);

VarlinkConcept *varlink_validator_find(VarlinkValidator *validator, const char *name);

int varlink_validator_find_method(VarlinkValidator *validator, const char *name, VarlinkConcept **ret);
int varlink_validator_find_error(VarlinkValidator *validator, const char *name, VarlinkConcept **ret);

enum {
        VARLINK_DUMP_COLOR = 1,
};

void varlink_validator_dump(VarlinkValidator *validator, FILE *f, unsigned flags);

int varlink_validate(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret);

int varlink_validate_method(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret);
int varlink_validate_reply(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret);
int varlink_validate_error(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkValidator*, varlink_validator_unref);
