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

#include "util.h"
#include "varlink-validate.h"
#include "strv.h"

const char interface[] =
R"(# Interface to jump a spacecraft to another point in space. The
# FTL Drive is the propulsion system to achieve faster-than-light
# travel through space. A ship making a properly calculated
# jump can arrive safely in planetary orbit, or alongside other
# ships or spaceborne objects.
interface org.example.ftl

# The current state of the FTL drive and the amount of fuel
# available to jump.
type DriveCondition (
  # The current state
  state: (
    # When we are idle
    idle,
    # When we are spooling
    spooling, # obsolete
    # When we are busy
    busy) = "idle",
  # The amount of Tylium
  tylium_level: int = 7
)

# Speed, trajectory and jump duration is calculated prior to
# activating the FTL drive.
type DriveConfiguration (
  speed: int = 0,
  trajectory: int,
  duration: int
)

# The galactic coordinates use the Sun as the origin. Galactic
# longitude is measured with primary direction from the Sun to
# the center of the galaxy in the galactic plane, while the
# galactic latitude measures the angle of the object above the
# galactic plane.
type Coordinate (
  # The geographical longitude
  longitude: int = 88,
  # The geographical latitude
  latitude: int = 77,
  distance: int
)

# Monitor the drive. The method will reply with an update whenever
# the drive's state changes
method Monitor() -> (condition: DriveCondition)

# Calculate the drive's jump parameters from the current
# position to the target position in the galaxy
method CalculateConfiguration(
  current: Coordinate = { "longitude" : 99, "latitude" : 4711, "distance" : 99 },
  target: Coordinate
) -> (configuration: DriveConfiguration)

# Jump to the calculated point in space
method Jump(configuration: DriveConfiguration) -> ()

# There is not enough tylium to jump with the given parameters
error NotEnoughEnergy ()

# The supplied parameters are outside the supported range
error ParameterOutOfRange (field: string = "")
)";

int main(int argc, char *argv[]) {
        _cleanup_(varlink_validator_unrefp) VarlinkValidator *v = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *j = NULL, *transformed = NULL;
        VarlinkConcept *c;

        assert_se(varlink_validator_parse(&v, STRV_MAKE(interface)) >= 0);

        varlink_validator_dump(v, NULL, VARLINK_DUMP_COLOR);

        assert_se(json_build(&j, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("speed", JSON_BUILD_INTEGER(7)),
                                                   JSON_BUILD_PAIR("trajectory", JSON_BUILD_INTEGER(9)),
                                                   JSON_BUILD_PAIR("duration", JSON_BUILD_INTEGER(111)))) >= 0);

        c = varlink_validator_find(v, "org.example.ftl.DriveConfiguration");
        assert_se(c);
        assert_se(varlink_validate(c, j, &transformed) >= 0);
        assert_se(json_variant_equal(j, transformed));

        j = json_variant_unref(j);
        transformed = json_variant_unref(transformed);

        assert_se(json_build(&j, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("somethinelse", JSON_BUILD_STRING("miepf")),
                                                   JSON_BUILD_PAIR("distance", JSON_BUILD_INTEGER(99)))) >= 0);

        c = varlink_validator_find(v, "org.example.ftl.Coordinate");
        assert_se(c);
        assert_se(varlink_validate(c, j, &transformed) >= 0);
        json_variant_dump(transformed, JSON_FORMAT_PRETTY, NULL, NULL);
        printf("\n");

        j = json_variant_unref(j);
        transformed = json_variant_unref(transformed);

        assert_se(json_build(&j, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("state", JSON_BUILD_STRING("busy")))) >= 0);

        c = varlink_validator_find(v, "org.example.ftl.DriveCondition");
        assert_se(c);
        assert_se(varlink_validate(c, j, &transformed) >= 0);
        json_variant_dump(transformed, JSON_FORMAT_PRETTY, NULL, NULL);
        printf("\n");

        return 0;
}
