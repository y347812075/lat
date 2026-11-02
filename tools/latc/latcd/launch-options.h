#ifndef LATCD_LAUNCH_OPTIONS_H
#define LATCD_LAUNCH_OPTIONS_H

#include <glib.h>
#include <stdbool.h>

bool latcd_launch_options_match(int fd, const GPtrArray *options);

#endif
