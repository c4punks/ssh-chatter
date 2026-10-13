/**
 * @file theme.h
 * @desc Theme descriptors backing /color, /systemcolor and /palette. Every
 *       color member is a ready-to-emit ANSI escape sequence (see
 *       palettes.h), not a color name.
 */
#ifndef THEME_H
#define THEME_H

#include <stdbool.h>

#include "palettes.h"

/* Default styling of user handles; copied into new sessions and updated
 * from /color. */
typedef struct UserTheme {
    const char *userColor; // Foreground of the nickname
    const char *highlight; // Background behind the nickname
    bool isBold;
} UserTheme;

/* Default styling of the interface chrome; copied into new sessions and
 * updated from /systemcolor or /palette. */
typedef struct SystemTheme {
    const char *backgroundColor;
    const char *foregroundColor; // Text Color
    const char *highlightColor;  //Highlight with <hl></hl>
    bool isBold;
} SystemTheme;

#endif
