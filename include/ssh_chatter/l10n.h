/**
 * @file l10n.h
 * @desc Localization primitive used for translatable UI strings such as the
 *       /palette names and descriptions.
 */
#ifndef L10N_H
#define L10N_H

/**
 * @desc One user-facing string in every supported UI language. Callers start
 *       from `en` and switch to the member matching the session's UI
 *       language, so every member should be populated (the L10N_ALL() helper
 *       in color_and_palette.c fills all of them with the same text).
 */
typedef struct l10n_string {
    const char *en; /* English (default) */
    const char *ko; /* Korean */
    const char *jp; /* Japanese */
    const char *zh; /* Chinese */
    const char *ru; /* Russian */
    const char *pl; /* Polish */
} l10n_string_t;

#endif
