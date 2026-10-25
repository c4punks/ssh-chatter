/**
 * @file zmh.c
 * @desc Zone Mail Hour: the daily hour, fixed per FidoNet zone, during which
 *       every node must accept mail.  The node polls its uplink inside this
 *       window by default.  Times are UTC:
 *
 *         Zone 1 (North America)  09:00-10:00
 *         Zone 2 (Europe)         02:30-03:30
 *         Zone 3 (Australasia)    18:00-19:00
 *         Zone 4 (Latin America)  08:00-09:00
 *         Zone 5 (Africa)         01:00-02:00
 *         Zone 6 (Asia)           20:00-21:00
 *
 *       Other zones fall back to the original FidoNet mail hour, 09:00 UTC.
 *       Only libc is used so the unit test can include this file.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define FTN_MINUTES_PER_DAY (24 * 60)

/* A daily window in minutes after 00:00 UTC; end may be lower than start
 * when the window crosses midnight. */
typedef struct ftn_zmh {
    int start;
    int end;
} ftn_zmh_t;

static ftn_zmh_t ftn_zmh_for_zone(unsigned int zone)
{
    static const ftn_zmh_t kZones[7] = {
        {9 * 60, 10 * 60},           /* fallback */
        {9 * 60, 10 * 60},           /* zone 1 */
        {2 * 60 + 30, 3 * 60 + 30},  /* zone 2 */
        {18 * 60, 19 * 60},          /* zone 3 */
        {8 * 60, 9 * 60},            /* zone 4 */
        {1 * 60, 2 * 60},            /* zone 5 */
        {20 * 60, 21 * 60},          /* zone 6 */
    };
    return kZones[zone >= 1U && zone <= 6U ? zone : 0U];
}

/* Parse "HH:MM-HH:MM" (UTC). */
static bool ftn_zmh_parse(const char *text, ftn_zmh_t *out)
{
    if (text == nullptr || out == nullptr) {
        return false;
    }
    int sh = 0, sm = 0, eh = 0, em = 0;
    char tail = '\0';
    if (sscanf(text, " %d:%d - %d:%d %c", &sh, &sm, &eh, &em, &tail) != 4 ||
        sh < 0 || sh > 23 || eh < 0 || eh > 24 || sm < 0 || sm > 59 ||
        em < 0 || em > 59 || (eh == 24 && em != 0)) {
        return false;
    }
    out->start = sh * 60 + sm;
    out->end = (eh * 60 + em) % FTN_MINUTES_PER_DAY;
    return out->start != out->end;
}

static int ftn_zmh_minute_of_day(time_t now)
{
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    return tm_utc.tm_hour * 60 + tm_utc.tm_min;
}

static bool ftn_zmh_contains(const ftn_zmh_t *zmh, time_t now)
{
    const int minute = ftn_zmh_minute_of_day(now);
    if (zmh->start < zmh->end) {
        return minute >= zmh->start && minute < zmh->end;
    }
    return minute >= zmh->start || minute < zmh->end;
}

/* Start of the window that contains now, or of the next one. */
static time_t ftn_zmh_window_start(const ftn_zmh_t *zmh, time_t now)
{
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    const time_t midnight = now - (tm_utc.tm_hour * 3600 + tm_utc.tm_min * 60 +
                                   tm_utc.tm_sec);
    const int minute = tm_utc.tm_hour * 60 + tm_utc.tm_min;
    time_t start = midnight + (time_t)zmh->start * 60;
    if (ftn_zmh_contains(zmh, now)) {
        /* A window that crossed midnight started yesterday. */
        if (minute < zmh->start) {
            start -= 24 * 3600;
        }
        return start;
    }
    if (minute >= zmh->start) {
        start += 24 * 3600;
    }
    return start;
}

static void ftn_zmh_format(const ftn_zmh_t *zmh, char *out, size_t size)
{
    snprintf(out, size, "%02d:%02d-%02d:%02d UTC", zmh->start / 60,
             zmh->start % 60, zmh->end / 60, zmh->end % 60);
}
